import os
import json
import importlib
import re
from src import settings
from fastapi.logger import logger
from typing import Any


# Unified error classification for every secret-manager backend.
# Error messages may contain secret *names* and backend exception *types*,
# but never secret *values*.

class SecretManagerError(ValueError):
    """Base class for secret-manager boundary errors.

    Subclasses ValueError so existing `except ValueError` callers keep working.
    """


class SecretManagerConfigError(SecretManagerError):
    """Local configuration is missing or invalid (manager, credentials, scope, key)."""


class SecretNotFoundError(SecretManagerError):
    """The requested secret key does not exist on the backend."""


class SecretAccessDeniedError(SecretManagerError):
    """The backend rejected the request due to insufficient permissions."""


class SecretBackendError(SecretManagerError):
    """Unexpected backend failure or malformed stored payload."""


BACKEND_OPTIONS = ('aws', 'azure', 'gcloud', 'vault', 'local')

# Canonical key charset. Path separators and traversal sequences are rejected
# at the boundary so no backend can interpret them on its own.
_KEY_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]*$')


def log_and_raise_value_error(message: str):
    logger.error(message)
    raise ValueError(message)


def _log_and_raise(error: SecretManagerError):
    logger.error(str(error))
    # Suppress the exception context: it may carry objects holding secret values.
    raise error from None


def normalize_key(key: str) -> str:
    """Validate a canonical secret key, rejecting names that could escape the scope."""
    if not isinstance(key, str) or not key.strip():
        _log_and_raise(SecretManagerConfigError("Secret key must be a non-empty string."))
    key = key.strip()
    if '..' in key or not _KEY_PATTERN.match(key):
        _log_and_raise(SecretManagerConfigError(
            f"Invalid secret key '{key}': use letters, digits, '_', '-', '.' "
            "(no path separators or traversal sequences)."
        ))
    return key


def validate_scope(scope: str) -> str:
    """Validate a scope string and return it normalized ('' disables scoping)."""
    scope = (scope or '').strip().strip('/')
    if scope:
        segments = scope.split('/')
        if any(
            not segment or '..' in segment or not _KEY_PATTERN.match(segment)
            for segment in segments
        ):
            _log_and_raise(SecretManagerConfigError(
                "Invalid SECRET_SCOPE: use letters, digits, '_', '-', '.' "
                "separated by '/'."
            ))
    return scope


def get_secret_scope() -> str:
    """Optional tenant/environment namespace applied uniformly on every backend."""
    return validate_scope(
        getattr(settings, 'SECRET_SCOPE', '')
        or os.getenv('SECRET_SCOPE', '')
        or ''
    )


def scoped_key(key: str) -> str:
    """Bind a canonical key to the configured scope (identity when scope is unset)."""
    key = normalize_key(key)
    scope = get_secret_scope()
    return f'{scope}/{key}' if scope else key


def _secret_manager_name() -> str:
    secret_manager = getattr(settings, 'SECRET_MANAGER', None)
    if not secret_manager:
        print(f"\nOptions: {', '.join(BACKEND_OPTIONS)}")
        _log_and_raise(SecretManagerConfigError(
            "'SECRET_MANAGER' isn't set in src/settings.py. Set it, or run setup.py."
        ))
    if secret_manager not in BACKEND_OPTIONS:
        _log_and_raise(SecretManagerConfigError(
            f"Unsupported SECRET_MANAGER '{secret_manager}'. "
            f"Options: {', '.join(BACKEND_OPTIONS)}"
        ))
    return secret_manager


def _decode_payload(raw: Any, key: str) -> Any:
    """Single place where stored JSON envelopes are decoded."""
    if not isinstance(raw, str):
        _log_and_raise(SecretBackendError(
            f"Backend returned a non-string payload for '{key}'."
        ))
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Do not chain: JSONDecodeError carries the raw secret payload.
        _log_and_raise(SecretBackendError(
            f"Stored secret '{key}' is not valid JSON."
        ))


def _encode_payload(value: Any) -> str:
    """Single place where values are JSON-encoded for storage."""
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        _log_and_raise(SecretBackendError("Secret value is not JSON-serializable."))


def _exception_names(exc: Exception) -> set:
    return {cls.__name__ for cls in type(exc).__mro__}


def _classify_backend_error(
    backend: str,
    exc: Exception,
    key: str,
    not_found: tuple = (),
    access_denied: tuple = (),
    config: tuple = (),
) -> SecretManagerError:
    """Map backend-specific exceptions onto the unified error taxonomy.

    Only the exception *type* is reported, never the backend message,
    which may echo request payloads.
    """
    if isinstance(exc, SecretManagerError):
        return exc
    if isinstance(exc, ModuleNotFoundError):
        return SecretManagerConfigError(
            f"{backend}: backend dependency is not installed ({exc.name})."
        )
    names = _exception_names(exc)
    status = getattr(exc, 'status_code', None)
    code = ''
    response = getattr(exc, 'response', None)
    if isinstance(response, dict):
        code = response.get('Error', {}).get('Code', '')
    if names & set(not_found) or code in not_found or status == 404:
        return SecretNotFoundError(f"{backend}: secret '{key}' not found.")
    if names & set(access_denied) or code in access_denied or status in (401, 403):
        return SecretAccessDeniedError(f"{backend}: access denied for secret '{key}'.")
    if names & set(config) or code in config:
        return SecretManagerConfigError(
            f"{backend}: backend credentials are not configured ({type(exc).__name__})."
        )
    return SecretBackendError(
        f"{backend}: failed to access secret '{key}' ({type(exc).__name__})."
    )


def get_secret(key: str) -> Any:
    secret_getters = {
        "aws": aws_get_secret,
        "azure": azure_get_secret,
        "gcloud": gcloud_get_secret,
        "vault": vault_get_secret,
        "local": local_get_secret,
    }
    getter = secret_getters[_secret_manager_name()]
    return _decode_payload(getter(scoped_key(key)), key)


def set_secret(key: str, value: Any) -> None:
    secret_setters = {
        "aws": aws_set_secret,
        "azure": azure_set_secret,
        "gcloud": gcloud_set_secret,
        "vault": vault_set_secret,
        "local": local_set_secret,
    }
    setter = secret_setters[_secret_manager_name()]
    setter(scoped_key(key), _encode_payload(value))


# AWS Secrets Manager

_AWS_NOT_FOUND = ('ResourceNotFoundException',)
_AWS_ACCESS_DENIED = ('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation')
_AWS_CONFIG = ('NoCredentialsError', 'NoRegionError', 'ProfileNotFound')


def init_aws_client(region_name: str):
    boto3 = importlib.import_module("boto3")
    return boto3.client('secretsmanager', region_name=region_name)


def aws_get_secret(key: str) -> str:
    region_name = getattr(settings, "AWS_REGION", "us-east-1")
    try:
        client = init_aws_client(region_name)
        response = client.get_secret_value(SecretId=key)
    except Exception as exc:
        raise _classify_backend_error(
            'aws', exc, key, _AWS_NOT_FOUND, _AWS_ACCESS_DENIED, _AWS_CONFIG
        ) from None
    return response['SecretString']


def aws_set_secret(key: str, value: str) -> None:
    region_name = getattr(settings, "AWS_REGION", "us-east-1")
    try:
        client = init_aws_client(region_name)
        client.create_secret(Name=key, SecretString=value)
    except Exception as exc:
        raise _classify_backend_error(
            'aws', exc, key, _AWS_NOT_FOUND, _AWS_ACCESS_DENIED, _AWS_CONFIG
        ) from None


# Azure Key Vault Secrets Manager

_AZURE_NOT_FOUND = ('ResourceNotFoundError',)
_AZURE_ACCESS_DENIED = ('ClientAuthenticationError', 'AuthorizationFailed')
_AZURE_CONFIG = ('DefaultAzureCredentialError',)


def _azure_encode(key: str) -> str:
    # Key Vault names allow only alphanumerics and '-'.
    # Encode the canonical separators deterministically: '/' -> '--', '_' -> '-'.
    return key.replace('/', '--').replace('_', '-')


def init_azure_client(azure_vault_url: str):
    azure_identity = importlib.import_module("azure.identity")
    azure_keyvault = importlib.import_module("azure.keyvault.secrets")
    return azure_keyvault.SecretClient(
        vault_url=azure_vault_url,
        credential=azure_identity.DefaultAzureCredential()
    )


def azure_get_secret(key: str) -> str:
    azure_vault_url = getattr(settings, "AZURE_VAULT_URL", None)
    if not azure_vault_url:
        _log_and_raise(SecretManagerConfigError(
            "'AZURE_VAULT_URL' isn't set in src/settings.py."
        ))
    try:
        client = init_azure_client(azure_vault_url)
        secret = client.get_secret(_azure_encode(key))
    except Exception as exc:
        raise _classify_backend_error(
            'azure', exc, key, _AZURE_NOT_FOUND, _AZURE_ACCESS_DENIED, _AZURE_CONFIG
        ) from None
    return secret.value


def azure_set_secret(key: str, value: str) -> None:
    azure_vault_url = getattr(settings, "AZURE_VAULT_URL", None)
    if not azure_vault_url:
        _log_and_raise(SecretManagerConfigError(
            "'AZURE_VAULT_URL' isn't set in src/settings.py."
        ))
    try:
        client = init_azure_client(azure_vault_url)
        client.set_secret(_azure_encode(key), value)
    except Exception as exc:
        raise _classify_backend_error(
            'azure', exc, key, _AZURE_NOT_FOUND, _AZURE_ACCESS_DENIED, _AZURE_CONFIG
        ) from None


# Google Cloud Secret Manager

_GCLOUD_NOT_FOUND = ('NotFound',)
_GCLOUD_ACCESS_DENIED = ('PermissionDenied', 'Unauthenticated')
_GCLOUD_CONFIG = ('DefaultCredentialsError',)


def _gcloud_encode(key: str) -> str:
    # Secret IDs allow letters, digits, '-' and '_'; encode the scope separator.
    return key.replace('/', '-')


def init_gcloud_client():
    secretmanager = importlib.import_module("google.cloud.secretmanager")
    return secretmanager.SecretManagerServiceClient()


def gcloud_get_secret(key: str) -> str:
    project_id = getattr(settings, "PROJECT_ID", None)
    if not project_id:
        _log_and_raise(SecretManagerConfigError(
            "'PROJECT_ID' isn't set in src/settings.py."
        ))
    try:
        client = init_gcloud_client()
        secret_name = f"projects/{project_id}/secrets/{_gcloud_encode(key)}/versions/latest"
        response = client.access_secret_version(name=secret_name)
    except Exception as exc:
        raise _classify_backend_error(
            'gcloud', exc, key, _GCLOUD_NOT_FOUND, _GCLOUD_ACCESS_DENIED, _GCLOUD_CONFIG
        ) from None
    return response.payload.data.decode("UTF-8")


def gcloud_set_secret(key: str, value: str) -> None:
    project_id = getattr(settings, "PROJECT_ID", None)
    if not project_id:
        _log_and_raise(SecretManagerConfigError(
            "'PROJECT_ID' isn't set in src/settings.py."
        ))
    try:
        client = init_gcloud_client()
        secret = client.create_secret(
            parent=f"projects/{project_id}",
            secret_id=_gcloud_encode(key),
            secret={"replication": {"automatic": {}}}
        )
        client.add_secret_version(
            parent=secret.name,
            payload={"data": value.encode("UTF-8")}
        )
    except Exception as exc:
        raise _classify_backend_error(
            'gcloud', exc, key, _GCLOUD_NOT_FOUND, _GCLOUD_ACCESS_DENIED, _GCLOUD_CONFIG
        ) from None


# HashiCorp Vault

_VAULT_NOT_FOUND = ('InvalidPath',)
_VAULT_ACCESS_DENIED = ('Forbidden', 'Unauthorized')


def read_existent_file(file_path: str) -> str:
    if not os.path.exists(file_path):
        return ''
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                logger.warning(f"File is empty: {file_path}")
            return content
    except FileNotFoundError:
        raise OSError(f"File not found: {file_path}")
    except PermissionError:
        raise OSError(f"Permission denied when reading file: {file_path}")


def init_vault_client():
    try:
        hvac = importlib.import_module("hvac")
    except ModuleNotFoundError as exc:
        _log_and_raise(SecretManagerConfigError(
            f"vault: backend dependency is not installed ({exc.name})."
        ))
    token_file_path = os.path.expanduser("~/.vault-token")

    try:
        token = read_existent_file(token_file_path)
    except OSError:
        _log_and_raise(SecretAccessDeniedError(
            f"vault: cannot read token file {token_file_path}."
        ))
    if not token:
        print("Authenticate using `vault login`.")
        _log_and_raise(SecretManagerConfigError(
            f"Vault token file {token_file_path} is missing."
        ))

    address_file_path = f"{settings.CONFIG_DIR}/vault-address"
    address = (
        read_existent_file(address_file_path)
        or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    )
    if not address:
        print(f"Vault address file {address_file_path} is missing.")
        print("Set 'VAULT_ADDR' or provide a vault-address file.")

    return hvac.Client(url=address, token=token)


def vault_get_secret(key: str) -> Any:
    client = init_vault_client()
    try:
        data = client.secrets.kv.v2.read_secret_version(path=key)
    except Exception as exc:
        raise _classify_backend_error(
            'vault', exc, key, _VAULT_NOT_FOUND, _VAULT_ACCESS_DENIED
        ) from None
    if data is None:
        _log_and_raise(SecretNotFoundError(f"vault: secret '{key}' not found."))
    try:
        # Unwrap the KV v2 envelope here so every backend returns the same shape.
        return data["data"]["data"]["data"]
    except (KeyError, TypeError):
        _log_and_raise(SecretBackendError(
            f"vault: unexpected secret envelope for '{key}'."
        ))


def vault_set_secret(key: str, value: Any) -> None:
    client = init_vault_client()
    try:
        client.secrets.kv.v2.create_or_update_secret(
            path=key,
            secret={"data": value}
        )
    except Exception as exc:
        raise _classify_backend_error(
            'vault', exc, key, _VAULT_NOT_FOUND, _VAULT_ACCESS_DENIED
        ) from None


# 'local' development keeps using a local Vault dev server (historical alias).
local_get_secret = vault_get_secret
local_set_secret = vault_set_secret
