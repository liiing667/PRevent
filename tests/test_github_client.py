import jwt
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from src.github_client import create_jwt
from src.settings import JWT_EXPIRY_SECONDS


def test_create_jwt():
    private_key = serialization.load_pem_private_key(
        rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ),
        password=None
    )
    secrets = {
        "GITHUB_APP_INTEGRATION_ID": "123456",
        "GITHUB_APP_PRIVATE_KEY": private_key,
    }
    with patch("time.time") as mock_time, \
         patch("src.github_client.get_secret", side_effect=lambda key: secrets[key]):
        mock_time.return_value = 1609459200  # Fixed mocked time
        token = create_jwt()
        decoded_token = jwt.decode(
            token,
            private_key.public_key(),
            algorithms=["RS256"],
            options={"verify_signature": False}
        )
        assert decoded_token["iat"] == 1609459200
        assert decoded_token["exp"] == 1609459200 + JWT_EXPIRY_SECONDS
        assert int(decoded_token["iss"]) > 9999
