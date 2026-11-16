import re


# GitHub repository full name: "owner/repo"
REPO_NAME_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,38}/[A-Za-z0-9._-]{1,100}$')
# Git ref name characters. Explicitly forbids control chars, whitespace and
# path-traversal sequences (":", "\", "..", "@{", "~", "^", ":", "?").
BRANCH_NAME_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$')
SHA_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
# GitHub usernames: alphanumeric with single hyphens, 1-39 chars.
GITHUB_LOGIN_PATTERN = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$')


def normalize_repo_name(repo_name: str) -> str:
    """
    Validate a repository full name ("owner/repo") and return its canonical form.
    Repository names are case-insensitive on GitHub, so they are lowercased.
    """
    if not isinstance(repo_name, str):
        raise ValueError(f"Invalid repository name value: {repo_name}")
    repo_name = repo_name.strip()
    if not REPO_NAME_PATTERN.fullmatch(repo_name):
        raise ValueError(f"Invalid repository name value: {repo_name}")
    return repo_name.lower()


def normalize_branch_name(branch_name: str) -> str:
    """
    Validate and canonicalize a branch name.
    Branch names are case-sensitive, so casing is preserved; only surrounding
    whitespace is stripped and traversal/control sequences are rejected.
    """
    if not isinstance(branch_name, str):
        raise ValueError(f"Invalid branch name value: {branch_name}")
    branch_name = branch_name.strip()
    if (
        not branch_name
        or branch_name.endswith('/')
        or '..' in branch_name
        or '//' in branch_name
        or '@{' in branch_name
        or not BRANCH_NAME_PATTERN.fullmatch(branch_name)
    ):
        raise ValueError(f"Invalid branch name value: {branch_name}")
    return branch_name


def validate_pr_number(number: int) -> None:
    # bool is a subclass of int; reject it explicitly.
    if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= 100_000:
        raise ValueError(f"Invalid PR number value: {number}")


def normalize_sha(sha: str) -> str:
    if not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha):
        raise ValueError(f"Invalid parameter value: {sha}")
    return sha.lower()


def normalize_reviewer_login(login: str) -> str:
    if not isinstance(login, str) or not GITHUB_LOGIN_PATTERN.fullmatch(login):
        raise ValueError(f"Invalid reviewer login value: {login}")
    # GitHub logins are case-insensitive; canonicalize for membership checks.
    return login.lower()
