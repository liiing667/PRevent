import pytest
from src.branch_protection import is_branch_included


def mock_get_secret(setting):
    data = {
        'BRANCHES_INCLUDE': {
            'acme/repo1': ['main', 'dev'],
            'acme/repo2': ['release']
        },
        'BRANCHES_EXCLUDE': {
            'acme/repo1': ['test'],
            'acme/repo3': ['staging']
        }
    }
    return data.get(setting, {})


# Patch the function for testing
@pytest.fixture(autouse=True)
def patch_get_secret(monkeypatch):
    monkeypatch.setattr('src.branch_protection.get_secret', mock_get_secret)


@pytest.mark.parametrize("repo_name, branch_name, expected", [
    ('acme/repo1', 'main', True),        # Included explicitly
    ('ACME/Repo1', 'dev', True),         # Repo names are case-insensitive
    ('acme/repo1', 'test', False),       # Excluded explicitly
    ('acme/repo2', 'release', True),     # Included explicitly
    ('acme/repo2', 'main', False),       # Not included
    ('acme/repo3', 'staging', False),    # Excluded explicitly
    ('acme/repo3', 'main', False),       # Not included or excluded
])
def test_is_branch_included(repo_name, branch_name, expected):
    assert is_branch_included(repo_name, branch_name) == expected


def test_is_branch_included_exclude_all(monkeypatch):
    def secret(setting):
        if setting == 'BRANCHES_INCLUDE':
            return {}
        return {'acme/repo4': 'all'}

    monkeypatch.setattr('src.branch_protection.get_secret', secret)
    assert is_branch_included('acme/repo4', 'anything') is False
