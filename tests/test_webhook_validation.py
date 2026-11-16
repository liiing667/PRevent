import pytest

from src.validation.webhook import (
    normalize_repo_name,
    normalize_branch_name,
    normalize_sha,
    normalize_reviewer_login,
    validate_pr_number
)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Acme/Repo-1", "acme/repo-1"),
        ("  acme/repo_x ", "acme/repo_x"),
        ("o-rg123/r.name-42", "o-rg123/r.name-42"),
    ],
)
def test_normalize_repo_name_accepts_valid(raw, expected):
    assert normalize_repo_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "no-slash",
        "../evil/repo",
        "acme/repo/../../etc",
        "acme/repo:name",
        "",
        123,
        None,
        "acme/",
        "-acme/repo",
        "acme/" + "a" * 101,
    ],
)
def test_normalize_repo_name_rejects_invalid(raw):
    with pytest.raises(ValueError):
        normalize_repo_name(raw)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("main", "main"),
        ("  feature/login ", "feature/login"),
        ("release-1.2.3", "release-1.2.3"),
    ],
)
def test_normalize_branch_name_accepts_valid(raw, expected):
    assert normalize_branch_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "../main",
        "feature..main",
        "bad//branch",
        "trailing/",
        "a~b",
        "a^b",
        "a:b",
        "a?b",
        "a\\b",
        "@{b}",
        "",
        42,
        None,
    ],
)
def test_normalize_branch_name_rejects_invalid(raw):
    with pytest.raises(ValueError):
        normalize_branch_name(raw)


@pytest.mark.parametrize("number", [1, 100_000, 42])
def test_validate_pr_number_accepts_positive_int(number):
    validate_pr_number(number)


@pytest.mark.parametrize("number", [0, -1, 100_001, True, False, "5", 1.5, None])
def test_validate_pr_number_rejects_invalid(number):
    with pytest.raises(ValueError):
        validate_pr_number(number)


def test_normalize_sha():
    raw = "A" * 40
    assert normalize_sha(raw) == "a" * 40
    with pytest.raises(ValueError):
        normalize_sha("g" * 40)
    with pytest.raises(ValueError):
        normalize_sha("a" * 39)
    with pytest.raises(ValueError):
        normalize_sha(1234)


def test_normalize_reviewer_login():
    assert normalize_reviewer_login("Alice-1") == "alice-1"
    with pytest.raises(ValueError):
        normalize_reviewer_login("bad login")
    with pytest.raises(ValueError):
        normalize_reviewer_login("-leading")
