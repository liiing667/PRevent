from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.utils.webhook import PRIdentity, extract_pr_identity, bind_pr_identity
from src.scan.scan_logic import ScanOutcome


SHA = "a" * 40


def make_payload(
    repo="acme/app",
    branch="main",
    number=7,
    sha=SHA,
):
    return {
        "repository": {"full_name": repo},
        "pull_request": {
            "base": {"ref": branch},
            "number": number,
            "head": {"sha": sha},
        },
    }


def make_github_pr(repo="acme/app", branch="main", number=7, sha=SHA):
    repo_obj = SimpleNamespace(full_name=repo)
    pr_obj = SimpleNamespace(
        number=number,
        base=SimpleNamespace(ref=branch),
        head=SimpleNamespace(sha=sha),
    )
    return repo_obj, pr_obj


def test_extract_pr_identity_canonicalizes_fields():
    identity = extract_pr_identity(make_payload(repo="ACME/App", branch="  main "))
    assert identity == PRIdentity(
        repo_name="acme/app",
        branch_name="main",
        pr_number=7,
        commit_sha=SHA,
    )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda p: p["repository"].__setitem__("full_name", "../evil"),
        lambda p: p["pull_request"]["base"].__setitem__("ref", "../main"),
        lambda p: p["pull_request"].__setitem__("number", 0),
        lambda p: p["pull_request"]["head"].__setitem__("sha", "x" * 40),
    ],
)
def test_extract_pr_identity_rejects_malformed_payload(mutator):
    payload = make_payload()
    mutator(payload)
    with pytest.raises(ValueError):
        extract_pr_identity(payload)


def test_extract_pr_identity_rejects_missing_keys():
    with pytest.raises(ValueError):
        extract_pr_identity({})


def test_bind_pr_identity_accepts_matching_pr():
    identity = extract_pr_identity(make_payload())
    repo_obj, pr_obj = make_github_pr()
    # Casing differences are allowed because normalization canonicalizes both sides.
    pr_obj.base.ref = "  main "
    bind_pr_identity(repo_obj, pr_obj, identity)


@pytest.mark.parametrize(
    "repo, branch, number, sha",
    [
        ("acme/other", "main", 7, SHA),
        ("acme/app", "dev", 7, SHA),
        ("acme/app", "main", 8, SHA),
        ("acme/app", "main", 7, "b" * 40),
    ],
)
def test_bind_pr_identity_rejects_mismatch(repo, branch, number, sha):
    identity = extract_pr_identity(make_payload())
    repo_obj, pr_obj = make_github_pr(repo, branch, number, sha)
    with pytest.raises(ValueError):
        bind_pr_identity(repo_obj, pr_obj, identity)


def _make_listener():
    from src.webhook import GitHubPRWebhook

    with patch("src.webhook.initialize_github_client"), \
         patch("src.webhook.get_secret") as mock_get_secret:
        mock_get_secret.side_effect = lambda key: {
            "SECURITY_REVIEWERS": ["reviewer-1"],
            "PROTECTED_BRANCHES": {},
        }.get(key, {})
        return GitHubPRWebhook()


def test_on_pull_request_aborts_before_side_effects_on_binding_failure():
    listener = _make_listener()
    repo_obj, pr_obj = make_github_pr(sha="b" * 40)
    repo_obj.get_pull = MagicMock(return_value=pr_obj)

    with patch("src.webhook.is_branch_included", return_value=True), \
         patch.object(
             listener.github_client, "get_repo", return_value=repo_obj
         ) as mock_get_repo, \
         patch("src.webhook.process_scan") as mock_scan, \
         patch("src.webhook.bind_pr_identity", side_effect=ValueError("sha mismatch")):
        response = listener.on_pull_request(make_payload())

    mock_scan.assert_not_called()
    mock_get_repo.assert_called_once_with("acme/app")
    assert response.status_code == 400


def test_on_pull_request_invalid_payload_performs_no_side_effects():
    listener = _make_listener()
    payload = make_payload(repo="not-a-valid-repo")

    with patch("src.webhook.is_branch_included") as mock_included, \
         patch("src.webhook.process_scan") as mock_scan:
        response = listener.on_pull_request(payload)

    mock_included.assert_not_called()
    mock_scan.assert_not_called()
    assert response.status_code == 400


def test_on_pull_request_unmonitored_branch_skips_github_calls():
    listener = _make_listener()

    with patch("src.webhook.is_branch_included", return_value=False), \
         patch.object(listener.github_client, "get_repo") as mock_get_repo, \
         patch("src.webhook.process_scan") as mock_scan:
        response = listener.on_pull_request(make_payload())

    mock_get_repo.assert_not_called()
    mock_scan.assert_not_called()
    assert response.status_code == 204


def test_on_pull_request_no_status_means_no_review_or_protection_change():
    listener = _make_listener()
    repo_obj, pr_obj = make_github_pr()
    repo_obj.get_pull = MagicMock(return_value=pr_obj)

    with patch("src.webhook.is_branch_included", return_value=True), \
         patch.object(listener.github_client, "get_repo", return_value=repo_obj), \
         patch("src.webhook.bind_pr_identity"), \
         patch("src.webhook.process_scan", return_value=ScanOutcome("success", False)), \
         patch.object(listener, "_request_code_review") as mock_review, \
         patch.object(listener, "_handle_block_mode") as mock_block:
        response = listener.on_pull_request(make_payload())

    mock_review.assert_not_called()
    mock_block.assert_not_called()
    assert response.status_code == 200


def test_on_pull_request_success_drives_review_and_protection():
    listener = _make_listener()
    repo_obj, pr_obj = make_github_pr()
    repo_obj.get_pull = MagicMock(return_value=pr_obj)

    with patch("src.webhook.is_branch_included", return_value=True), \
         patch.object(listener.github_client, "get_repo", return_value=repo_obj), \
         patch("src.webhook.bind_pr_identity"), \
         patch("src.webhook.process_scan", return_value=ScanOutcome("failure", True)), \
         patch.object(listener, "_request_code_review") as mock_review, \
         patch.object(listener, "_handle_block_mode") as mock_block:
        response = listener.on_pull_request(make_payload())

    mock_review.assert_called_once_with("failure", pr_obj, "acme/app")
    mock_block.assert_called_once_with("acme/app", "main")
    assert response.status_code == 200


def make_review_payload(
    repo="acme/app",
    branch="feature/x",
    number=7,
    state="approved",
    reviewer="Reviewer-1",
):
    return {
        "repository": {"full_name": repo},
        "pull_request": {
            "head": {"ref": branch},
            "number": number,
        },
        "review": {
            "state": state,
            "user": {"login": reviewer},
        },
    }


def test_on_pull_request_review_approved_by_listed_reviewer_posts_status():
    listener = _make_listener()
    pr_obj = SimpleNamespace(head=SimpleNamespace(sha=SHA))
    repo_obj = SimpleNamespace()
    repo_obj.get_pull = MagicMock(return_value=pr_obj)

    with patch.object(listener.github_client, "get_repo", return_value=repo_obj), \
         patch("src.webhook.create_commit_status") as mock_status:
        response = listener.on_pull_request_review(make_review_payload())

    # Logins are case-insensitive: payload uses "Reviewer-1", config "reviewer-1".
    mock_status.assert_called_once()
    assert response.status_code == 200


def test_on_pull_request_review_unknown_reviewer_posts_no_status():
    listener = _make_listener()

    with patch.object(listener.github_client, "get_repo") as mock_get_repo, \
         patch("src.webhook.create_commit_status") as mock_status:
        response = listener.on_pull_request_review(
            make_review_payload(reviewer="intruder-9")
        )

    mock_get_repo.assert_not_called()
    mock_status.assert_not_called()
    assert response.status_code == 200


def test_on_pull_request_review_invalid_payload_returns_400_without_side_effects():
    listener = _make_listener()

    with patch.object(listener.github_client, "get_repo") as mock_get_repo, \
         patch("src.webhook.create_commit_status") as mock_status:
        response = listener.on_pull_request_review(make_review_payload(repo="../evil"))

    mock_get_repo.assert_not_called()
    mock_status.assert_not_called()
    assert response.status_code == 400
