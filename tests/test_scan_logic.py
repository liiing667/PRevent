from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.scan.scan_logic import process_scan, ScanOutcome


SHA = "a" * 40


def make_repo_pr(sha=SHA):
    pr = SimpleNamespace(number=3, head=SimpleNamespace(sha=sha))
    repo = SimpleNamespace(name="acme/app")
    return repo, pr


def test_process_scan_rejects_sha_mismatch_before_fetching_files():
    repo, pr = make_repo_pr()

    with patch("src.scan.scan_logic.get_changed_files") as mock_changed:
        with pytest.raises(ValueError):
            process_scan(repo, pr, "b" * 40)

    mock_changed.assert_not_called()


def test_process_scan_no_changed_files_posts_no_status():
    repo, pr = make_repo_pr()

    with patch("src.scan.scan_logic.get_changed_files", return_value=[]), \
         patch("src.scan.scan_logic.create_commit_status") as mock_status:
        outcome = process_scan(repo, pr, SHA.upper())

    mock_status.assert_not_called()
    assert outcome == ScanOutcome(status="success", status_posted=False)


def test_process_scan_posts_status_when_files_changed():
    repo, pr = make_repo_pr()

    with patch("src.scan.scan_logic.get_changed_files", return_value=[{"filename": "x.py"}]), \
         patch("src.scan.scan_logic.scan_additions", return_value=[]), \
         patch(
             "src.scan.scan_logic.determine_and_comment_scan_status",
             return_value=("success", "desc", "Scan completed successfully.")
         ), \
         patch("src.scan.scan_logic.create_commit_status") as mock_status:
        outcome = process_scan(repo, pr, SHA)

    mock_status.assert_called_once()
    assert outcome == ScanOutcome(status="success", status_posted=True)
