import pytest

from src.scan import scan_logic
from src.utils.github import determine_and_comment_scan_status


UNSUPPORTED_DIFF = (
    "--- a/notes.txt\n"
    "+++ b/notes.txt\n"
    "@@ -1,1 +1,2 @@\n"
    " context\n"
    "+some unsupported note\n"
)

PYTHON_DIFF = (
    "--- a/evil.py\n"
    "+++ b/evil.py\n"
    "@@ -1,1 +1,2 @@\n"
    " context\n"
    "+import os\n"
)


@pytest.fixture
def patched_file_helpers(monkeypatch):
    monkeypatch.setattr(scan_logic, "handle_one_liners", lambda *args: False)
    monkeypatch.setattr(scan_logic, "get_file_full_content", lambda *args: "import os\n")


def _detection(message, line_number, filename):
    return {
        "message": message,
        "line_number": line_number,
        "filename": filename,
        "match": "import os"
    }


def test_unsupported_file_is_skipped_but_scan_continues(patched_file_helpers, monkeypatch):
    changed_files = [
        {"filename": "notes.txt", "diff": UNSUPPORTED_DIFF},
        {"filename": "evil.py", "diff": PYTHON_DIFF},
    ]

    monkeypatch.setattr(
        scan_logic,
        "get_detections",
        lambda file, extension: ([_detection("malicious change", 2, "evil.py")], []),
    )

    result = scan_logic.scan_additions(changed_files, repo=None, pr=None)

    assert result["errors"] == []
    assert [d["filename"] for d in result["detections"]] == ["evil.py"]


def test_all_unsupported_files_returns_clean(patched_file_helpers, monkeypatch):
    changed_files = [
        {"filename": "notes.txt", "diff": UNSUPPORTED_DIFF},
        {"filename": "image.bin", "diff": UNSUPPORTED_DIFF},
    ]

    result = scan_logic.scan_additions(changed_files, repo=None, pr=None)

    assert result == {"detections": [], "errors": []}


def test_file_processing_failure_does_not_abort_scan(patched_file_helpers, monkeypatch):
    changed_files = [
        {"filename": "broken.py", "diff": PYTHON_DIFF},
        {"filename": "evil.py", "diff": PYTHON_DIFF},
    ]

    def flaky_get_detections(file, extension):
        if file["filename"] == "broken.py":
            raise RuntimeError("boom")
        return [_detection("malicious change", 2, "evil.py")], []

    monkeypatch.setattr(scan_logic, "get_detections", flaky_get_detections)

    result = scan_logic.scan_additions(changed_files, repo=None, pr=None)

    assert [d["filename"] for d in result["detections"]] == ["evil.py"]
    assert len(result["errors"]) == 1
    assert result["errors"][0].startswith("broken.py: scan failed")


def test_terminal_detection_is_selected_by_stable_order(patched_file_helpers, monkeypatch):
    changed_files = [
        {"filename": "zebra.py", "diff": PYTHON_DIFF},
        {"filename": "alpha.py", "diff": PYTHON_DIFF},
    ]

    def detections_per_file(file, extension):
        if file["filename"] == "zebra.py":
            return [_detection("z finding", 9, "zebra.py")], []
        return [_detection("a finding", 1, "alpha.py")], []

    monkeypatch.setattr(scan_logic, "get_detections", detections_per_file)

    result = scan_logic.scan_additions(changed_files, repo=None, pr=None)

    assert len(result["detections"]) == 1
    assert result["detections"][0]["filename"] == "alpha.py"


def test_full_findings_keeps_every_detection_ordered(patched_file_helpers, monkeypatch):
    monkeypatch.setattr(scan_logic, "FULL_FINDINGS", True)
    changed_files = [
        {"filename": "zebra.py", "diff": PYTHON_DIFF},
        {"filename": "alpha.py", "diff": PYTHON_DIFF},
    ]

    def detections_per_file(file, extension):
        if file["filename"] == "zebra.py":
            return [_detection("z finding", 9, "zebra.py")], []
        return [_detection("a finding", 1, "alpha.py")], []

    monkeypatch.setattr(scan_logic, "get_detections", detections_per_file)

    result = scan_logic.scan_additions(changed_files, repo=None, pr=None)

    assert [d["filename"] for d in result["detections"]] == ["alpha.py", "zebra.py"]


def test_detector_timeout_is_collected_as_error(monkeypatch):
    def slow_detector(_content):
        return []

    class StubFuture:
        def result(self, timeout):
            raise scan_logic.concurrent.futures.TimeoutError()

        def cancel(self):
            return True

    class StubExecutor:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def submit(self, fn, *args):
            return StubFuture()

    monkeypatch.setattr(
        scan_logic.concurrent.futures, "ThreadPoolExecutor", StubExecutor
    )
    detections, errors = scan_logic.run_detection_tasks(
        [(slow_detector, ("content",))], "evil.py"
    )

    assert detections == []
    assert errors == ["detector slow_detector timed out"]


def test_detector_exception_is_collected_as_error():
    def broken_detector(_content):
        raise RuntimeError("parse failure")

    def clean_detector(_content):
        return []

    detections, errors = scan_logic.run_detection_tasks(
        [(broken_detector, ("content",)), (clean_detector, ("content",))],
        "evil.py",
    )

    assert detections == []
    assert len(errors) == 1
    assert "broken_detector failed" in errors[0]
    assert "parse failure" in errors[0]


def test_status_is_error_when_only_failures_occurred():
    pr = type("PR", (), {"number": 1})()
    status, _, _ = determine_and_comment_scan_status(
        {"detections": [], "errors": ["evil.py: detector failed (boom)"]},
        pr=pr,
        repo=None,
    )

    assert status == "error"


def test_status_is_failure_with_errors_when_detections_exist(monkeypatch):
    monkeypatch.setattr(
        "src.utils.github.comment_detections", lambda detections, repo, pr: "comment"
    )
    pr = type("PR", (), {"number": 1})()

    status, description, _ = determine_and_comment_scan_status(
        {
            "detections": [_detection("malicious change", 2, "evil.py")],
            "errors": ["evil.py: detector timed out"],
        },
        pr=pr,
        repo=None,
    )

    assert status == "failure"
    assert "detector timed out" in description


def test_status_is_success_when_clean():
    pr = type("PR", (), {"number": 1})()
    status, _, _ = determine_and_comment_scan_status(
        {"detections": [], "errors": []},
        pr=pr,
        repo=None,
    )

    assert status == "success"
