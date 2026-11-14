import os
import concurrent.futures
from fastapi.logger import logger
from github import Repository, PullRequest
from typing import Optional, Callable
from src.scan.detectors.utils import DetectionType, ScanResult
from src.scan.detectors.run_semgrep import detect_dynamic_execution_and_obfuscation
from src.scan.detectors.obfuscation_extras.detect_encoded import detect_encoded
from src.scan.detectors.obfuscation_extras.detect_executable import detect_executable
from src.scan.detectors.obfuscation_extras.detect_space_hidden import detect_space_hiding
from src.scan.detectors.obfuscation_extras.detect_homoglyph import detect_homoglyph
from src.scan.utils import (
    get_lang,
    get_loc,
    handle_one_liners
)
from src.utils.github import (
    get_changed_files,
    get_file_full_content,
    determine_and_comment_scan_status,
    create_commit_status
)
from src.utils.diffs import process_diff
from src.settings import APP_REPO, FP_STRICT, FULL_FINDINGS


def process_scan(
    repo: Repository,
    pr: PullRequest,
    commit_sha: str
) -> str:
    # "success" status if no files were changed
    status = "success"

    # Get full files for proper code analysis. PR contains only diffs.
    changed_files = get_changed_files(repo, pr)
    if changed_files:
        scan_results: ScanResult = scan_additions(changed_files, repo, pr)
        logger.info(f"Scanned PR #{pr.number}")
        status, description, comment = determine_and_comment_scan_status(scan_results, pr, repo)
        target_url = comment.html_url if hasattr(comment, 'html_url') else APP_REPO
        create_commit_status(repo, commit_sha, status, description, target_url)

    return status


def scan_additions(
    changed_files: list[dict[str, str]],
    repo: Repository,
    pr: PullRequest
) -> ScanResult:
    """
    Scan every changed file. Files in unsupported languages are skipped individually
    and processing/ detector failures are collected as explicit errors instead of
    aborting the scan or being treated as clean.

    All supported files are processed before a terminal finding is chosen so the
    result does not depend on thread scheduling or file ordering in the diff.
    """
    detections: list[DetectionType] = []
    errors: list[str] = []

    for file in changed_files:
        filename = file['filename']
        extension, language = get_lang(filename)
        if not language:
            # Unsupported file type: skip only this file, keep scanning the rest.
            continue

        try:
            file_detections, file_errors = scan_single_file(file, extension, language, repo, pr)
        except Exception as e:
            logger.error(f"Failed to scan {filename}: {e}")
            errors.append(f"{filename}: scan failed ({e})")
            continue

        detections.extend(file_detections)
        errors.extend(file_errors)

    terminal_detections = select_terminal_detections(detections)
    return {"detections": terminal_detections, "errors": errors}


def scan_single_file(
    file: dict[str, str],
    extension: str,
    language: str,
    repo: Repository,
    pr: PullRequest
) -> tuple[list[DetectionType], list[str]]:
    filename = file['filename']
    errors: list[str] = []

    additions_list = process_diff(file['diff'], language)
    if not additions_list:
        return [], errors

    # Exclude minified files and other one-liners from the scan to avoid false-positives
    if handle_one_liners(additions_list, filename, repo, pr):
        return [], errors

    file['full_content'] = get_file_full_content(repo, filename, pr)
    file_detections, detector_errors = get_detections(file, extension)
    errors.extend(f"{filename}: {error}" for error in detector_errors)

    results = []
    for detection in file_detections:
        try:
            if full_detection_data := enrich_detection(file, detection, additions_list):
                results.append(full_detection_data)
        except Exception as e:
            logger.error(f"Failed to enrich a detection in {filename}: {e}")
            errors.append(f"{filename}: failed to process a detection ({e})")

    return results, errors


def select_terminal_detections(
    detections: list[DetectionType]
) -> list[DetectionType]:
    """
    Deterministic terminal finding selection.

    FULL_FINDINGS keeps every detection, ordered by file, line and message so the
    output is independent of detector completion order. Otherwise only the first
    detection of that stable ordering is returned to avoid PR comment spam.
    """
    ordered = sorted(
        detections,
        key=lambda detection: (
            detection.get('filename') or '',
            detection.get('line_number') or 0,
            detection.get('message') or ''
        )
    )
    if FULL_FINDINGS:
        return ordered
    return ordered[:1]


def get_detections(
    file: dict[str, str],
    extension: str
) -> tuple[list[dict], list[str]]:
    full_content = file['full_content']

    detection_tasks = [
        (detect_dynamic_execution_and_obfuscation, (full_content, extension)),
        (detect_executable, (file['filename'], full_content)),
        *get_extra_detection_tasks(full_content)
    ]

    return run_detection_tasks(detection_tasks, file['filename'])


def get_extra_detection_tasks(
    full_content: str
) -> list[tuple[Callable, tuple]]:
    extra_obfuscation_detectors = [
        (detect_space_hiding, "ERROR"),
        (detect_encoded, "WARNING"),
        (detect_homoglyph, "WARNING")
    ]

    tasks = []

    # Add extra obfuscation detectors
    for detector, severity in extra_obfuscation_detectors:
        if FP_STRICT and severity != "ERROR":
            continue
        tasks.append((detector, (full_content,)))  # Pass as tuple for executor

    return tasks


def run_detection_tasks(
    tasks: list[tuple[Callable, tuple]],
    filename: str
) -> tuple[list[dict], list[str]]:
    # CPU-bound string processing. Semgrep is I/O bound, but runs as a single-command blackbox.
    detections: list[dict] = []
    errors: list[str] = []
    if not tasks:
        return detections, errors

    # A detector failure must never look like a clean scan: every timeout or
    # exception is surfaced as an explicit error while the other detectors finish.
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        future_to_task = {
            executor.submit(task[0], *task[1]): task[0].__name__ for task in tasks
        }
        # Iterate in submission order so the aggregated findings are stable.
        for future, task_name in future_to_task.items():
            try:
                results = future.result(timeout=5)
                if results:
                    detections.extend(results)
            except concurrent.futures.TimeoutError:
                future.cancel()
                message = f"detector {task_name} timed out"
                logger.error(f"{filename}: {message}.")
                errors.append(message)
            except Exception as e:
                message = f"detector {task_name} failed ({e})"
                logger.error(f"{filename}: {message}.")
                errors.append(message)

    return detections, errors


def enrich_detection(
    file: dict[str, str],
    detection: DetectionType,
    additions_list: list[tuple]
) -> Optional[DetectionType]:

    # Derived from the detector's nature, a match key may or may not be present.
    # Also helps with Semgerp placing the match field behind an auth wall.
    match = detection.get('match') or get_loc(file['full_content'], detection['line_number'])
    
    # Whole updated file is scanned, report only detections in additions.
    if any(new_code[1] in match for new_code in additions_list):
        return {
            "filename": file['filename'],
            **detection,
            "match": match.replace('  ', '')
        }
    return None
