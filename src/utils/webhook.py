import hmac
import hashlib
import time
from dataclasses import dataclass
from datetime import datetime
from fastapi import Request, HTTPException
from fastapi.logger import logger
from github import Github, Repository, PullRequest
from typing import Any
from src.validation.webhook import (
    normalize_repo_name,
    normalize_branch_name,
    normalize_reviewer_login,
    normalize_sha,
    validate_pr_number
)
from src.secret_manager import get_secret


@dataclass(frozen=True)
class PRIdentity:
    """
    Canonical identity of a pull request, derived solely from the
    signature-verified webhook payload and bound to GitHub's authoritative PR.
    Every downstream side effect must consume these fields instead of
    re-reading raw payload values.
    """
    repo_name: str
    branch_name: str
    pr_number: int
    commit_sha: str


def extract_pr_identity(webhook_data: dict[str, Any]) -> PRIdentity:
    """
    Extract and validate the PR identity from a signature-verified payload.
    Raises ValueError (mapped to HTTP 400) on any malformed field, before any
    GitHub API call or other side effect takes place.
    """
    try:
        identity = PRIdentity(
            repo_name=normalize_repo_name(webhook_data['repository']['full_name']),
            branch_name=normalize_branch_name(
                webhook_data['pull_request']['base']['ref']
            ),
            pr_number=webhook_data['pull_request']['number'],
            commit_sha=normalize_sha(webhook_data['pull_request']['head']['sha'])
        )
        validate_pr_number(identity.pr_number)
        return identity

    except KeyError as e:
        logger.error(f"Missing expected key: {e}")
        raise ValueError(f"Missing expected key: {e}")


def bind_pr_identity(repo: Repository, pr: PullRequest, identity: PRIdentity) -> None:
    """
    Bind the validated payload identity to GitHub's authoritative PR object.
    Any mismatch means the payload cannot be trusted to describe this PR;
    raise ValueError so the caller aborts without side effects (no comments,
    no commit statuses, no protection-rule changes).
    """
    actual_repo_name = normalize_repo_name(repo.full_name)
    actual_branch_name = normalize_branch_name(pr.base.ref)
    actual_sha = normalize_sha(pr.head.sha)

    if actual_repo_name != identity.repo_name:
        raise ValueError(
            f"Repository mismatch: payload {identity.repo_name} vs GitHub {actual_repo_name}"
        )
    if pr.number != identity.pr_number:
        raise ValueError(
            f"PR number mismatch: payload {identity.pr_number} vs GitHub {pr.number}"
        )
    if actual_branch_name != identity.branch_name:
        raise ValueError(
            f"Base branch mismatch: payload {identity.branch_name} vs GitHub {actual_branch_name}"
        )
    if actual_sha != identity.commit_sha:
        raise ValueError(
            f"Head SHA mismatch: payload {identity.commit_sha} vs GitHub {actual_sha}"
        )


def validate_review_state(state: str) -> None:
    valid_states = {'approved', 'changes_requested', 'commented', 'dismissed', 'pending'}
    if state.lower() not in valid_states:
        raise ValueError(f"Invalid review state: {state}")


def extract_review_info(webhook_data: dict[str, Any]) -> tuple:
    try:
        repo_name = normalize_repo_name(webhook_data['repository']['full_name'])
        branch_name = normalize_branch_name(
            webhook_data['pull_request']['head']['ref']
        )
        pr_number = webhook_data['pull_request']['number']
        review_state = webhook_data['review']['state']
        reviewer = normalize_reviewer_login(webhook_data['review']['user']['login'])

        validate_pr_number(pr_number)
        validate_review_state(review_state)

        return repo_name, branch_name, pr_number, review_state, reviewer

    except KeyError as e:
        logger.error(f"Missing expected key: {e}")
        raise ValueError("Invalid webhook_data format")

async def verify_webhook_signature(event_request: Request) -> None:
    signature_header: str = event_request.headers.get('X-Hub-Signature-256', '')
    if not signature_header:
        logger.error("Missing X-Hub-Signature header.")
        raise HTTPException(status_code=401, detail="Missing X-Hub-Signature header")

    secret_token = get_secret('WEBHOOK_SECRET')
    payload_body: bytes = await event_request.body()
    computed_signature = 'sha256=' + hmac.new(
        secret_token.encode("utf-8"),
        payload_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(computed_signature, signature_header):
        logger.error("Invalid webhook signature.")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")


def check_rate_limit(github_client: Github) -> None:
    rate_limit = github_client.get_rate_limit().core
    remaining = rate_limit.remaining
    reset_time = rate_limit.reset  # (Unix timestamp)

    if remaining < 5:
        time_delta = reset_time.replace(tzinfo=None) - datetime.now()
        sleep_seconds = time_delta.total_seconds()
        if sleep_seconds > 0:
            logger.warning(
                f"Approaching rate limit. Sleeping for {sleep_seconds} seconds."
            )
            time.sleep(sleep_seconds)

    return None
