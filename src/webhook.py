from typing import Any
from fastapi.responses import JSONResponse
from fastapi.logger import logger
from github import PullRequest
from github.GithubException import GithubException
from src.github_client import initialize_github_client
from src.utils.github import create_commit_status
from src.utils.webhook import (
    extract_pr_identity,
    extract_review_info,
    bind_pr_identity,
    PRIdentity
)
from src.branch_protection import (
    is_branch_included,
    is_branch_status_check_protected,
    get_existing_protection_conf,
    apply_branch_protection_rule,
    update_protected_branches
)
from src.scan.scan_logic import process_scan
from src.secret_manager import get_secret
from src.settings import BLOCK_PR


class GitHubPRWebhook:
    def __init__(self):
        self.github_client = initialize_github_client()
        self.security_reviewers: list[str] = get_secret('SECURITY_REVIEWERS')
        self.protected_branches: dict[str, list[str]] = get_secret('PROTECTED_BRANCHES')

    def on_pull_request(self, webhook_data: dict[str, Any]) -> tuple:
        """
        Process a pull request event:
        1. Validate and normalize the identity carried by the signed payload.
        2. Check if the branch is monitored (no API call otherwise).
        3. Bind the payload identity to GitHub's authoritative PR object.
        4. Perform the security scan using only the bound identity.
        5. Only on a completed scan: request reviews / adjust protection rules.

        Any validation or binding failure aborts before the first side effect:
        no file fetching, no comments, no commit statuses, no protection changes.
        """

        try:
            identity: PRIdentity = extract_pr_identity(webhook_data)

            # Should this branch be scanned?
            if not is_branch_included(identity.repo_name, identity.branch_name):
                return JSONResponse(
                    content={
                        "message": (
                            f"{identity.repo_name}:{identity.branch_name} "
                            "is not monitored, skipping"
                        )
                    },
                    status_code=204
                )

            # Requires Repository permissions: Metadata -> Read
            repo = self.github_client.get_repo(identity.repo_name)

            # Requires Repository Permissions: Pull requests -> Read
            pr = repo.get_pull(identity.pr_number)

            # Reject payloads that do not actually describe this PR.
            bind_pr_identity(repo, pr, identity)

            # Malicious-code scan
            outcome = process_scan(repo, pr, identity.commit_sha)

            # Every remaining side effect is gated on a completed scan.
            if not outcome.status_posted:
                return JSONResponse(
                    content={"message": "No changed files to scan, no side effects performed"},
                    status_code=200
                )

            # Trigger a code review (optional)
            self._request_code_review(outcome.status, pr, identity.repo_name)

            # Block merging upon detection (optional)
            self._handle_block_mode(identity.repo_name, identity.branch_name)

            return JSONResponse(content={"message": "PR processed successfully"}, status_code=200)

        except KeyError as e:
            logger.error(f"Missing key in payload: {e}")
            return JSONResponse(content={"error": f"Missing key: {e}"}, status_code=400)
        except ValueError as e:
            logger.error(f"Invalid value encountered: {e}")
            return JSONResponse(content={"error": f"Invalid value: {e}"}, status_code=400)
        except GithubException as e:
            logger.error(f"GitHub API error: {e}")
            return JSONResponse(content={"error": "GitHub API request failed"}, status_code=502)

    def _request_code_review(
        self,
        status: str,
        pr: PullRequest,
        repo_name: str
    ) -> None:
        """
        If reviewers are defined, a review request is triggered upon detection.
        If block mode is enabled, merging is blocked until the scan passes.
        The scan passes either upon a code fix or upon a reviewer approval.
        """
        if status == 'failure':
            if self.security_reviewers:
                self._request_security_review(pr, repo_name)

    def _handle_block_mode(self, repo_name, branch_name):
        """
        1. Apply branch protection upon the first monitored pull request of a protected branch.
        2. Track protected branches.
        Called only after a scan posted its status, so protection can never
        deadlock a commit that has no corresponding check.
        """

        if self.security_reviewers and BLOCK_PR:
            """
            An initial "success" status could prevent unintentional blocking due to errors,
            but it creates a brief window for merging infected code, so we avoid it.

            You can change it, by adding the following call bellow this comment,
            and at the beginning of `on_pull_request`:
            
            create_commit_status(repo, pr.head.sha, "success", "Pass by default (set by user)")
            """

            protection = get_existing_protection_conf(repo_name, branch_name)
            if not is_branch_status_check_protected(protection):
                apply_branch_protection_rule(repo_name, branch_name, protection)
                self.protected_branches = update_protected_branches(
                    self.protected_branches,
                    repo_name,
                    branch_name
                )

    def _request_security_review(
        self,
        pr: PullRequest,
        repo_name: str,
    ):
        # Separate requests so if one request fails the rest still succeed.
        team_reviewers = []
        individual_reviewers = []
        for reviewer in self.security_reviewers:
            if reviewer.startswith("team:"):
                team_reviewers.append(reviewer[5:])
            else:
                individual_reviewers.append(reviewer)
        try:
            pr.create_review_request(team_reviewers=team_reviewers, reviewers=individual_reviewers)
            logger.info(
                f"Requested review from {self.security_reviewers} for {repo_name}, PR #{pr.number}"
            )
        except GithubException as e:
            logger.error(
                f"GitHub API error on review request for {repo_name}, PR #{pr.number}: {e}"
            )

    def on_pull_request_review(self, webhook_data: dict[str, Any]) -> tuple:
        """
        Change check status to "success" upon a pull request review approval event.
        If blocking mode (branch protection) was applied, this will release the block.
        """
        try:
            (
                repo_name,
                branch_name,
                pr_number,
                review_state,
                reviewer
            ) = extract_review_info(webhook_data)

            if review_state.lower() == "approved":
                logger.info(
                    f"Review approved by {reviewer}: {repo_name}/{branch_name}, PR #{str(pr_number)}"
                )
                # GitHub logins are case-insensitive; compare against the canonical form.
                allowed_reviewers = {
                    member[5:].lower() if member.startswith("team:") else member.lower()
                    for member in self.security_reviewers
                }
                if reviewer in allowed_reviewers:
                    repo = self.github_client.get_repo(repo_name)
                    pr = repo.get_pull(pr_number)
                    create_commit_status(
                        repo,
                        pr.head.sha,
                        "success",
                        f"Approved by {reviewer}"
                    )

            return JSONResponse(
                content={"message": "PR review processed successfully"},
                status_code=200
            )
        except KeyError as e:
            logger.error(f"Missing key in payload: {e}")
            return JSONResponse(content={"error": f"Missing key: {e}"}, status_code=400)
        except ValueError as e:
            logger.error(f"Invalid value encountered: {e}")
            return JSONResponse(content={"error": f"Invalid value: {e}"}, status_code=400)
        except GithubException as e:
            logger.error(f"GitHub API error: {e}")
            return JSONResponse(content={"error": "GitHub API request failed"}, status_code=502)
