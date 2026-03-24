"""Presentation helpers for shaping RepoData into UI/report payloads.

These helpers are intentionally pure: they only map ``RepoData`` into
dict/list structures consumed by CLI output and dashboard views.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from core.models import RepoData


def flags_for_list(data: RepoData) -> list[str]:
    """Return list-relevant flags for a repository row."""
    repo = data.repo_details
    alerts = data.alerts
    branch = data.branch_protection

    if repo is None:
        return []

    flags: list[str] = []
    if repo.archived:
        flags.append("archived")
    if repo.fork:
        flags.append("fork")
    if not repo.private and branch and not branch.default_branch_protected:
        flags.append("public_unprotected_default_branch")
    if alerts and alerts.dependabot_alerts > 0:
        flags.append("dependabot_alerts_present")
    if alerts and alerts.secret_scanning_alerts > 0:
        flags.append("secret_scanning_alerts_present")
    if alerts and alerts.code_scanning_alerts > 0:
        flags.append("code_scanning_alerts_present")

    return flags


def flags_for_dashboard(data: RepoData) -> list[str]:
    """Return dashboard-focused human-readable flags."""
    repo = data.repo_details
    alerts = data.alerts
    branch = data.branch_protection
    community = data.community
    workflows = data.workflows
    fork_template = data.fork_template

    if repo is None:
        return []

    flags: list[str] = []
    if repo.archived:
        flags.append("archived")
    if fork_template and fork_template.is_fork:
        flags.append(
            f"fork_of_{fork_template.fork_source}"
            if fork_template.fork_source
            else "fork"
        )
    if fork_template and fork_template.is_generated_from_template:
        flags.append(
            f"generated_from_template_{fork_template.template_source}"
            if fork_template.template_source
            else "generated_from_template"
        )
    if repo.license is None:
        flags.append("no_license")
    if not repo.private and branch and not branch.default_branch_protected:
        flags.append("public_unprotected_default_branch")
    if alerts and alerts.dependabot_alerts > 0:
        flags.append("dependabot_alerts_present")
    if alerts and alerts.secret_scanning_alerts > 0:
        flags.append("secret_alerts_present")
    if alerts and alerts.code_scanning_alerts > 0:
        flags.append("code_scanning_alerts_present")

    community_files = (community.files if community else None) or {}
    if not community_files.get("security_policy"):
        flags.append("no_security_policy")
    if not community_files.get("code_of_conduct"):
        flags.append("no_code_of_conduct")

    workflow_analysis = workflows.analysis if workflows and workflows.analysis else None
    if not workflows or workflows.count == 0:
        flags.append("no_actions_workflows")
    else:
        if not (workflow_analysis and workflow_analysis.has_tests):
            flags.append("no_detected_tests")
        if not (workflow_analysis and workflow_analysis.has_linting):
            flags.append("no_detected_linting")

    return flags


def repo_data_to_list_row(full_name: str, data: RepoData) -> dict[str, Any]:
    """Map RepoData into the list_repos output row schema."""
    repo = data.repo_details
    alerts = data.alerts
    branch = data.branch_protection
    codeowners = data.codeowners
    fork_template = data.fork_template

    owner = full_name.split("/", 1)[0] if "/" in full_name else None
    list_flags = flags_for_list(data)

    return {
        "org": owner,
        "repo": repo.name if repo else full_name,
        "full_name": full_name,
        "private": repo.private if repo else None,
        "archived": repo.archived if repo else None,
        "fork": repo.fork if repo else None,
        "fork_source": fork_template.fork_source if fork_template else None,
        "is_generated_from_template": (
            fork_template.is_generated_from_template if fork_template else None
        ),
        "template_source": fork_template.template_source if fork_template else None,
        "pushed_at": repo.pushed_at if repo else None,
        "default_branch": repo.default_branch if repo else None,
        "language": repo.language if repo else None,
        "open_issues": repo.open_issues_count if repo else None,
        "stargazers": repo.stargazers_count if repo else None,
        "dependabot_access": alerts.dependabot_access if alerts else None,
        "dependabot_alerts": alerts.dependabot_alerts if alerts else None,
        "code_scanning_access": alerts.code_scanning_access if alerts else None,
        "code_scanning_alerts": alerts.code_scanning_alerts if alerts else None,
        "secret_scanning_access": alerts.secret_scanning_access if alerts else None,
        "secret_scanning_alerts": alerts.secret_scanning_alerts if alerts else None,
        "default_branch_protected": (
            branch.default_branch_protected if branch else None
        ),
        "protection_settings": branch.protection_settings if branch else None,
        "codeowners": codeowners.present if codeowners else None,
        "flags": ", ".join(list_flags),
    }


def repo_data_to_dashboard_row(full_name: str, data: RepoData) -> dict[str, Any]:
    """Map RepoData into the dashboard table row schema."""
    repo = data.repo_details
    alerts = data.alerts
    branch = data.branch_protection
    codeowners = data.codeowners
    dashboard_flags = flags_for_dashboard(data)

    return {
        "repo": full_name,
        "private": repo.private if repo else None,
        "archived": repo.archived if repo else None,
        "fork": repo.fork if repo else None,
        "language": repo.language if repo else None,
        "stars": repo.stargazers_count if repo else 0,
        "open_issues": repo.open_issues_count if repo else 0,
        "dependabot_alerts": alerts.dependabot_alerts if alerts else None,
        "secret_alerts": alerts.secret_scanning_alerts if alerts else None,
        "code_scanning_alerts": alerts.code_scanning_alerts if alerts else None,
        "branch_protected": branch.default_branch_protected if branch else None,
        "codeowners": codeowners.present if codeowners else None,
        "flags": ", ".join(dashboard_flags),
        "pushed_at": repo.pushed_at if repo else "",
    }


def repo_data_to_audit_result(data: RepoData) -> dict[str, Any]:
    """Map RepoData into dashboard detail-panel audit payload."""
    repo = data.repo_details.model_dump() if data.repo_details else {}
    alerts = data.alerts.model_dump() if data.alerts else {}
    branch_protection = (
        data.branch_protection.model_dump() if data.branch_protection else {}
    )
    community = data.community.model_dump() if data.community else {}
    codeowners = data.codeowners.model_dump() if data.codeowners else {}
    workflows = data.workflows
    fork_template = data.fork_template.model_dump() if data.fork_template else {}

    workflow_analysis: dict[str, Any] = {}
    workflow_payload: dict[str, Any] = {"count": 0, "list": []}
    if workflows:
        workflow_payload = {
            "count": workflows.count,
            "list": workflows.workflows,
        }
        if workflows.analysis:
            workflow_analysis = workflows.analysis.model_dump()

    return {
        "repo": repo,
        "alerts": alerts,
        "branch_protection": branch_protection,
        "community": community,
        "codeowners": codeowners,
        "workflows": workflow_payload,
        "workflow_analysis": workflow_analysis,
        "fork_and_template": fork_template,
        "flags": flags_for_dashboard(data),
    }


def build_repo_summary_table(df: pd.DataFrame) -> pd.DataFrame:
    """Build the summary metrics table used in list_repos outputs."""
    if df.empty:
        values = [0] * 8
    else:
        values = [
            len(df),
            int((~df["private"].fillna(False)).sum()),
            int(df["private"].fillna(False).sum()),
            int(df["archived"].fillna(False).sum()),
            int((df["dependabot_alerts"].fillna(0) > 0).sum()),
            int((df["secret_scanning_alerts"].fillna(0) > 0).sum()),
            int((df["code_scanning_alerts"].fillna(0) > 0).sum()),
            int((~df["default_branch_protected"].fillna(False)).sum()),
        ]

    return pd.DataFrame(
        {
            "metric": [
                "repos_total",
                "repos_public",
                "repos_private",
                "repos_archived",
                "repos_with_dependabot_alerts",
                "repos_with_secret_alerts",
                "repos_with_code_scanning_alerts",
                "repos_unprotected_default_branch",
            ],
            "value": values,
        }
    )
