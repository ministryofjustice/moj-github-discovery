"""Presentation helpers for shaping RepoData into UI/report payloads.

These helpers are intentionally pure: they only map ``RepoData`` into
dict/list structures consumed by CLI output and dashboard views.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from core.models import RepoData
from core.storage import BaseStorage


def flags_for_list(data: RepoData) -> list[str]:
    """Return list-relevant flags for a repository row."""
    repo = data.repo_details
    branch = data.branch_protection

    if repo is None:
        return []

    flags: list[str] = []
    if repo.archived:
        flags.append("archived")
    if not repo.pushed_at:
        flags.append("empty_repo_no_push_activity")
    if repo.fork:
        flags.append("fork")
    if repo.visibility == "public" and branch and not branch.default_branch_protected:
        flags.append("public_unprotected_default_branch")

    return flags


def flags_for_dashboard(data: RepoData) -> list[str]:
    """Return dashboard-focused human-readable flags."""
    repo = data.repo_details
    alerts = data.alerts
    branch = data.branch_protection
    workflows = data.workflows
    fork_template = data.fork_template

    if repo is None:
        return []

    flags: list[str] = []
    if repo.archived:
        flags.append("archived")
    if not repo.pushed_at:
        flags.append("empty_repo_no_push_activity")

    # Prefer fork_template when present (archive_repos run), fall back to repo_details
    is_fork = fork_template.is_fork if fork_template else repo.fork
    fork_src = (
        fork_template.fork_source
        if fork_template and fork_template.fork_source not in (None, "N/A")
        else None
    ) or repo.parent_repo_full_name
    if is_fork:
        flags.append(f"fork_of_{fork_src}" if fork_src else "fork")

    is_template_gen = (
        fork_template.is_generated_from_template
        if fork_template
        else bool(repo.template_repo_full_name)
    )
    tmpl_src = (
        fork_template.template_source
        if fork_template and fork_template.template_source not in (None, "N/A")
        else None
    ) or repo.template_repo_full_name
    if is_template_gen:
        flags.append(
            f"generated_from_template_{tmpl_src}"
            if tmpl_src
            else "generated_from_template"
        )

    license_info = getattr(repo, "license", None)
    if license_info is None:
        flags.append("no_license")
    if repo.visibility == "public" and branch and not branch.default_branch_protected:
        flags.append("public_unprotected_default_branch")
    if alerts and alerts.dependabot_alerts > 0:
        flags.append("dependabot_alerts_present")
    if alerts and alerts.secret_scanning_alerts > 0:
        flags.append("secret_alerts_present")
    if alerts and alerts.code_scanning_alerts > 0:
        flags.append("code_scanning_alerts_present")

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
    branch = data.branch_protection
    codeowners = data.codeowners
    fork_template = data.fork_template
    repo_rulesets = data.repo_rulesets

    owner = full_name.split("/", 1)[0] if "/" in full_name else None
    list_flags = flags_for_list(data)

    # Robust fallbacks to keep output stable when some endpoint payloads are missing.
    visibility = repo.visibility if repo and repo.visibility else "unknown"
    last_push_activity = repo.pushed_at if repo else None
    last_pushed_at = (
        data.default_branch_commit.last_pushed_at
        if data.default_branch_commit
        else None
    )
    if not last_pushed_at:
        last_pushed_at = last_push_activity
    if not last_push_activity:
        last_push_activity = "N/A"
    if not last_pushed_at:
        last_pushed_at = "N/A"

    is_fork = repo.fork if repo else (fork_template.is_fork if fork_template else None)
    if is_fork is False:
        fork_source = "N/A"
    elif is_fork is True:
        fork_source = (
            (repo.parent_repo_full_name if repo else None)
            or (
                fork_template.fork_source
                if fork_template and fork_template.fork_source not in (None, "N/A")
                else None
            )
            or "UNKNOWN"
        )
    else:
        fork_source = None

    is_generated_from_template = bool(
        (repo.template_repo_full_name if repo else None)
        or (fork_template.is_generated_from_template if fork_template else False)
    )
    if not is_generated_from_template:
        template_source = "N/A"
    else:
        template_source = (
            (repo.template_repo_full_name if repo else None)
            or (
                fork_template.template_source
                if fork_template and fork_template.template_source not in (None, "N/A")
                else None
            )
            or "UNKNOWN"
        )

    # Resolve Compliance Method (Branch Protection vs Rulesets) for the default branch
    compliance_method = "none"
    if branch and branch.branch_protection_enabled:
        compliance_method = "branch_protection"
    elif repo_rulesets and repo_rulesets.has_active_rulesets:
        compliance_method = "rulesets"

    # Resolve Compliance Method-Specific Flags
    if compliance_method == "branch_protection":
        enforce_admins = branch.enforce_admins_enabled if branch else None
        dismiss_stale_reviews = branch.dismiss_stale_reviews if branch else None
        require_code_owner_reviews = (
            branch.require_code_owner_reviews if branch else None
        )
        required_approving_review_count = (
            branch.required_approving_review_count if branch else None
        )
        required_signatures = branch.required_signatures_enabled if branch else None
    elif compliance_method == "rulesets":
        enforce_admins = repo_rulesets.enforce_admins if repo_rulesets else None
        dismiss_stale_reviews = (
            repo_rulesets.dismiss_stale_reviews if repo_rulesets else None
        )
        require_code_owner_reviews = (
            repo_rulesets.require_code_owner_reviews if repo_rulesets else None
        )
        required_approving_review_count = (
            repo_rulesets.required_approving_review_count if repo_rulesets else None
        )
        required_signatures = (
            repo_rulesets.required_signatures if repo_rulesets else None
        )
    else:
        enforce_admins = False
        dismiss_stale_reviews = False
        require_code_owner_reviews = False
        required_approving_review_count = 0
        required_signatures = False

    return {
        "org": owner,
        "repo": repo.name if repo else full_name,
        "full_name": full_name,
        "visibility": visibility,
        "archived": repo.archived if repo else None,
        "fork": is_fork,
        "fork_source": fork_source,
        "is_generated_from_template": is_generated_from_template,
        "template_source": template_source,
        "last_pushed_at": last_pushed_at,
        "last_push_activity": last_push_activity,
        "default_branch": repo.default_branch if repo else None,
        "language": repo.language if repo else None,
        "open_issues": repo.open_issues_count if repo else None,
        "stargazers": repo.stargazers_count if repo else None,
        "disabled": repo.disabled if repo else None,
        "is_template": repo.is_template if repo else None,
        "size": repo.size if repo else None,
        "created_at": repo.created_at if repo else None,
        "updated_at": repo.updated_at if repo else None,
        "license": repo.license if repo else None,
        "default_branch_protected": (
            branch.default_branch_protected if branch else None
        ),
        "compliance_method": compliance_method,
        "branch_protection_enabled": branch.branch_protection_enabled
        if branch
        else None,
        "has_active_rulesets": repo_rulesets.has_active_rulesets
        if repo_rulesets
        else None,
        "protection_settings": branch.protection_settings if branch else None,
        "enforce_admin_protection": enforce_admins,
        "dismiss_stale_reviews": dismiss_stale_reviews,
        "require_code_owner_reviews": require_code_owner_reviews,
        "required_approving_review_count": required_approving_review_count,
        "required_signatures": required_signatures,
        "codeowners": codeowners.present if codeowners else None,
        "codeowners_path": codeowners.path if codeowners else None,
        "flags": ", ".join(list_flags),
    }


def repo_data_to_dashboard_row(full_name: str, data: RepoData) -> dict[str, Any]:
    """Map RepoData into the dashboard table row schema."""
    repo = data.repo_details
    alerts = data.alerts
    branch = data.branch_protection
    codeowners = data.codeowners
    dashboard_flags = flags_for_dashboard(data)

    visibility = repo.visibility if repo and repo.visibility else "unknown"
    last_push_activity = repo.pushed_at if repo else ""
    last_pushed_at = (
        data.default_branch_commit.last_pushed_at
        if data.default_branch_commit
        else None
    )
    if not last_pushed_at:
        last_pushed_at = last_push_activity
    if not last_push_activity:
        last_push_activity = "N/A"
    if not last_pushed_at:
        last_pushed_at = "N/A"

    return {
        "repo": full_name,
        "visibility": visibility,
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
        "last_pushed_at": last_pushed_at,
        "last_push_activity": last_push_activity,
    }


def build_dashboard_dataframe(storage: BaseStorage) -> pd.DataFrame:
    """Build the dashboard row dataframe from storage contents."""
    rows = [
        repo_data_to_dashboard_row(full_name, data)
        for full_name, data in storage.read_all()
    ]
    return pd.DataFrame(rows)


def repo_data_to_audit_result(data: RepoData) -> dict[str, Any]:
    """Map RepoData into dashboard detail-panel audit payload."""
    repo = data.repo_details.model_dump() if data.repo_details else {}
    alerts = data.alerts.model_dump() if data.alerts else {}
    branch_protection = (
        data.branch_protection.model_dump() if data.branch_protection else {}
    )
    codeowners = data.codeowners.model_dump() if data.codeowners else {}
    workflows = data.workflows
    fork_template = data.fork_template.model_dump() if data.fork_template else {}
    repo_rulesets = data.repo_rulesets.model_dump() if data.repo_rulesets else {}

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
        "repo_rulesets": repo_rulesets,
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
            int((df["visibility"].fillna("") == "public").sum()),
            int((df["visibility"].fillna("") == "private").sum()),
            int((df["visibility"].fillna("") == "internal").sum()),
            int(df["archived"].fillna(False).sum()),
            int((~df["default_branch_protected"].fillna(False)).sum()),
            int(df["branch_protection_enabled"].fillna(False).sum()),
            int(df["has_active_rulesets"].fillna(False).sum()),
        ]

    return pd.DataFrame(
        {
            "metric": [
                "repos_total",
                "repos_public",
                "repos_private",
                "repos_internal",
                "repos_archived",
                "repos_unprotected_default_branch",
                "repos_using_classic_branch_protection",
                "repos_with_active_rulesets",
            ],
            "value": values,
        }
    )


def build_org_security_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Build a high-level summary dict from an org security posture report."""
    overview = report.get("org_overview", {})
    org_settings = report.get("1_org_settings", {})
    ghas = report.get("2_ghas_alerts", {})
    deps = report.get("3_dependency_supply_chain", {}).get("summary", {})
    actions = report.get("4_actions_posture", {}).get("details", {})
    webhooks = report.get("5_webhooks_integrations", {}).get("details", {})
    rulesets = report.get("6_rulesets", {}).get("details", {})

    def val_or_no_access(data: dict[str, Any], key: str) -> Any:
        access = data.get("access")
        if access and access != "ok":
            return f"no_access ({access})"
        val = data.get(key)
        return val if val is not None else 0

    summary: dict[str, Any] = {}
    summary["org_name"] = overview.get("name", "")
    summary["public_repos"] = overview.get("public_repos")
    summary["total_private_repos"] = overview.get("total_private_repos", "no_access")
    summary["2fa_requirement_enabled"] = overview.get("two_factor_requirement_enabled")
    summary["default_repo_permission"] = overview.get("default_repository_permission")
    summary["default_branch"] = overview.get("default_repository_branch")

    total_members = org_settings.get("total_members", {})
    summary["total_members"] = (
        val_or_no_access(total_members, "total_members")
        if isinstance(total_members, dict)
        else "no_access"
    )
    mfa_data = org_settings.get("members_without_2fa", {})
    summary["members_without_2fa"] = (
        len(mfa_data.get("members", [])) if isinstance(mfa_data, dict) else "no_access"
    )

    collabs_data = org_settings.get("outside_collaborators", {})
    summary["outside_collaborators"] = (
        len(collabs_data.get("collaborators", []))
        if isinstance(collabs_data, dict)
        else "no_access"
    )
    teams = org_settings.get("teams", [])
    summary["teams_count"] = len(teams) if isinstance(teams, list) else "no_access"

    summary["code_scanning_open_alerts"] = val_or_no_access(
        ghas.get("code_scanning", {}), "open_count"
    )
    summary["credential_scanning_open_alerts"] = val_or_no_access(
        ghas.get("secret_scanning", {}), "open_count"
    )

    summary["repos_checked_for_supply_chain"] = deps.get("repos_checked", 0)
    summary["repos_with_sbom"] = deps.get("sbom_available", 0)
    summary["repos_with_branch_protection"] = deps.get("default_branch_protected", 0)

    summary["self_hosted_runners"] = val_or_no_access(
        actions.get("runners", {}), "total_count"
    )
    summary["allowed_actions_policy"] = val_or_no_access(
        actions.get("actions_permissions", {}), "allowed_actions"
    )
    summary["org_credential_count"] = val_or_no_access(
        actions.get("credential_inventory", {}), "total_count"
    )
    summary["default_workflow_permissions"] = val_or_no_access(
        actions.get("default_workflow_permissions", {}), "default_workflow_permissions"
    )

    summary["org_webhooks_count"] = val_or_no_access(
        webhooks.get("webhooks", {}), "count"
    )
    summary["installed_github_apps"] = val_or_no_access(
        webhooks.get("github_apps", {}), "total_count"
    )
    summary["org_rulesets_count"] = val_or_no_access(rulesets, "count")
    return summary
