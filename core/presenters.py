"""Presentation helpers for shaping RepoData into UI/report payloads.

These helpers are intentionally pure: they only map ``RepoData`` into
dict/list structures consumed by CLI output and dashboard views.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pandas as pd

from core.models import RepoActionsPermissionsData, RepoData
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
    if branch and branch.branch_protection_enabled:
        # Protection enabled with no active enforcement rules = nominal / trivially bypassable
        has_enforcement = (
            branch.enforce_admins_enabled
            or branch.required_approving_review_count > 0
            or branch.required_signatures_enabled
            or branch.require_code_owner_reviews
        )
        if not has_enforcement:
            flags.append("branch_protection_not_enforced")

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
    if is_template_gen:
        flags.append("generated_from_template")

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


#
# Org Security Posture Builders
#


def build_org_settings_rows(org_settings_data: Any) -> dict[str, Any]:
    return {
        "total_members": {
            "access": "ok",
            "total_members": org_settings_data["org_members"].total_members,
            "public_members": None,
        },
        "members_without_2fa": {
            "access": "ok",
            "members": [
                {"login": login}
                for login in org_settings_data["org_members"].members_without_2fa
            ],
        },
        "outside_collaborators": {
            "access": org_settings_data["org_outside_collaborators"].access,
            "collaborators": org_settings_data[
                "org_outside_collaborators"
            ].collaborators,
        },
        "teams": org_settings_data["org_teams"].teams,
        "audit_log_recent": {
            "access": org_settings_data["org_audit_log"].access,
            "entries": org_settings_data["org_audit_log"].entries,
        },
    }


def build_org_actions_posture_rows(org_actions_data: Any) -> dict[str, Any]:
    """Build the org actions posture rows from the org security posture report."""
    return {
        "runners": {
            "access": org_actions_data.access,
            "total_count": org_actions_data.self_hosted_runners,
            "runners": org_actions_data.runners,
        },
        "actions_permissions": {
            "access": org_actions_data.access,
            "allowed_actions": org_actions_data.allowed_actions_policy,
        },
        "credential_inventory": {
            "access": org_actions_data.access,
            "total_count": org_actions_data.org_secrets_count,
            "names": org_actions_data.org_secrets,
        },
        "default_workflow_permissions": {
            "access": org_actions_data.access,
            "default_workflow_permissions": org_actions_data.default_workflow_permissions,
        },
    }


def build_org_webhook_rows(org_webhook_data: Any) -> dict[str, Any]:
    apps = [
        {
            "app_slug": app.app_slug,
            "installation_id": app.installation_id,
            "repository_selection": app.repository_selection,
            "permissions": ", ".join(
                f"{scope}:{level}" for scope, level in sorted(app.permissions.items())
            ),
        }
        for app in org_webhook_data.installed_apps_detail
    ]
    if not apps and org_webhook_data.installed_apps:
        apps = [
            {
                "app_slug": app_slug,
                "installation_id": None,
                "repository_selection": None,
                "permissions": "",
            }
            for app_slug in org_webhook_data.installed_apps
        ]

    return {
        "webhooks": {
            "access": org_webhook_data.access,
            "count": org_webhook_data.webhooks_count,
            "hooks": org_webhook_data.hooks,
        },
        "github_apps": {
            "access": org_webhook_data.access,
            "total_count": len(apps),
            "apps": apps,
        },
    }


def build_org_ruleset_rows(org_ruleset_data: Any) -> dict[str, Any]:
    return {
        "access": org_ruleset_data.access,
        "count": org_ruleset_data.count,
        "rulesets": org_ruleset_data.rulesets,
    }


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


def workflow_repo_data_to_summary_row(full_name: str, data: RepoData) -> dict[str, Any]:
    """Map RepoData into github_workflow posture summary row schema."""
    repo = data.repo_details
    workflows = data.workflows
    actions_permissions = data.repo_actions_permissions or RepoActionsPermissionsData()
    owner, _, repo_name = full_name.partition("/")

    archived = repo.archived if repo else False
    default_branch = (repo.default_branch if repo else "") or "main"
    visibility = (repo.visibility if repo else "") or "unknown"

    workflow_count = workflows.count if workflows else 0
    has_workflows = workflow_count > 0
    workflow_names = ",".join(
        sorted(wf.get("name", "") for wf in (workflows.workflows if workflows else []))
    )

    actions_enabled = actions_permissions.enabled
    allowed_actions = actions_permissions.allowed_actions or ""

    if archived and has_workflows:
        posture = "archived_with_workflows"
    elif archived:
        posture = "archived_no_workflows"
    elif has_workflows:
        posture = "active_with_workflows"
    else:
        posture = "active_no_workflows"

    disable_candidate = (archived and has_workflows) or (
        not has_workflows and actions_enabled is True
    )

    return {
        "repo": full_name,
        "owner": owner,
        "repo_name": repo_name,
        "visibility": visibility,
        "archived": archived,
        "default_branch": default_branch,
        "actions_enabled": actions_enabled,
        "allowed_actions": allowed_actions,
        "has_workflows": has_workflows,
        "workflow_count": workflow_count,
        "workflow_names": workflow_names,
        "latest_workflow_run": (
            data.latest_workflow_run.created_at if data.latest_workflow_run else ""
        )
        or "",
        "posture": posture,
        "disable_candidate": disable_candidate,
    }


def workflow_repo_data_to_detail_rows(
    full_name: str,
    data: RepoData,
) -> list[dict[str, Any]]:
    """Map RepoData into github_workflow per-workflow detail row schema."""
    owner, _, repo_name = full_name.partition("/")
    workflows = data.workflows
    rows: list[dict[str, Any]] = []
    for wf in workflows.workflows if workflows else []:
        rows.append(
            {
                "repo": full_name,
                "owner": owner,
                "repo_name": repo_name,
                "workflow_name": wf.get("name", ""),
                "path": wf.get("path", ""),
                "state": wf.get("state", ""),
            }
        )
    return rows


def write_workflow_summary(
    path: str,
    repo_rows: list[dict[str, Any]],
    detail_rows: list[dict[str, Any]],
) -> None:
    """Write a human-readable summary report for github_workflow outputs."""
    total = len(repo_rows)
    with_wf = [r for r in repo_rows if r.get("has_workflows")]
    without_wf = [r for r in repo_rows if not r.get("has_workflows")]
    archived_with = [
        r for r in repo_rows if r.get("archived") and r.get("has_workflows")
    ]
    archived_without = [
        r for r in repo_rows if r.get("archived") and not r.get("has_workflows")
    ]
    active_with = [
        r for r in repo_rows if not r.get("archived") and r.get("has_workflows")
    ]
    active_without = [
        r for r in repo_rows if not r.get("archived") and not r.get("has_workflows")
    ]
    disable_candidates = [r for r in repo_rows if r.get("disable_candidate")]

    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "=" * 70,
        "GITHUB ACTIONS WORKFLOW POSTURE - DISCOVERY REPORT",
        f"Generated: {now}",
        "=" * 70,
        "",
        "OVERVIEW",
        "-" * 40,
        f"  Total repositories scanned:       {total}",
        f"  Repos using GitHub Actions:       {len(with_wf)} ({len(with_wf) / max(total, 1) * 100:.1f}%)",
        f"  Repos NOT using GitHub Actions:   {len(without_wf)} ({len(without_wf) / max(total, 1) * 100:.1f}%)",
        f"  Total workflow files found:       {len(detail_rows)}",
        "",
        "BREAKDOWN",
        "-" * 40,
        f"  Active repos with workflows:      {len(active_with)}",
        f"  Active repos without workflows:   {len(active_without)}",
        f"  Archived repos with workflows:    {len(archived_with)}",
        f"  Archived repos without workflows: {len(archived_without)}",
        "",
        f"  Candidates for disabling Actions: {len(disable_candidates)}",
        "  (archived repos with workflows + active repos with Actions enabled but no workflow files)",
        "",
    ]

    top_repos = sorted(with_wf, key=lambda x: -x.get("workflow_count", 0))[:15]
    if top_repos:
        lines.append("TOP REPOSITORIES BY WORKFLOW COUNT")
        lines.append("-" * 40)
        for r in top_repos:
            lines.append(f"  {r['repo']:<55} workflows={r.get('workflow_count', 0):>3}")
        lines.append("")

    if archived_with:
        lines.append("ARCHIVED REPOS WITH WORKFLOWS (DISABLE CANDIDATES)")
        lines.append("-" * 40)
        lines.append(
            "  (Actions should be disabled on archived repos to reduce attack surface)"
        )
        lines.append("")
        for r in archived_with:
            lines.append(f"  {r['repo']:<55} workflows={r.get('workflow_count', 0):>3}")
        lines.append("")

    actions_no_wf = [r for r in active_without if r.get("actions_enabled") is True]
    if actions_no_wf:
        lines.append("ACTIVE REPOS: ACTIONS ENABLED BUT NO WORKFLOWS")
        lines.append("-" * 40)
        lines.append("  (Consider disabling Actions if not needed)")
        lines.append("")
        for r in actions_no_wf[:20]:
            lines.append(f"  {r['repo']}")
        if len(actions_no_wf) > 20:
            lines.append(f"  ... and {len(actions_no_wf) - 20} more")
        lines.append("")

    lines += ["=" * 70, "END OF REPORT", "=" * 70]

    report = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"Wrote {path}")
    print()
    print(report)
