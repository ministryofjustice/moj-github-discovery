"""GitHub REST API endpoint layer.

Each endpoint is a class that calls one (or a small set of related) GitHub
REST paths and returns a typed Pydantic model.  Two abstract bases are
provided:

* :class:`BaseEndpoint`    — repo-scoped (called once per repo)
* :class:`BaseOrgEndpoint` — org-scoped  (called once per org)

Concrete endpoints are registered in :data:`REPO_ENDPOINTS` /
:data:`ORG_ENDPOINTS`.  The collector iterates through these lists
automatically — adding a new endpoint requires only:

1. Add a Pydantic model to ``core/models.py`` (if needed).
2. Subclass ``BaseEndpoint`` here.
3. Register the class in ``REPO_ENDPOINTS``.

See ``CONTRIBUTING.md § 1`` for a full walkthrough.

Migration notes
---------------
Consolidates endpoint logic from ``utils.py`` (``count_alerts``,
``branch_protection``, ``check_codeowners_exists``, ``fork_and_template_info``),
the legacy single-repo audit script (``repo_info``, ``community_profile``, ``list_workflows``,
``analyze_workflows``), ``archive_repos.py`` (``_search_references``), and
``org_security_posture.py`` (all org-level functions).
"""

from __future__ import annotations

import base64
import time
from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel

from core.github_client import BaseHttpClient
from core.models import (
    AlertData,
    BranchProtection,
    CodeownersData,
    CommunityProfile,
    DependencyGraphData,
    ForkTemplateData,
    OrgActionsData,
    OrgAuditLogData,
    OrgCodeScanningAlertsData,
    OrgMembersData,
    OrgOutsideCollaboratorsData,
    OrgOverviewData,
    OrgRulesetsData,
    OrgSecretScanningAlertsData,
    OrgTeamsData,
    OrgWebhooksData,
    ReferenceData,
    ReferenceItem,
    RepoDetails,
    WorkflowAnalysis,
    WorkflowData,
    WorkflowPermissionFinding,
)


# ── Helpers ───────────────────────────────────────────────────────────


def list_org_repos(
    org: str,
    client: BaseHttpClient,
    *,
    type: Literal["all", "public", "private", "forks", "sources", "member"] = "all",
    sort: Literal["created", "updated", "pushed", "full_name"] = "pushed",
    direction: Literal["asc", "desc"] | None = None,
) -> list[str]:
    """Return a list of ``owner/repo`` strings for all repos in an organisation.

    Args:
        org:       GitHub organisation login name.
        client:    HTTP client to use for the request.
        type:      Filter by repo type.  ``"all"`` returns every repo.
        sort:      Property to sort results by.
        direction: Sort order.  Defaults to ``"asc"`` when *sort* is
                   ``"full_name"``, otherwise ``"desc"`` (GitHub API default).
    """
    params = f"type={type}&sort={sort}"
    if direction is not None:
        params += f"&direction={direction}"
    items = client.get_paginated(f"/orgs/{org}/repos?{params}")
    return [r["full_name"] for r in items if isinstance(r, dict) and "full_name" in r]


def dependency_supply_chain_summary(
    org: str,
    client: BaseHttpClient,
    repo_limit: int = 100,
    repo_full_names: list[str] | None = None,
) -> dict[str, object]:
    """Return org-level supply-chain summary by sampling/pinning repositories."""
    cap = max(1, min(repo_limit, 100))
    repos: list[dict[str, object]] = []
    if repo_full_names is not None:
        for full_name in repo_full_names:
            owner, sep, name = full_name.partition("/")
            if sep != "/" or not owner or not name:
                continue
            try:
                repo_data = client.get(f"/repos/{owner}/{name}")
            except Exception:
                continue
            if isinstance(repo_data, dict):
                repos.append(repo_data)
        cap = len(repos)
    else:
        try:
            repos = client.get_paginated(
                f"/orgs/{org}/repos?sort=pushed&direction=desc"
            )
        except Exception:
            repos = []

    details: list[dict[str, object]] = []
    for repo in repos[:cap]:
        owner = (repo.get("owner") or {}).get("login", "")
        name = repo.get("name", "")
        full_name = f"{owner}/{name}"
        default_branch = repo.get("default_branch", "main")

        try:
            client.get(f"/repos/{owner}/{name}/dependency-graph/sbom")
            sbom_available = True
        except Exception:
            sbom_available = False

        try:
            branch = client.get(f"/repos/{owner}/{name}/branches/{default_branch}")
            branch_protected = bool(branch.get("protected", False))
        except Exception:
            branch_protected = False

        details.append(
            {
                "repo": full_name,
                "visibility": repo.get("visibility", ""),
                "archived": bool(repo.get("archived", False)),
                "default_branch": default_branch,
                "license": ((repo.get("license") or {}).get("spdx_id") or "none"),
                "topics": ", ".join(repo.get("topics") or []),
                "sbom_available": sbom_available,
                "default_branch_protected": branch_protected,
            }
        )

    return {
        "repos_checked": len(details),
        "sbom_available": sum(1 for d in details if d["sbom_available"]),
        "default_branch_protected": sum(
            1 for d in details if d["default_branch_protected"]
        ),
        "details": details,
    }


def fetch_repo_actions_permissions(
    client: BaseHttpClient,
    owner: str,
    repo: str,
) -> dict[str, Any]:
    """Return repo-level Actions permissions from the GitHub API."""
    try:
        data = client.get(f"/repos/{owner}/{repo}/actions/permissions")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def fetch_latest_workflow_run_created_at(
    client: BaseHttpClient,
    owner: str,
    repo: str,
) -> str | None:
    """Return created_at of the most recent workflow run for a repo."""
    try:
        data = client.get(f"/repos/{owner}/{repo}/actions/runs?per_page=1")
        if isinstance(data, dict):
            runs = data.get("workflow_runs", [])
            if runs:
                first = runs[0]
                if isinstance(first, dict):
                    return first.get("created_at")
        return None
    except Exception:
        return None


def fetch_repo_file_text(
    client: BaseHttpClient,
    owner: str,
    repo: str,
    path: str,
) -> str | None:
    """Return UTF-8 file text for a repository path via contents API."""
    try:
        data = client.get(f"/repos/{owner}/{repo}/contents/{path}")
        if not (isinstance(data, dict) and data.get("encoding") == "base64"):
            return None
        content = data.get("content")
        if not isinstance(content, str):
            return None
        return base64.b64decode(content).decode("utf-8")
    except Exception:
        return None


def check_workflow_permissions(
    client: BaseHttpClient,
    owner: str,
    repo_name: str,
    workflow_path: str,
) -> WorkflowPermissionFinding:
    """Check if a workflow file has explicit permissions defined and flag broad scopes."""
    content = fetch_repo_file_text(client, owner, repo_name, workflow_path)
    if content is None:
        return WorkflowPermissionFinding(
            repo=f"{owner}/{repo_name}",
            workflow_path=workflow_path,
            finding="could_not_load",
        )

    has_permissions = False
    permissions_value = ""
    has_write = False
    finding = "no_permissions_block"

    in_permissions_block = False
    permissions_lines: list[str] = []

    for line in content.splitlines():
        stripped = line.strip()

        if line.startswith("permissions:") or line.startswith("permissions :"):
            has_permissions = True
            in_permissions_block = True
            parts = stripped.split(":", 1)
            if len(parts) > 1 and parts[1].strip():
                permissions_value = parts[1].strip()
                in_permissions_block = False
            continue

        if in_permissions_block:
            if stripped and not line[0].isspace():
                in_permissions_block = False
            elif stripped:
                permissions_lines.append(stripped)

    if permissions_lines:
        permissions_value = "; ".join(permissions_lines)

    if not has_permissions:
        finding = "no_permissions_block"
    elif "write-all" in permissions_value:
        finding = "write-all"
        has_write = True
    elif "write" in permissions_value:
        finding = "has_write_scope"
        has_write = True
    else:
        finding = "compliant"

    return WorkflowPermissionFinding(
        repo=f"{owner}/{repo_name}",
        workflow_path=workflow_path,
        has_explicit_permissions=has_permissions,
        permissions_value=permissions_value,
        has_write_permissions=has_write,
        finding=finding,
    )


def fetch_repo_alerts(
    client: BaseHttpClient,
    owner: str,
    repo: str,
    kind: Literal["dependabot", "code_scanning", "secret_scanning"],
) -> list[dict[str, Any]]:
    """Return raw alert rows for one alert kind on a repository."""
    endpoint_map = {
        "dependabot": "dependabot/alerts",
        "code_scanning": "code-scanning/alerts",
        "secret_scanning": "secret-scanning/alerts",
    }
    endpoint = endpoint_map[kind]
    items = client.get_paginated(f"/repos/{owner}/{repo}/{endpoint}")
    return [item for item in items if isinstance(item, dict)]


# ── Abstract bases ────────────────────────────────────────────────────


class BaseEndpoint(ABC):
    """Repo-scoped GitHub API endpoint.

    Subclass this and implement ``name`` and ``fetch``, then register the
    class in :data:`REPO_ENDPOINTS`.

    The ``name`` property **must** match the corresponding field on
    :class:`~core.models.RepoData` so that the collector can write the
    result via ``RepoData(**{endpoint.name: result})``.

    Example::

        class ReleasesEndpoint(BaseEndpoint):
            @property
            def name(self) -> str:
                return "releases"          # must match RepoData.releases

            def fetch(self, owner: str, repo: str) -> ReleaseData:
                items = self.client.get_paginated(
                    f"/repos/{owner}/{repo}/releases"
                )
                return ReleaseData(count=len(items))
    """

    def __init__(self, client: BaseHttpClient) -> None:
        self.client = client

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique key stored as a field name in the ``repo_data`` JSON blob.

        Must match the corresponding field name on ``RepoData``.
        """

    @abstractmethod
    def fetch(self, owner: str, repo: str) -> BaseModel:
        """Call the GitHub API and return a validated Pydantic model.

        Args:
            owner: Repository owner (org or user login).
            repo:  Repository name (without the owner prefix).

        Returns:
            A Pydantic ``BaseModel`` instance corresponding to this endpoint's
            ``name`` field on ``RepoData``.
        """


class BaseOrgEndpoint(ABC):
    """Org-scoped GitHub API endpoint.

    Works like :class:`BaseEndpoint` but operates at the organisation level.
    Register in :data:`ORG_ENDPOINTS`.

    The ``name`` property should be a unique key describing the org-level
    data being collected (e.g. ``"org_members"``, ``"org_actions"``).
    """

    def __init__(self, client: BaseHttpClient) -> None:
        self.client = client

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique key for this org-level data source."""

    @abstractmethod
    def fetch(self, org: str) -> BaseModel:
        """Call the GitHub API and return a validated Pydantic model.

        Args:
            org: GitHub organisation login name.
        """


# ── Repo-scoped endpoints ─────────────────────────────────────────────


class RepoDetailsEndpoint(BaseEndpoint):
    """Core repository metadata from ``/repos/{owner}/{repo}``.

    Migrated from ``audit_repo.repo_info`` and ``utils.gh_api``.
    """

    @property
    def name(self) -> str:
        return "repo_details"

    def fetch(self, owner: str, repo: str) -> RepoDetails:
        data = self.client.get(f"/repos/{owner}/{repo}")
        data["org"] = owner
        return RepoDetails.model_validate(data)


class AlertsEndpoint(BaseEndpoint):
    """Open security alert counts — Dependabot, code scanning, secret scanning.

    Migrated from ``utils.count_alerts``.
    """

    @property
    def name(self) -> str:
        return "alerts"

    def fetch(self, owner: str, repo: str) -> AlertData:
        result: dict = {}
        for alert_type, key in [
            ("dependabot/alerts", "dependabot"),
            ("code-scanning/alerts", "code_scanning"),
            ("secret-scanning/alerts", "secret_scanning"),
        ]:
            try:
                items = self.client.get_paginated(
                    f"/repos/{owner}/{repo}/{alert_type}?state=open"
                )
                result[f"{key}_alerts"] = len(items)
                result[f"{key}_access"] = "ok"
            except Exception as exc:
                result[f"{key}_alerts"] = 0
                result[f"{key}_access"] = str(exc)
        return AlertData.model_validate(result)


class BranchProtectionEndpoint(BaseEndpoint):
    """Default branch protection status and active settings.

    Migrated from ``utils.branch_protection``.
    """

    @property
    def name(self) -> str:
        return "branch_protection"

    def fetch(
        self,
        owner: str,
        repo: str,
        repo_details: RepoDetails | None = None,
    ) -> BranchProtection:
        try:
            default_branch = repo_details.default_branch if repo_details else "main"
            branch = self.client.get(f"/repos/{owner}/{repo}/branches/{default_branch}")
            protected = bool(branch.get("protected", False))
            settings: list[str] = []
            bp = branch.get("protection", {})
            if bp.get("required_status_checks"):
                settings.append("required_status_checks")
            if bp.get("required_pull_request_reviews"):
                settings.append("required_pr_reviews")
            if bp.get("enforce_admins", {}).get("enabled"):
                settings.append("enforce_admins")
            return BranchProtection(
                default_branch_protected=protected,
                protection_settings=settings,
            )
        except Exception as exc:
            return BranchProtection(branch_protection_access=str(exc))


class CommunityProfileEndpoint(BaseEndpoint):
    """Community health profile — policy files and health percentage.

    Migrated from ``audit_repo.community_profile``.
    """

    @property
    def name(self) -> str:
        return "community"

    def fetch(self, owner: str, repo: str) -> CommunityProfile:
        try:
            data = self.client.get(f"/repos/{owner}/{repo}/community/profile")
            return CommunityProfile.model_validate(data)
        except Exception:
            return CommunityProfile()


class CodeownersEndpoint(BaseEndpoint):
    """Whether a CODEOWNERS file exists and its location.

    Migrated from ``utils.check_codeowners_exists``.
    """

    @property
    def name(self) -> str:
        return "codeowners"

    _LOCATIONS = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]

    def fetch(self, owner: str, repo: str) -> CodeownersData:
        try:
            repo_data = self.client.get(f"/repos/{owner}/{repo}")
            default_branch = repo_data.get("default_branch", "main")
            tree = self.client.get(
                f"/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
            )
            paths = {item["path"] for item in tree.get("tree", [])}
            for loc in self._LOCATIONS:
                if loc in paths:
                    return CodeownersData(present=True, path=loc)
        except Exception:
            pass
        return CodeownersData(present=False)


class ForkTemplateEndpoint(BaseEndpoint):
    """Fork source and template origin details.

    Migrated from ``utils.fork_and_template_info``.
    """

    @property
    def name(self) -> str:
        return "fork_template"

    def fetch(self, owner: str, repo: str) -> ForkTemplateData:
        try:
            data = self.client.get(f"/repos/{owner}/{repo}")
            parent = data.get("parent") or data.get("source")
            template = data.get("template_repository")
            return ForkTemplateData(
                is_fork=bool(data.get("fork")),
                fork_source=parent["full_name"] if parent else None,
                is_generated_from_template=bool(template),
                template_source=template["full_name"] if template else None,
            )
        except Exception:
            return ForkTemplateData()


class WorkflowsEndpoint(BaseEndpoint):
    """GitHub Actions workflows — count plus test/lint signals.

    Migrated from ``audit_repo.list_workflows`` and
    ``audit_repo.analyze_workflows``.
    """

    @property
    def name(self) -> str:
        return "workflows"

    _TEST_KEYWORDS = frozenset({"test", "pytest", "jest", "spec", "rspec", "unittest"})
    _LINT_KEYWORDS = frozenset(
        {"lint", "ruff", "flake8", "eslint", "pylint", "rubocop"}
    )

    def fetch(self, owner: str, repo: str) -> WorkflowData:
        try:
            resp = self.client.get(f"/repos/{owner}/{repo}/actions/workflows")
            workflows = resp.get("workflows", []) if isinstance(resp, dict) else []
            has_tests = False
            has_linting = False
            for wf in workflows:
                combined = (
                    (wf.get("name") or "").lower()
                    + " "
                    + (wf.get("path") or "").lower()
                )
                if any(k in combined for k in self._TEST_KEYWORDS):
                    has_tests = True
                if any(k in combined for k in self._LINT_KEYWORDS):
                    has_linting = True
            return WorkflowData(
                count=len(workflows),
                workflows=workflows,
                analysis=WorkflowAnalysis(
                    has_tests=has_tests,
                    has_linting=has_linting,
                    workflows_analyzed=len(workflows),
                ),
            )
        except Exception:
            return WorkflowData()


class DependencyGraphEndpoint(BaseEndpoint):
    """Whether the dependency graph / SBOM endpoint is available.

    Migrated from ``archive_repos.process_single`` dependency-graph check.
    """

    @property
    def name(self) -> str:
        return "dependency_graph"

    def fetch(self, owner: str, repo: str) -> DependencyGraphData:
        try:
            self.client.get(f"/repos/{owner}/{repo}/dependency-graph/sbom")
            return DependencyGraphData(enabled=True)
        except Exception:
            return DependencyGraphData(enabled=False)


class CodeSearchEndpoint(BaseEndpoint):
    """Code search hits referencing this repo within the organisation.

    Migrated from ``archive_repos._search_references``.

    Note: GitHub's code search API enforces a secondary rate limit of
    approximately 30 requests per minute.  A 2.1-second sleep is applied
    after each call to stay within this limit.
    """

    _SLEEP_SECONDS = 2.1

    @property
    def name(self) -> str:
        return "references"

    def fetch(self, owner: str, repo: str) -> ReferenceData:
        full_name = f"{owner}/{repo}"
        try:
            items = self.client.get_paginated(
                f'/search/code?q="{repo}"+in:file+org:{owner}'
            )
            time.sleep(self._SLEEP_SECONDS)
            refs: list[ReferenceItem] = []
            for item in items:
                repo_info = item.get("repository") or {}
                ref_full = repo_info.get("full_name")
                if ref_full and ref_full != full_name:
                    refs.append(
                        ReferenceItem(
                            full_name=ref_full,
                            path=item.get("path"),
                            archived=bool(repo_info.get("archived", False)),
                        )
                    )
            return ReferenceData(items=refs)
        except Exception:
            return ReferenceData()


# ── Org-scoped endpoints ──────────────────────────────────────────────


class OrgMembersEndpoint(BaseOrgEndpoint):
    """Organisation member counts and 2FA compliance.

    Migrated from ``org_security_posture.members_without_2fa`` and
    ``org_security_posture._count_org_members``.
    """

    @property
    def name(self) -> str:
        return "org_members"

    def fetch(self, org: str) -> OrgMembersData:
        try:
            all_members = self.client.get_paginated(f"/orgs/{org}/members")
            no_2fa = self.client.get_paginated(
                f"/orgs/{org}/members?filter=2fa_disabled"
            )
            return OrgMembersData(
                total_members=len(all_members),
                members_without_2fa=[m.get("login", "") for m in no_2fa],
            )
        except Exception:
            return OrgMembersData()


class OrgOverviewEndpoint(BaseOrgEndpoint):
    """Organisation overview and selected security posture settings."""

    @property
    def name(self) -> str:
        return "org_overview"

    def fetch(self, org: str) -> OrgOverviewData:
        try:
            data = self.client.get(f"/orgs/{org}")

            def _get(key: str, admin_only: bool = False) -> object:
                if key in data:
                    return data[key]
                return "requires_admin_token" if admin_only else None

            return OrgOverviewData(
                access="ok",
                data={
                    "name": _get("name"),
                    "description": _get("description"),
                    "public_repos": _get("public_repos"),
                    "total_private_repos": _get("total_private_repos"),
                    "created_at": _get("created_at"),
                    "updated_at": _get("updated_at"),
                    "two_factor_requirement_enabled": _get(
                        "two_factor_requirement_enabled", admin_only=True
                    ),
                    "default_repository_permission": _get(
                        "default_repository_permission", admin_only=True
                    ),
                    "default_repository_branch": _get("default_repository_branch"),
                    "web_commit_signoff_required": _get("web_commit_signoff_required"),
                },
            )
        except Exception as exc:
            return OrgOverviewData(access=str(exc))


class OrgOutsideCollaboratorsEndpoint(BaseOrgEndpoint):
    """Outside collaborators listing for an organisation."""

    @property
    def name(self) -> str:
        return "org_outside_collaborators"

    def fetch(self, org: str) -> OrgOutsideCollaboratorsData:
        try:
            collabs = self.client.get_paginated(f"/orgs/{org}/outside_collaborators")
            return OrgOutsideCollaboratorsData(
                access="ok",
                collaborators=[
                    {"login": c.get("login"), "id": c.get("id")} for c in collabs
                ],
            )
        except Exception as exc:
            return OrgOutsideCollaboratorsData(access=str(exc))


class OrgTeamsEndpoint(BaseOrgEndpoint):
    """Organisation teams metadata."""

    @property
    def name(self) -> str:
        return "org_teams"

    def fetch(self, org: str) -> OrgTeamsData:
        try:
            teams = self.client.get_paginated(f"/orgs/{org}/teams")
            return OrgTeamsData(
                access="ok",
                teams=[
                    {
                        "name": t.get("name"),
                        "slug": t.get("slug"),
                        "description": t.get("description"),
                        "privacy": t.get("privacy"),
                        "notification_setting": t.get("notification_setting"),
                        "permission": t.get("permission"),
                        "parent": t.get("parent", {}).get("name")
                        if t.get("parent")
                        else None,
                    }
                    for t in teams
                ],
            )
        except Exception as exc:
            return OrgTeamsData(access=str(exc))


class OrgAuditLogEndpoint(BaseOrgEndpoint):
    """Recent org audit log entries."""

    @property
    def name(self) -> str:
        return "org_audit_log"

    def fetch(self, org: str) -> OrgAuditLogData:
        try:
            entries = self.client.get(f"/orgs/{org}/audit-log?per_page=100&include=all")
            if isinstance(entries, list):
                return OrgAuditLogData(access="ok", entries=entries)
            return OrgAuditLogData(access="ok")
        except Exception as exc:
            return OrgAuditLogData(access=str(exc))


class OrgCodeScanningAlertsEndpoint(BaseOrgEndpoint):
    """Organisation code scanning alerts summary."""

    @property
    def name(self) -> str:
        return "org_code_scanning_alerts"

    def fetch(self, org: str) -> OrgCodeScanningAlertsData:
        try:
            alerts = self.client.get_paginated(
                f"/orgs/{org}/code-scanning/alerts?state=open"
            )
            return OrgCodeScanningAlertsData(
                access="ok",
                open_count=len(alerts),
                alerts=[
                    {
                        "rule_id": a.get("rule", {}).get("id"),
                        "severity": a.get("rule", {}).get("severity"),
                        "repo": a.get("repository", {}).get("full_name"),
                        "state": a.get("state"),
                    }
                    for a in alerts
                ],
                truncated=False,
            )
        except Exception as exc:
            return OrgCodeScanningAlertsData(access=str(exc), open_count=0, alerts=[])


class OrgSecretScanningAlertsEndpoint(BaseOrgEndpoint):
    """Organisation secret scanning alerts summary."""

    @property
    def name(self) -> str:
        return "org_secret_scanning_alerts"

    def fetch(self, org: str) -> OrgSecretScanningAlertsData:
        try:
            alerts = self.client.get_paginated(
                f"/orgs/{org}/secret-scanning/alerts?state=open"
            )
            return OrgSecretScanningAlertsData(
                access="ok",
                open_count=len(alerts),
                alerts=[
                    {
                        "secret_type": a.get("secret_type_display_name")
                        or a.get("secret_type"),
                        "repo": a.get("repository", {}).get("full_name"),
                        "state": a.get("state"),
                        "created_at": a.get("created_at"),
                    }
                    for a in alerts
                ],
                truncated=False,
            )
        except Exception as exc:
            return OrgSecretScanningAlertsData(access=str(exc), open_count=0, alerts=[])


class OrgActionsEndpoint(BaseOrgEndpoint):
    """Org-level Actions configuration — runners, permissions, secrets.

    Migrated from ``org_security_posture.actions_posture``.
    """

    @property
    def name(self) -> str:
        return "org_actions"

    def fetch(self, org: str) -> OrgActionsData:
        try:
            runners = self.client.get(f"/orgs/{org}/actions/runners")
            permissions = self.client.get(f"/orgs/{org}/actions/permissions")
            secrets = self.client.get(f"/orgs/{org}/actions/secrets")
            wf_perms = self.client.get(f"/orgs/{org}/actions/permissions/workflow")
            return OrgActionsData(
                self_hosted_runners=runners.get("total_count", 0)
                if isinstance(runners, dict)
                else 0,
                allowed_actions_policy=permissions.get("allowed_actions")
                if isinstance(permissions, dict)
                else None,
                org_secrets_count=secrets.get("total_count", 0)
                if isinstance(secrets, dict)
                else 0,
                default_workflow_permissions=wf_perms.get(
                    "default_workflow_permissions"
                )
                if isinstance(wf_perms, dict)
                else None,
            )
        except Exception:
            return OrgActionsData()


class OrgWebhooksEndpoint(BaseOrgEndpoint):
    """Org webhooks and installed GitHub Apps.

    Migrated from ``org_security_posture.webhooks_and_integrations``.
    """

    @property
    def name(self) -> str:
        return "org_webhooks"

    def fetch(self, org: str) -> OrgWebhooksData:
        try:
            hooks = self.client.get_paginated(f"/orgs/{org}/hooks")
            apps = self.client.get(f"/orgs/{org}/installations")
            app_names = [
                a.get("app_slug", "")
                for a in (
                    apps.get("installations", []) if isinstance(apps, dict) else []
                )
            ]
            return OrgWebhooksData(
                webhooks_count=len(hooks),
                installed_apps=app_names,
            )
        except Exception:
            return OrgWebhooksData()


class OrgRulesetsEndpoint(BaseOrgEndpoint):
    """Org-level repository rulesets.

    Migrated from ``org_security_posture.org_rulesets``.
    """

    @property
    def name(self) -> str:
        return "org_rulesets"

    def fetch(self, org: str) -> OrgRulesetsData:
        try:
            rulesets = self.client.get_paginated(f"/orgs/{org}/rulesets")
            return OrgRulesetsData(count=len(rulesets), rulesets=rulesets)
        except Exception:
            return OrgRulesetsData()


# ── Endpoint registries ───────────────────────────────────────────────
# The collector iterates REPO_ENDPOINTS for every repo in order.
# Add new endpoint classes here — no changes to collector.py are needed.

REPO_ENDPOINTS: list[type[BaseEndpoint]] = [
    RepoDetailsEndpoint,
    AlertsEndpoint,
    BranchProtectionEndpoint,
    CommunityProfileEndpoint,
    CodeownersEndpoint,
    ForkTemplateEndpoint,
    WorkflowsEndpoint,
    DependencyGraphEndpoint,
    CodeSearchEndpoint,
]

STANDARD_REPO_AUDIT_ENDPOINTS: list[type[BaseEndpoint]] = [
    RepoDetailsEndpoint,
    BranchProtectionEndpoint,
    AlertsEndpoint,
    CommunityProfileEndpoint,
    CodeownersEndpoint,
    ForkTemplateEndpoint,
    WorkflowsEndpoint,
]

ORG_ENDPOINTS: list[type[BaseOrgEndpoint]] = [
    OrgMembersEndpoint,
    OrgActionsEndpoint,
    OrgWebhooksEndpoint,
    OrgRulesetsEndpoint,
]
