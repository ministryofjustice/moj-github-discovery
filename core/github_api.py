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
``audit_repo.py`` (``repo_info``, ``community_profile``, ``list_workflows``,
``analyze_workflows``), ``archive_repos.py`` (``_search_references``), and
``org_security_posture.py`` (all org-level functions).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from pydantic import BaseModel

from core.http_client import BaseHttpClient
from core.models import (
    AlertData,
    BranchProtection,
    CodeownersData,
    CommunityProfile,
    DependencyGraphData,
    ForkTemplateData,
    OrgActionsData,
    OrgMembersData,
    OrgRulesetsData,
    OrgWebhooksData,
    ReferenceData,
    ReferenceItem,
    RepoMeta,
    WorkflowAnalysis,
    WorkflowData,
)


# ── Helpers ───────────────────────────────────────────────────────────


def list_org_repos(org: str, client: BaseHttpClient) -> list[str]:
    """Return a list of ``owner/repo`` strings for all repos in an organisation."""
    items = client.get_paginated(f"/orgs/{org}/repos?sort=pushed&direction=desc")
    return [r["full_name"] for r in items if isinstance(r, dict) and "full_name" in r]


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


class RepoMetaEndpoint(BaseEndpoint):
    """Core repository metadata from ``/repos/{owner}/{repo}``.

    Migrated from ``audit_repo.repo_info`` and ``utils.gh_api``.
    """

    @property
    def name(self) -> str:
        return "repo_meta"

    def fetch(self, owner: str, repo: str) -> RepoMeta:
        data = self.client.get(f"/repos/{owner}/{repo}")
        data["org"] = owner
        return RepoMeta.model_validate(data)


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

    def fetch(self, owner: str, repo: str) -> BranchProtection:
        try:
            repo_data = self.client.get(f"/repos/{owner}/{repo}")
            default_branch = repo_data.get("default_branch", "main")
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
    RepoMetaEndpoint,
    AlertsEndpoint,
    BranchProtectionEndpoint,
    CommunityProfileEndpoint,
    CodeownersEndpoint,
    ForkTemplateEndpoint,
    WorkflowsEndpoint,
    DependencyGraphEndpoint,
    CodeSearchEndpoint,
]

ORG_ENDPOINTS: list[type[BaseOrgEndpoint]] = [
    OrgMembersEndpoint,
    OrgActionsEndpoint,
    OrgWebhooksEndpoint,
    OrgRulesetsEndpoint,
]
