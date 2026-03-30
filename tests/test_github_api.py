"""Tests for core/github_api.py — endpoint classes and helpers."""

from __future__ import annotations

from unittest.mock import patch


from core.github_api import (
    REPO_ENDPOINTS,
    ORG_ENDPOINTS,
    BaseEndpoint,
    BaseOrgEndpoint,
    AlertsEndpoint,
    BranchProtectionEndpoint,
    CodeownersEndpoint,
    CodeSearchEndpoint,
    CommunityProfileEndpoint,
    DependencyGraphEndpoint,
    ForkTemplateEndpoint,
    OrgActionsEndpoint,
    OrgMembersEndpoint,
    OrgRulesetsEndpoint,
    OrgWebhooksEndpoint,
    RepoDetailsEndpoint,
    WorkflowsEndpoint,
    dependency_supply_chain_summary,
    fetch_latest_workflow_run_created_at,
    fetch_repo_actions_permissions,
    fetch_repo_alerts,
    fetch_repo_file_text,
    list_org_repos,
)
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
    RepoDetails,
    WorkflowData,
)
from tests.conftest import MockHttpClient


# ── list_org_repos ────────────────────────────────────────────────────


class TestListOrgRepos:
    def test_basic_listing(self):
        client = MockHttpClient(
            {
                "/orgs/myorg/repos?type=all&sort=pushed": [
                    {"full_name": "myorg/repo-a"},
                    {"full_name": "myorg/repo-b"},
                ],
            }
        )
        repos = list_org_repos("myorg", client)
        assert repos == ["myorg/repo-a", "myorg/repo-b"]

    def test_filters_malformed_items(self):
        client = MockHttpClient(
            {
                "/orgs/myorg/repos?type=all&sort=pushed": [
                    {"full_name": "myorg/repo-a"},
                    "not a dict",
                    {"no_full_name_key": True},
                ],
            }
        )
        repos = list_org_repos("myorg", client)
        assert repos == ["myorg/repo-a"]

    def test_custom_params(self):
        client = MockHttpClient(
            {
                "/orgs/myorg/repos?type=public&sort=full_name&direction=asc": [
                    {"full_name": "myorg/aaa"},
                ],
            }
        )
        repos = list_org_repos(
            "myorg",
            client,
            type="public",
            sort="full_name",
            direction="asc",
        )
        assert repos == ["myorg/aaa"]

    def test_direction_omitted_by_default(self):
        client = MockHttpClient(
            {
                "/orgs/myorg/repos?type=all&sort=pushed": [],
            }
        )
        list_org_repos("myorg", client)
        assert any("direction" not in call[1] for call in client.calls)


class TestDependencySupplyChainSummary:
    def test_empty_repo_scope_does_not_fallback_to_org(self):
        client = MockHttpClient()
        result = dependency_supply_chain_summary(
            "myorg",
            client,
            repo_full_names=[],
        )

        assert result["repos_checked"] == 0
        assert result["details"] == []
        # Explicit empty scope should not trigger org-wide listing.
        assert not any(
            call[0] == "GET_PAGINATED" and "/orgs/myorg/repos" in call[1]
            for call in client.calls
        )

    def test_none_repo_scope_uses_org_listing(self):
        client = MockHttpClient(
            {
                "/orgs/myorg/repos?sort=pushed&direction=desc": [
                    {
                        "owner": {"login": "myorg"},
                        "name": "repo-a",
                        "visibility": "private",
                        "archived": False,
                        "default_branch": "main",
                        "license": {"spdx_id": "MIT"},
                        "topics": ["one", "two"],
                    }
                ],
                "/repos/myorg/repo-a/dependency-graph/sbom": {},
                "/repos/myorg/repo-a/branches/main": {"protected": True},
            }
        )

        result = dependency_supply_chain_summary("myorg", client, repo_full_names=None)

        assert result["repos_checked"] == 1
        assert any(
            call[0] == "GET_PAGINATED" and "/orgs/myorg/repos" in call[1]
            for call in client.calls
        )


# ── script-helper functions ──────────────────────────────────────────


class TestWorkflowAndAlertHelpers:
    def test_fetch_repo_actions_permissions(self):
        client = MockHttpClient(
            {
                "/repos/o/r/actions/permissions": {
                    "enabled": True,
                    "allowed_actions": "selected",
                }
            }
        )
        result = fetch_repo_actions_permissions(client, "o", "r")
        assert result["enabled"] is True

    def test_fetch_latest_workflow_run_created_at(self):
        client = MockHttpClient(
            {
                "/repos/o/r/actions/runs?per_page=1": {
                    "workflow_runs": [{"created_at": "2026-01-01T10:00:00Z"}],
                }
            }
        )
        result = fetch_latest_workflow_run_created_at(client, "o", "r")
        assert result == "2026-01-01T10:00:00Z"

    def test_fetch_latest_workflow_run_created_at_missing(self):
        client = MockHttpClient(
            {"/repos/o/r/actions/runs?per_page=1": {"workflow_runs": []}}
        )
        result = fetch_latest_workflow_run_created_at(client, "o", "r")
        assert result is None

    def test_fetch_repo_file_text(self):
        client = MockHttpClient(
            {
                "/repos/o/r/contents/.github/workflows/ci.yml": {
                    "encoding": "base64",
                    "content": "bmFtZTogQ0kK",
                }
            }
        )
        text = fetch_repo_file_text(client, "o", "r", ".github/workflows/ci.yml")
        assert text == "name: CI\n"

    def test_fetch_repo_alerts(self):
        client = MockHttpClient(
            {
                "/repos/o/r/code-scanning/alerts": [{"id": 1}, {"id": 2}],
            }
        )
        alerts = fetch_repo_alerts(client, "o", "r", "code_scanning")
        assert alerts == [{"id": 1}, {"id": 2}]


# ── Endpoint registries ──────────────────────────────────────────────


class TestEndpointRegistries:
    def test_repo_endpoints_count(self):
        assert len(REPO_ENDPOINTS) == 9

    def test_org_endpoints_count(self):
        assert len(ORG_ENDPOINTS) == 4

    def test_all_repo_endpoints_are_base_endpoint(self):
        for cls in REPO_ENDPOINTS:
            assert issubclass(cls, BaseEndpoint)

    def test_all_org_endpoints_are_base_org_endpoint(self):
        for cls in ORG_ENDPOINTS:
            assert issubclass(cls, BaseOrgEndpoint)

    def test_unique_repo_endpoint_names(self):
        client = MockHttpClient()
        names = [cls(client).name for cls in REPO_ENDPOINTS]
        assert len(names) == len(set(names))

    def test_unique_org_endpoint_names(self):
        client = MockHttpClient()
        names = [cls(client).name for cls in ORG_ENDPOINTS]
        assert len(names) == len(set(names))


# ── RepoDetailsEndpoint ──────────────────────────────────────────────


class TestRepoDetailsEndpoint:
    def test_fetch(self):
        client = MockHttpClient(
            {
                "/repos/org/repo": {
                    "full_name": "org/repo",
                    "name": "repo",
                    "private": False,
                    "archived": False,
                    "default_branch": "main",
                },
            }
        )
        ep = RepoDetailsEndpoint(client)
        assert ep.name == "repo_details"
        result = ep.fetch("org", "repo")
        assert isinstance(result, RepoDetails)
        assert result.full_name == "org/repo"
        assert result.org == "org"

    def test_sets_org_from_owner(self):
        client = MockHttpClient(
            {
                "/repos/myorg/myrepo": {
                    "full_name": "myorg/myrepo",
                    "name": "myrepo",
                },
            }
        )
        result = RepoDetailsEndpoint(client).fetch("myorg", "myrepo")
        assert result.org == "myorg"


# ── AlertsEndpoint ────────────────────────────────────────────────────


class TestAlertsEndpoint:
    def test_fetch_all_types(self):
        client = MockHttpClient(
            {
                "/repos/o/r/dependabot/alerts?state=open": [{"id": 1}, {"id": 2}],
                "/repos/o/r/code-scanning/alerts?state=open": [{"id": 3}],
                "/repos/o/r/secret-scanning/alerts?state=open": [],
            }
        )
        result = AlertsEndpoint(client).fetch("o", "r")
        assert isinstance(result, AlertData)
        assert result.dependabot_alerts == 2
        assert result.code_scanning_alerts == 1
        assert result.secret_scanning_alerts == 0

    def test_access_error_recorded(self):
        client = MockHttpClient(
            {
                "/repos/o/r/code-scanning/alerts?state=open": [],
                "/repos/o/r/secret-scanning/alerts?state=open": [],
                # dependabot missing → will raise
            }
        )
        result = AlertsEndpoint(client).fetch("o", "r")
        assert result.dependabot_alerts == 0
        assert "no fixture" in result.dependabot_access


# ── BranchProtectionEndpoint ─────────────────────────────────────────


class TestBranchProtectionEndpoint:
    def test_protected_branch(self):
        details = RepoDetails(full_name="o/r", name="r", default_branch="main")
        client = MockHttpClient(
            {
                "/repos/o/r/branches/main": {
                    "protected": True,
                    "protection": {
                        "required_status_checks": {"strict": True},
                        "required_pull_request_reviews": {
                            "dismiss_stale_reviews": True
                        },
                        "enforce_admins": {"enabled": True},
                    },
                },
            }
        )
        result = BranchProtectionEndpoint(client).fetch("o", "r", details)
        assert isinstance(result, BranchProtection)
        assert result.default_branch_protected is True
        assert "required_status_checks" in result.protection_settings
        assert "required_pr_reviews" in result.protection_settings
        assert "enforce_admins" in result.protection_settings

    def test_unprotected_branch(self):
        details = RepoDetails(full_name="o/r", name="r", default_branch="main")
        client = MockHttpClient(
            {
                "/repos/o/r/branches/main": {
                    "protected": False,
                    "protection": {},
                },
            }
        )
        result = BranchProtectionEndpoint(client).fetch("o", "r", details)
        assert result.default_branch_protected is False
        assert result.protection_settings == []

    def test_api_error_returns_default(self):
        details = RepoDetails(full_name="o/r", name="r")
        client = MockHttpClient()  # no fixtures → raises
        result = BranchProtectionEndpoint(client).fetch("o", "r", details)
        assert result.default_branch_protected is False
        assert result.branch_protection_access is not None


# ── CommunityProfileEndpoint ─────────────────────────────────────────


class TestCommunityProfileEndpoint:
    def test_fetch(self):
        client = MockHttpClient(
            {
                "/repos/o/r/community/profile": {
                    "health_percentage": 85,
                    "files": {"readme": {"url": "..."}},
                },
            }
        )
        result = CommunityProfileEndpoint(client).fetch("o", "r")
        assert isinstance(result, CommunityProfile)
        assert result.health_percentage == 85

    def test_error_returns_default(self):
        client = MockHttpClient()
        result = CommunityProfileEndpoint(client).fetch("o", "r")
        assert result.health_percentage == 0


# ── CodeownersEndpoint ────────────────────────────────────────────────


class TestCodeownersEndpoint:
    def test_codeowners_found(self):
        client = MockHttpClient(
            {
                "/repos/o/r": {"default_branch": "main"},
                "/repos/o/r/git/trees/main?recursive=1": {
                    "tree": [
                        {"path": "README.md"},
                        {"path": ".github/CODEOWNERS"},
                    ],
                },
            }
        )
        result = CodeownersEndpoint(client).fetch("o", "r")
        assert isinstance(result, CodeownersData)
        assert result.present is True
        assert result.path == ".github/CODEOWNERS"

    def test_codeowners_not_found(self):
        client = MockHttpClient(
            {
                "/repos/o/r": {"default_branch": "main"},
                "/repos/o/r/git/trees/main?recursive=1": {
                    "tree": [{"path": "README.md"}],
                },
            }
        )
        result = CodeownersEndpoint(client).fetch("o", "r")
        assert result.present is False

    def test_error_returns_not_present(self):
        client = MockHttpClient()
        result = CodeownersEndpoint(client).fetch("o", "r")
        assert result.present is False


# ── ForkTemplateEndpoint ──────────────────────────────────────────────


class TestForkTemplateEndpoint:
    def test_fork(self):
        client = MockHttpClient(
            {
                "/repos/o/r": {
                    "fork": True,
                    "parent": {"full_name": "upstream/repo"},
                    "template_repository": None,
                },
            }
        )
        result = ForkTemplateEndpoint(client).fetch("o", "r")
        assert isinstance(result, ForkTemplateData)
        assert result.is_fork is True
        assert result.fork_source == "upstream/repo"

    def test_template(self):
        client = MockHttpClient(
            {
                "/repos/o/r": {
                    "fork": False,
                    "template_repository": {"full_name": "tmpl/repo"},
                },
            }
        )
        result = ForkTemplateEndpoint(client).fetch("o", "r")
        assert result.is_generated_from_template is True
        assert result.template_source == "tmpl/repo"

    def test_neither(self):
        client = MockHttpClient(
            {
                "/repos/o/r": {"fork": False},
            }
        )
        result = ForkTemplateEndpoint(client).fetch("o", "r")
        assert result.is_fork is False
        assert result.fork_source is None


# ── WorkflowsEndpoint ────────────────────────────────────────────────


class TestWorkflowsEndpoint:
    def test_with_test_and_lint(self):
        client = MockHttpClient(
            {
                "/repos/o/r/actions/workflows": {
                    "workflows": [
                        {"name": "Run Tests", "path": ".github/workflows/test.yml"},
                        {"name": "Lint", "path": ".github/workflows/ruff.yml"},
                        {"name": "Deploy", "path": ".github/workflows/deploy.yml"},
                    ],
                },
            }
        )
        result = WorkflowsEndpoint(client).fetch("o", "r")
        assert isinstance(result, WorkflowData)
        assert result.count == 3
        assert result.analysis.has_tests is True
        assert result.analysis.has_linting is True

    def test_no_workflows(self):
        client = MockHttpClient(
            {
                "/repos/o/r/actions/workflows": {"workflows": []},
            }
        )
        result = WorkflowsEndpoint(client).fetch("o", "r")
        assert result.count == 0
        assert result.analysis.has_tests is False

    def test_error_returns_default(self):
        client = MockHttpClient()
        result = WorkflowsEndpoint(client).fetch("o", "r")
        assert result.count == 0
        assert result.analysis is None


# ── DependencyGraphEndpoint ───────────────────────────────────────────


class TestDependencyGraphEndpoint:
    def test_enabled(self):
        client = MockHttpClient({"/repos/o/r/dependency-graph/sbom": {}})
        result = DependencyGraphEndpoint(client).fetch("o", "r")
        assert isinstance(result, DependencyGraphData)
        assert result.enabled is True

    def test_disabled(self):
        client = MockHttpClient()
        result = DependencyGraphEndpoint(client).fetch("o", "r")
        assert result.enabled is False


# ── CodeSearchEndpoint ────────────────────────────────────────────────


class TestCodeSearchEndpoint:
    @patch("core.github_api.time.sleep")
    def test_with_references(self, mock_sleep):
        client = MockHttpClient(
            {
                '/search/code?q="repo"+in:file+org:o': [
                    {
                        "repository": {"full_name": "o/other", "archived": False},
                        "path": "README.md",
                    },
                    {
                        "repository": {"full_name": "o/repo", "archived": False},
                        "path": "self-ref.md",
                    },
                ],
            }
        )
        result = CodeSearchEndpoint(client).fetch("o", "repo")
        assert isinstance(result, ReferenceData)
        # Self-references are excluded
        assert len(result.items) == 1
        assert result.items[0].full_name == "o/other"
        mock_sleep.assert_called_once()

    @patch("core.github_api.time.sleep")
    def test_error_returns_empty(self, mock_sleep):
        client = MockHttpClient()
        result = CodeSearchEndpoint(client).fetch("o", "r")
        assert result.items == []


# ── OrgMembersEndpoint ────────────────────────────────────────────────


class TestOrgMembersEndpoint:
    def test_fetch(self):
        client = MockHttpClient(
            {
                "/orgs/myorg/members": [
                    {"login": "alice"},
                    {"login": "bob"},
                    {"login": "carol"},
                ],
                "/orgs/myorg/members?filter=2fa_disabled": [
                    {"login": "bob"},
                ],
            }
        )
        ep = OrgMembersEndpoint(client)
        assert ep.name == "org_members"
        result = ep.fetch("myorg")
        assert isinstance(result, OrgMembersData)
        assert result.total_members == 3
        assert result.members_without_2fa == ["bob"]

    def test_error_returns_default(self):
        client = MockHttpClient()
        result = OrgMembersEndpoint(client).fetch("myorg")
        assert result.total_members == 0


# ── OrgActionsEndpoint ────────────────────────────────────────────────


class TestOrgActionsEndpoint:
    def test_fetch(self):
        client = MockHttpClient(
            {
                "/orgs/o/actions/runners": {"total_count": 2},
                "/orgs/o/actions/permissions": {"allowed_actions": "selected"},
                "/orgs/o/actions/secrets": {"total_count": 5},
                "/orgs/o/actions/permissions/workflow": {
                    "default_workflow_permissions": "read",
                },
            }
        )
        result = OrgActionsEndpoint(client).fetch("o")
        assert isinstance(result, OrgActionsData)
        assert result.self_hosted_runners == 2
        assert result.allowed_actions_policy == "selected"
        assert result.org_secrets_count == 5
        assert result.default_workflow_permissions == "read"


# ── OrgWebhooksEndpoint ──────────────────────────────────────────────


class TestOrgWebhooksEndpoint:
    def test_fetch(self):
        client = MockHttpClient(
            {
                "/orgs/o/hooks": [{"id": 1}, {"id": 2}],
                "/orgs/o/installations": {
                    "installations": [
                        {"app_slug": "dependabot"},
                        {"app_slug": "renovate"},
                    ],
                },
            }
        )
        result = OrgWebhooksEndpoint(client).fetch("o")
        assert isinstance(result, OrgWebhooksData)
        assert result.webhooks_count == 2
        assert result.installed_apps == ["dependabot", "renovate"]


# ── OrgRulesetsEndpoint ──────────────────────────────────────────────


class TestOrgRulesetsEndpoint:
    def test_fetch(self):
        client = MockHttpClient(
            {
                "/orgs/o/rulesets": [
                    {"id": 1, "name": "rule-a"},
                    {"id": 2, "name": "rule-b"},
                ],
            }
        )
        result = OrgRulesetsEndpoint(client).fetch("o")
        assert isinstance(result, OrgRulesetsData)
        assert result.count == 2

    def test_error_returns_default(self):
        client = MockHttpClient()
        result = OrgRulesetsEndpoint(client).fetch("o")
        assert result.count == 0
