"""Integration tests against the ministryofjustice-test GitHub org.

These tests hit the real GitHub API and require a valid token
(``GITHUB_TOKEN``, ``GH_TOKEN``, or ``gh auth login``).

Run with::

    pytest tests/test_integration.py -v          # only integration tests
    pytest -m integration -v                      # via marker
    pytest -m "not integration"                   # skip integration tests

The test org ``ministryofjustice-test`` is a low-churn org specifically
maintained for this purpose.
"""

from __future__ import annotations

import os

import pytest

from core.collector import OrgEndpointCollector, RepoCollector, RepoListCollector
from core.github_api import (
    AlertsEndpoint,
    CodeownersEndpoint,
    CommunityProfileEndpoint,
    DependencyGraphEndpoint,
    ForkTemplateEndpoint,
    OrgActionsEndpoint,
    OrgMembersEndpoint,
    OrgRulesetsEndpoint,
    OrgWebhooksEndpoint,
    RepoDetailsEndpoint,
    WorkflowsEndpoint,
    list_org_repos,
)
from core.github_client import GitHubHttpClient
from core.models import (
    AlertData,
    CodeownersData,
    CommunityProfile,
    DependencyGraphData,
    ForkTemplateData,
    OrgActionsData,
    OrgMembersData,
    OrgRulesetsData,
    OrgWebhooksData,
    RepoDetails,
    WorkflowData,
)
from core.storage import SqliteStorage

# ── Constants ─────────────────────────────────────────────────────────

TEST_ORG = "ministryofjustice-test"
TEST_REPO = "demo-repository"
TEST_FULL_NAME = f"{TEST_ORG}/{TEST_REPO}"


# ── Skip condition ────────────────────────────────────────────────────


def _has_github_token() -> bool:
    """Check whether a GitHub token is available without raising."""
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):
        return True
    config_path = os.path.expanduser("~/.config/gh/hosts.yml")
    return os.path.exists(config_path)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _has_github_token(),
        reason="No GitHub token available — skipping integration tests",
    ),
]


# ── Shared client fixture ────────────────────────────────────────────


@pytest.fixture(scope="module")
def client() -> GitHubHttpClient:
    return GitHubHttpClient()


# ── list_org_repos ────────────────────────────────────────────────────


class TestListOrgReposIntegration:
    def test_discovers_repos(self, client):
        repos = list_org_repos(TEST_ORG, client)
        assert len(repos) >= 1
        assert all(r.startswith(f"{TEST_ORG}/") for r in repos)

    def test_demo_repo_present(self, client):
        repos = list_org_repos(TEST_ORG, client)
        assert TEST_FULL_NAME in repos

    def test_filter_by_type(self, client):
        repos = list_org_repos(TEST_ORG, client, type="private")
        # Should still find at least the demo repo (private)
        assert len(repos) >= 1

    def test_sort_by_full_name(self, client):
        repos = list_org_repos(TEST_ORG, client, sort="full_name", direction="asc")
        assert repos == sorted(repos)


# ── Repo-scoped endpoints ────────────────────────────────────────────


class TestRepoDetailsIntegration:
    def test_fetch(self, client):
        ep = RepoDetailsEndpoint(client)
        result = ep.fetch(TEST_ORG, TEST_REPO)
        assert isinstance(result, RepoDetails)
        assert result.full_name == TEST_FULL_NAME
        assert result.name == TEST_REPO
        assert result.org == TEST_ORG
        assert result.default_branch == "main"
        assert result.language == "HTML"


class TestAlertsIntegration:
    def test_fetch(self, client):
        result = AlertsEndpoint(client).fetch(TEST_ORG, TEST_REPO)
        assert isinstance(result, AlertData)
        # We can't assert exact counts, but the structure should be valid
        assert isinstance(result.dependabot_alerts, int)
        assert isinstance(result.code_scanning_alerts, int)


class TestCommunityProfileIntegration:
    def test_fetch(self, client):
        result = CommunityProfileEndpoint(client).fetch(TEST_ORG, TEST_REPO)
        assert isinstance(result, CommunityProfile)
        assert isinstance(result.health_percentage, int)


class TestCodeownersIntegration:
    def test_fetch(self, client):
        result = CodeownersEndpoint(client).fetch(TEST_ORG, TEST_REPO)
        assert isinstance(result, CodeownersData)
        assert isinstance(result.present, bool)


class TestForkTemplateIntegration:
    def test_fetch(self, client):
        result = ForkTemplateEndpoint(client).fetch(TEST_ORG, TEST_REPO)
        assert isinstance(result, ForkTemplateData)
        assert result.is_fork is False  # demo-repository is not a fork


class TestWorkflowsIntegration:
    def test_fetch(self, client):
        result = WorkflowsEndpoint(client).fetch(TEST_ORG, TEST_REPO)
        assert isinstance(result, WorkflowData)
        assert isinstance(result.count, int)


class TestDependencyGraphIntegration:
    def test_fetch(self, client):
        result = DependencyGraphEndpoint(client).fetch(TEST_ORG, TEST_REPO)
        assert isinstance(result, DependencyGraphData)
        assert isinstance(result.enabled, bool)


# ── Org-scoped endpoints ─────────────────────────────────────────────


class TestOrgMembersIntegration:
    def test_fetch(self, client):
        result = OrgMembersEndpoint(client).fetch(TEST_ORG)
        assert isinstance(result, OrgMembersData)
        assert result.total_members >= 1


class TestOrgActionsIntegration:
    def test_fetch(self, client):
        result = OrgActionsEndpoint(client).fetch(TEST_ORG)
        assert isinstance(result, OrgActionsData)


class TestOrgWebhooksIntegration:
    def test_fetch(self, client):
        result = OrgWebhooksEndpoint(client).fetch(TEST_ORG)
        assert isinstance(result, OrgWebhooksData)
        assert isinstance(result.webhooks_count, int)


class TestOrgRulesetsIntegration:
    def test_fetch(self, client):
        result = OrgRulesetsEndpoint(client).fetch(TEST_ORG)
        assert isinstance(result, OrgRulesetsData)
        assert isinstance(result.count, int)


# ── RepoListCollector ────────────────────────────────────────────────


class TestRepoListCollectorIntegration:
    def test_collect(self, client):
        collector = RepoListCollector(client=client)
        repos = collector.collect(TEST_ORG)
        assert len(repos) >= 1
        assert TEST_FULL_NAME in repos

    def test_collect_sorted(self, client):
        collector = RepoListCollector(client=client)
        repos = collector.collect(TEST_ORG, sort="full_name", direction="asc")
        assert repos == sorted(repos)


# ── OrgEndpointCollector ──────────────────────────────────────────────


class TestOrgEndpointCollectorIntegration:
    def test_collect(self, client):
        # Use only OrgMembersEndpoint to keep the test fast and avoid
        # secondary rate limits from the multi-call OrgActionsEndpoint.
        collector = OrgEndpointCollector(
            client=client,
            endpoints=[OrgMembersEndpoint],
        )
        results = collector.collect(TEST_ORG)
        assert "org_members" in results
        assert isinstance(results["org_members"], OrgMembersData)
        assert results["org_members"].total_members >= 1


# ── RepoCollector (single repo) ──────────────────────────────────────


class TestRepoCollectorIntegration:
    def test_collect_single_repo(self, client, tmp_path):
        """Full end-to-end: collect one repo into a temp SQLite DB.

        Uses a subset of endpoints to keep the test fast.
        """
        db_path = str(tmp_path / "integration.db")
        storage = SqliteStorage(db_path)
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[RepoDetailsEndpoint, CommunityProfileEndpoint],
        )
        collector.collect(TEST_ORG, repos=[TEST_FULL_NAME])

        result = storage.read(TEST_FULL_NAME)
        assert result is not None
        assert result.repo_meta is not None
        assert result.repo_meta.full_name == TEST_FULL_NAME
        assert result.community is not None
        assert result.collected_at is not None

    def test_resume_idempotent(self, client, tmp_path):
        """Running with resume=True after a full run should not error."""
        db_path = str(tmp_path / "resume.db")
        storage = SqliteStorage(db_path)
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[RepoDetailsEndpoint],
        )

        collector.collect(TEST_ORG, repos=[TEST_FULL_NAME])
        collector.collect(TEST_ORG, repos=[TEST_FULL_NAME], resume=True)

        result = storage.read(TEST_FULL_NAME)
        assert result is not None
        assert result.collected_at is not None
