"""Tests for core/collector.py — collection orchestration."""

from __future__ import annotations


import pytest

from core.collector import (
    BaseCollector,
    OrgEndpointCollector,
    RepoCollector,
    RepoListCollector,
)
from core.github_api import (
    BaseEndpoint,
    BaseOrgEndpoint,
    BranchProtectionEndpoint,
    RepoDetailsEndpoint,
)
from core.models import AlertData, CodeownersData, OrgMembersData, RepoData
from pydantic import BaseModel
from tests.conftest import MockHttpClient, MockStorage


# ── Tiny test endpoints ───────────────────────────────────────────────


class _FakeAlertEndpoint(BaseEndpoint):
    @property
    def name(self) -> str:
        return "alerts"

    def fetch(self, owner: str, repo: str) -> AlertData:
        return AlertData(dependabot_alerts=42)


class _FakeCodeownersEndpoint(BaseEndpoint):
    @property
    def name(self) -> str:
        return "codeowners"

    def fetch(self, owner: str, repo: str) -> CodeownersData:
        return CodeownersData(present=True, path="CODEOWNERS")


class _RepoDetailsAwareAlertEndpoint(BaseEndpoint):
    @property
    def name(self) -> str:
        return "alerts"

    def fetch(self, owner: str, repo: str, repo_details: object | None) -> AlertData:
        return AlertData(dependabot_alerts=1 if repo_details else 0)


class _FailingEndpoint(BaseEndpoint):
    @property
    def name(self) -> str:
        return "alerts"

    def fetch(self, owner: str, repo: str) -> BaseModel:
        raise RuntimeError("API exploded")


class _FakeOrgEndpoint(BaseOrgEndpoint):
    @property
    def name(self) -> str:
        return "org_members"

    def fetch(self, org: str) -> OrgMembersData:
        return OrgMembersData(total_members=10)


class _FailingOrgEndpoint(BaseOrgEndpoint):
    @property
    def name(self) -> str:
        return "org_fail"

    def fetch(self, org: str) -> BaseModel:
        raise RuntimeError("Org API exploded")


# ── BaseCollector ─────────────────────────────────────────────────────


class TestBaseCollector:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            BaseCollector()


# ── RepoCollector ─────────────────────────────────────────────────────


class TestRepoCollector:
    def test_collects_explicit_repos(self):
        storage = MockStorage()
        client = MockHttpClient()
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[_FakeAlertEndpoint, _FakeCodeownersEndpoint],
        )
        collector.collect("org", repos=["org/repo-a", "org/repo-b"])

        assert storage.init_called
        a = storage.read("org/repo-a")
        assert a is not None
        assert a.alerts.dependabot_alerts == 42
        assert a.codeowners.present is True
        assert a.collected_at is not None

        b = storage.read("org/repo-b")
        assert b is not None

    def test_discovers_repos_when_none_given(self):
        client = MockHttpClient(
            {
                "/orgs/myorg/repos?type=all&sort=pushed": [
                    {"full_name": "myorg/repo-a"},
                ],
            }
        )
        storage = MockStorage()
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[_FakeAlertEndpoint],
        )
        collector.collect("myorg")

        assert storage.read("myorg/repo-a") is not None

    def test_skips_invalid_repo_names(self):
        storage = MockStorage()
        client = MockHttpClient()
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[_FakeAlertEndpoint],
        )
        collector.collect("org", repos=["invalid-no-slash"])

        assert storage.read("invalid-no-slash") is None

    def test_endpoint_error_does_not_abort(self):
        """A failing endpoint should not prevent other endpoints from running."""
        storage = MockStorage()
        client = MockHttpClient()
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[_FailingEndpoint, _FakeCodeownersEndpoint],
        )
        collector.collect("org", repos=["org/repo"])

        result = storage.read("org/repo")
        assert result is not None
        # alerts failed, but codeowners should still be collected
        assert result.codeowners.present is True
        # collected_at timestamp should still be written
        assert result.collected_at is not None

    def test_resume_skips_existing(self):
        storage = MockStorage()
        # Pre-populate alerts
        storage.upsert("org/repo", RepoData(alerts=AlertData(dependabot_alerts=99)))

        client = MockHttpClient()
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[_FakeAlertEndpoint, _FakeCodeownersEndpoint],
        )
        collector.collect("org", repos=["org/repo"], resume=True)

        result = storage.read("org/repo")
        # alerts should NOT be overwritten (resume skipped it)
        assert result.alerts.dependabot_alerts == 99
        # codeowners was not pre-populated, so it should be collected
        assert result.codeowners.present is True

    def test_resume_collects_missing(self):
        storage = MockStorage()
        # Pre-populate only alerts
        storage.upsert("org/repo", RepoData(alerts=AlertData()))

        client = MockHttpClient()
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[_FakeAlertEndpoint, _FakeCodeownersEndpoint],
        )
        collector.collect("org", repos=["org/repo"], resume=True)

        result = storage.read("org/repo")
        assert result.codeowners is not None

    def test_stamps_collected_at(self):
        storage = MockStorage()
        client = MockHttpClient()
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[_FakeAlertEndpoint],
        )
        collector.collect("org", repos=["org/repo"])

        result = storage.read("org/repo")
        assert result.collected_at is not None
        # Should be an ISO-8601 string
        assert "T" in result.collected_at

    def test_branch_protection_reuses_collected_repo_details(self):
        client = MockHttpClient(
            {
                "/repos/org/repo": {
                    "full_name": "org/repo",
                    "name": "repo",
                    "default_branch": "develop",
                },
                "/repos/org/repo/branches/develop": {
                    "protected": True,
                    "protection": {},
                },
            }
        )
        storage = MockStorage()
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[RepoDetailsEndpoint, BranchProtectionEndpoint],
        )

        collector.collect("org", repos=["org/repo"])

        repo_calls = [
            path for method, path in client.calls if path == "/repos/org/repo"
        ]
        assert len(repo_calls) == 1

        result = storage.read("org/repo")
        assert result is not None
        assert result.branch_protection is not None
        assert result.branch_protection.default_branch_protected is True

    def test_collector_injects_repo_details_for_other_endpoints(self):
        client = MockHttpClient(
            {
                "/repos/org/repo": {
                    "full_name": "org/repo",
                    "name": "repo",
                    "default_branch": "main",
                },
            }
        )
        storage = MockStorage()
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[RepoDetailsEndpoint, _RepoDetailsAwareAlertEndpoint],
        )

        collector.collect("org", repos=["org/repo"])

        result = storage.read("org/repo")
        assert result is not None
        assert result.alerts is not None
        assert result.alerts.dependabot_alerts == 1


# ── OrgEndpointCollector ──────────────────────────────────────────────


class TestOrgEndpointCollector:
    def test_collects_org_endpoints(self):
        client = MockHttpClient()
        collector = OrgEndpointCollector(
            client=client,
            endpoints=[_FakeOrgEndpoint],
        )
        results = collector.collect("myorg")

        assert "org_members" in results
        assert isinstance(results["org_members"], OrgMembersData)
        assert results["org_members"].total_members == 10

    def test_error_does_not_abort(self):
        client = MockHttpClient()
        collector = OrgEndpointCollector(
            client=client,
            endpoints=[_FailingOrgEndpoint, _FakeOrgEndpoint],
        )
        results = collector.collect("myorg")

        # Failing endpoint omitted, successful one still present
        assert "org_fail" not in results
        assert "org_members" in results


# ── RepoListCollector ─────────────────────────────────────────────────


class TestRepoListCollector:
    def test_basic_collect(self):
        client = MockHttpClient(
            {
                "/orgs/myorg/repos?type=all&sort=pushed": [
                    {"full_name": "myorg/a"},
                    {"full_name": "myorg/b"},
                ],
            }
        )
        collector = RepoListCollector(client=client)
        repos = collector.collect("myorg")
        assert repos == ["myorg/a", "myorg/b"]

    def test_passes_filters(self):
        client = MockHttpClient(
            {
                "/orgs/myorg/repos?type=public&sort=full_name&direction=asc": [
                    {"full_name": "myorg/aaa"},
                ],
            }
        )
        collector = RepoListCollector(client=client)
        repos = collector.collect(
            "myorg", type="public", sort="full_name", direction="asc"
        )
        assert repos == ["myorg/aaa"]
