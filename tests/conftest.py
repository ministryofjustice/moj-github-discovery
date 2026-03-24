"""Shared fixtures for the core test suite."""

from __future__ import annotations

from typing import Any

import pytest

from core.github_client import BaseHttpClient
from core.models import (
    AlertData,
    BranchProtection,
    CodeownersData,
    CommunityProfile,
    DependencyGraphData,
    ForkTemplateData,
    ReferenceData,
    ReferenceItem,
    RepoData,
    RepoDetails,
    WorkflowData,
)
from core.storage import BaseStorage


# ── Mock HTTP client ──────────────────────────────────────────────────


class MockHttpClient(BaseHttpClient):
    """HTTP client that returns canned responses from a fixtures dict.

    Fixtures should be keyed by API path (e.g. ``"/repos/org/repo"``).
    For ``get()`` the value is the JSON response dict.
    For ``get_paginated()`` the value is a list of dicts.
    """

    def __init__(self, fixtures: dict[str, Any] | None = None) -> None:
        self.fixtures: dict[str, Any] = fixtures or {}
        self.calls: list[tuple[str, str]] = []  # [(method, path), ...]

    def get(self, path: str) -> Any:
        self.calls.append(("GET", path))
        if path in self.fixtures:
            return self.fixtures[path]
        raise Exception(f"MockHttpClient: no fixture for GET {path}")

    def get_paginated(self, path: str, per_page: int = 100) -> list[Any]:
        self.calls.append(("GET_PAGINATED", path))
        if path in self.fixtures:
            return self.fixtures[path]
        raise Exception(f"MockHttpClient: no fixture for GET_PAGINATED {path}")


# ── Mock storage ──────────────────────────────────────────────────────


class MockStorage(BaseStorage):
    """In-memory storage for testing collectors without SQLite."""

    def __init__(self) -> None:
        self._data: dict[str, RepoData] = {}
        self.init_called = False

    def init(self) -> None:
        self.init_called = True

    def upsert(self, full_name: str, update: RepoData) -> None:
        existing = self._data.get(full_name, RepoData())
        merged = existing.model_copy(
            update=update.model_dump(exclude_none=True),
        )
        # Round-trip through JSON like SqliteStorage to ensure nested dicts
        # are re-validated into proper Pydantic model instances.
        self._data[full_name] = RepoData.model_validate_json(
            merged.model_dump_json(),
        )

    def read(self, full_name: str) -> RepoData | None:
        return self._data.get(full_name)

    def read_all(self) -> list[tuple[str, RepoData]]:
        return sorted(self._data.items())

    def delete(self, full_name: str) -> None:
        self._data.pop(full_name, None)


# ── Convenience fixtures ──────────────────────────────────────────────


@pytest.fixture
def mock_client():
    """Return a fresh MockHttpClient."""
    return MockHttpClient()


@pytest.fixture
def mock_storage():
    """Return a fresh MockStorage."""
    return MockStorage()


@pytest.fixture
def sample_repo_details() -> RepoDetails:
    return RepoDetails(
        full_name="org/repo",
        name="repo",
        org="org",
        private=False,
        archived=False,
        default_branch="main",
        pushed_at="2024-01-15T10:00:00Z",
        created_at="2020-06-01T08:00:00Z",
    )


@pytest.fixture
def sample_repo_data(sample_repo_details) -> RepoData:
    return RepoData(
        repo_details=sample_repo_details,
        alerts=AlertData(dependabot_alerts=2, code_scanning_alerts=0),
        branch_protection=BranchProtection(default_branch_protected=True),
        codeowners=CodeownersData(present=True, path=".github/CODEOWNERS"),
        community=CommunityProfile(health_percentage=80),
        workflows=WorkflowData(count=3),
        fork_template=ForkTemplateData(),
        dependency_graph=DependencyGraphData(enabled=True),
        references=ReferenceData(
            items=[
                ReferenceItem(full_name="org/other", archived=False),
                ReferenceItem(full_name="org/old", archived=True),
            ]
        ),
        collected_at="2024-06-01T12:00:00Z",
    )
