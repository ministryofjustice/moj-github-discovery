"""Tests for core/storage.py — SQLite persistence layer."""

from __future__ import annotations

import time

import pytest

from core.models import AlertData, CodeownersData, RepoData, RepoDetails
from core.storage import SqliteOrgStorage, SqliteRepoStorage


@pytest.fixture
def storage(tmp_path) -> SqliteRepoStorage:
    db = SqliteRepoStorage(str(tmp_path / "test.db"))
    db.init()
    return db


class TestSqliteRepoStorageInit:
    def test_creates_table(self, tmp_path):
        db = SqliteRepoStorage(str(tmp_path / "new.db"))
        db.init()
        # Should not raise on second init (IF NOT EXISTS)
        db.init()

    def test_init_idempotent(self, storage):
        storage.init()
        storage.init()


class TestSqliteRepoStorageRead:
    def test_read_nonexistent(self, storage):
        assert storage.read("org/nonexistent") is None

    def test_read_all_empty(self, storage):
        assert storage.read_all() == []


class TestSqliteRepoStorageUpsert:
    def test_insert_new(self, storage):
        data = RepoData(alerts=AlertData(dependabot_alerts=5))
        storage.upsert("org/repo", data)

        result = storage.read("org/repo")
        assert result is not None
        assert result.alerts.dependabot_alerts == 5

    def test_merge_preserves_existing(self, storage):
        """Fields not present in the update should be preserved."""
        storage.upsert(
            "org/repo",
            RepoData(alerts=AlertData(dependabot_alerts=3)),
        )
        storage.upsert(
            "org/repo",
            RepoData(codeowners=CodeownersData(present=True)),
        )

        result = storage.read("org/repo")
        assert result.alerts.dependabot_alerts == 3  # preserved
        assert result.codeowners.present is True  # added

    def test_merge_overwrites_field(self, storage):
        """When both existing and update have the same field, update wins."""
        storage.upsert(
            "org/repo",
            RepoData(alerts=AlertData(dependabot_alerts=3)),
        )
        storage.upsert(
            "org/repo",
            RepoData(alerts=AlertData(dependabot_alerts=10)),
        )

        result = storage.read("org/repo")
        assert result.alerts.dependabot_alerts == 10

    def test_upsert_collected_at(self, storage):
        storage.upsert("org/repo", RepoData(collected_at="2024-01-01T00:00:00Z"))
        result = storage.read("org/repo")
        assert result.collected_at == "2024-01-01T00:00:00Z"


class TestSqliteRepoStorageReadAll:
    def test_returns_ordered_by_name(self, storage):
        storage.upsert("org/beta", RepoData())
        storage.upsert("org/alpha", RepoData())
        storage.upsert("org/gamma", RepoData())

        rows = storage.read_all()
        names = [name for name, _ in rows]
        assert names == ["org/alpha", "org/beta", "org/gamma"]

    def test_returns_full_data(self, storage):
        storage.upsert(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(full_name="org/repo", name="repo"),
                alerts=AlertData(dependabot_alerts=1),
            ),
        )
        rows = storage.read_all()
        assert len(rows) == 1
        name, data = rows[0]
        assert name == "org/repo"
        assert data.repo_details.full_name == "org/repo"
        assert data.alerts.dependabot_alerts == 1


class TestSqliteRepoStorageDelete:
    def test_delete_existing(self, storage):
        storage.upsert("org/repo", RepoData())
        assert storage.read("org/repo") is not None

        storage.delete("org/repo")
        assert storage.read("org/repo") is None

    def test_delete_nonexistent_is_noop(self, storage):
        storage.delete("org/nonexistent")  # should not raise


class TestSqliteRepoStorageJsonRoundtrip:
    def test_complex_data_roundtrip(self, storage):
        """All nested Pydantic models should survive serialization."""
        data = RepoData(
            repo_details=RepoDetails(
                full_name="org/repo",
                name="repo",
                language="Python",
                private=True,
            ),
            alerts=AlertData(
                dependabot_alerts=3,
                code_scanning_alerts=1,
                secret_scanning_access="ok",
            ),
            flags=["stale", "no_codeowners"],
            collected_at="2024-06-15T12:00:00Z",
        )
        storage.upsert("org/repo", data)

        result = storage.read("org/repo")
        assert result.repo_details.language == "Python"
        assert result.repo_details.private is True
        assert result.alerts.dependabot_alerts == 3
        assert result.flags == ["stale", "no_codeowners"]
        assert result.collected_at == "2024-06-15T12:00:00Z"


class TestSqliteOrgStorage:
    def test_read_cache_missing(self, tmp_path):
        storage = SqliteOrgStorage(str(tmp_path / "org_cache.db"))
        storage.init()
        assert storage.read_cache("missing-org") is None

    def test_upsert_and_read_cache(self, tmp_path):
        storage = SqliteOrgStorage(str(tmp_path / "org_cache.db"))
        storage.init()

        updated_at = time.time()
        payload = {"3_dependency_supply_chain": {"summary": {"repos_checked": 10}}}
        storage.upsert_cache("ministryofjustice", payload, updated_at)

        cached = storage.read_cache("ministryofjustice")
        assert cached is not None
        data, ts = cached
        assert data == payload
        assert ts == pytest.approx(updated_at)

    def test_upsert_overwrites_existing(self, tmp_path):
        storage = SqliteOrgStorage(str(tmp_path / "org_cache.db"))
        storage.init()

        storage.upsert_cache("moj", {"value": 1}, 1000.0)
        storage.upsert_cache("moj", {"value": 2}, 2000.0)

        cached = storage.read_cache("moj")
        assert cached is not None
        data, ts = cached
        assert data == {"value": 2}
        assert ts == 2000.0
