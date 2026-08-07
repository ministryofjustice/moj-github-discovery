"""Tests for core/dashboard_service.py."""

from __future__ import annotations

import pandas as pd
import pytest

from core.config import AuditConfig
from core.dashboard_service import DashboardDataService
from core.models import RepoData, RepoDetails
from tests.conftest import MockStorage


class TestDashboardDataService:
    def test_get_available_sources_reflects_existing_database_files(self, tmp_path):
        list_db = tmp_path / "list_repos.db"
        lfs_db = tmp_path / "lfs.db"
        list_db.write_text("")
        lfs_db.write_text("")

        config = AuditConfig(
            list_repos={"database_path": str(list_db)},
            archive_repos={"database_path": str(tmp_path / "archive.db")},
            alert_metrics={"database_path": str(tmp_path / "alerts.db")},
            lfs_script={"database_path": str(lfs_db)},
            org_security_posture={"database_path": str(tmp_path / "org.db")},
            workflow_audit={"database_path": str(tmp_path / "workflow.db")},
        )

        service = DashboardDataService(config)
        sources = service.get_available_sources()

        assert sources["list_repos"] is True
        assert sources["lfs"] is True
        assert sources["archive_repos"] is False
        assert sources["alert_metrics"] is False
        assert sources["org_security_posture"] is False
        assert sources["github_workflow"] is False

    def test_initialise_data_populates_cache_and_get_returns_source(self, monkeypatch):
        config = AuditConfig()
        service = DashboardDataService(config)
        expected_df = pd.DataFrame([{"repo": "org/repo"}])

        monkeypatch.setattr(
            DashboardDataService,
            "_load_available_data",
            lambda self: {"list_repos": expected_df, "archive_repos": None},
        )

        service.initialise_data()

        assert service.get("list_repos") is expected_df
        assert service.get("archive_repos") is None
        assert service.get("missing") is None

    def test_load_available_data_raises_when_no_sources_exist(self, monkeypatch):
        config = AuditConfig()
        service = DashboardDataService(config)

        monkeypatch.setattr(
            service,
            "get_available_sources",
            lambda: {
                "list_repos": False,
                "archive_repos": False,
                "alert_metrics": False,
                "lfs": False,
                "org_security_posture": False,
                "github_workflow": False,
            },
        )

        with pytest.raises(RuntimeError, match="No available sources found"):
            service._load_available_data()

    def test_load_repo_audit_result_returns_none_without_storage(self):
        service = DashboardDataService(AuditConfig())

        assert service.load_repo_audit_result("org/repo") is None

    def test_load_repo_audit_result_returns_mapped_payload(self):
        service = DashboardDataService(AuditConfig())
        storage = MockStorage()
        storage.upsert(
            "org/repo",
            RepoData(repo_details=RepoDetails(full_name="org/repo", name="repo")),
        )
        service._list_repos_storage = storage

        result = service.load_repo_audit_result("org/repo")

        assert result is not None
        assert result["repo"]["full_name"] == "org/repo"
        assert "flags" in result

    def test_load_list_repos_returns_none_when_database_missing(self, tmp_path):
        config = AuditConfig(list_repos={"database_path": str(tmp_path / "missing.db")})
        service = DashboardDataService(config)

        assert service._load_list_repos() is None
