"""Dashboard data service for loading and serving audit datasets."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from core.config import AuditConfig
from core.presenters import build_dashboard_dataframe, repo_data_to_audit_result
from core.storage import SqliteRepoStorage


class DashboardDataService:
    """Load dashboard datasets and expose them for layouts and callbacks."""

    def __init__(self, config: AuditConfig):
        self._config = config
        self._data: dict[str, pd.DataFrame | None] = {}
        self._list_repos_storage: SqliteRepoStorage | None = None
        self._page_size_default: int = config.dashboard.page_size_default
        self._page_size_options: list[int] = list(config.dashboard.page_size_options)

    def initialise_data(self) -> None:
        """Load all available datasets into the service cache."""
        self._data = self._load_available_data()

    def get(self, source: str) -> pd.DataFrame | None:
        """Return a dataset by source key, or None when unavailable."""
        return self._data.get(source)

    def get_available_sources(self) -> dict[str, bool]:
        """Return source availability derived from configured database paths."""
        config = self._config
        return {
            "list_repos": self._resolve_db_path(
                config.list_repos.database_path
            ).exists(),
            "archive_repos": self._resolve_db_path(
                config.archive_repos.database_path
            ).exists(),
            "alert_metrics": self._resolve_db_path(
                config.alert_metrics.database_path
            ).exists(),
            "lfs": self._resolve_db_path(config.lfs_script.database_path).exists(),
            "org_security_posture": self._resolve_db_path(
                config.org_security_posture.database_path
            ).exists(),
            "github_workflow": self._resolve_db_path(
                config.workflow_audit.database_path
            ).exists(),
        }

    def get_dashboard_page_size_default(self) -> int:
        """Return configured default page size."""
        return self._page_size_default

    def get_dashboard_page_size_options(self) -> list[int]:
        """Return configured page-size options."""
        return self._page_size_options

    def load_repo_audit_result(self, full_name: str) -> dict | None:
        """Load a single repo audit result dict from list_repos storage."""
        if self._list_repos_storage is None:
            return None

        repo_data = self._list_repos_storage.read(full_name)
        if repo_data is None:
            return None
        return repo_data_to_audit_result(repo_data)

    def _resolve_db_path(self, db_path: str) -> Path:
        project_root = Path(__file__).resolve().parents[1]
        path = Path(db_path)
        return path if path.is_absolute() else (project_root / path)

    def _load_list_repos(self) -> pd.DataFrame | None:
        db_path = self._resolve_db_path(self._config.list_repos.database_path)
        if not db_path.exists():
            print(f"Warning: list_repos database not found at {db_path}")
            return None

        try:
            storage = SqliteRepoStorage(str(db_path))
            storage.init()
            self._list_repos_storage = storage
            return build_dashboard_dataframe(storage)
        except Exception as exc:
            print(f"Error loading list_repos data from {db_path}: {exc}")
            return None

    def _load_archive_repos(self) -> pd.DataFrame | None:
        return None

    def _load_alert_metrics(self) -> pd.DataFrame | None:
        return None

    def _load_lfs(self) -> pd.DataFrame | None:
        return None

    def _load_org_security_posture(self) -> pd.DataFrame | None:
        return None

    def _load_github_workflow(self) -> pd.DataFrame | None:
        return None

    def _load_available_data(self) -> dict[str, pd.DataFrame | None]:
        sources = self.get_available_sources()
        data = {
            "list_repos": self._load_list_repos() if sources["list_repos"] else None,
            "archive_repos": self._load_archive_repos()
            if sources["archive_repos"]
            else None,
            "alert_metrics": self._load_alert_metrics()
            if sources["alert_metrics"]
            else None,
            "lfs": self._load_lfs() if sources["lfs"] else None,
            "org_security_posture": self._load_org_security_posture()
            if sources["org_security_posture"]
            else None,
            "github_workflow": self._load_github_workflow()
            if sources["github_workflow"]
            else None,
        }
        if all(value is None for value in data.values()):
            raise RuntimeError(
                "No available sources found in the database. - Run at least one audit-cli script to generate data before starting the dashboard."
            )
        return data
