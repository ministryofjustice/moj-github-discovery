"""Data-access helpers for the dashboard.

_data is a top-level dictionary that holds loaded DataFrames for each source. Keys are source names, values are DataFrames or None if the source is not available.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from core.config import AuditConfig, DashboardConfig
from core.presenters import build_dashboard_dataframe, repo_data_to_audit_result
from core.storage import SqliteRepoStorage

# Top-level data dictionary to hold loaded DataFrames for each source. Keys are source names, values are DataFrames or None if the source is not available.

_data: dict[str, pd.DataFrame | None] = {}
_list_repos_storage: SqliteRepoStorage | None = None
_dashboard_defaults = DashboardConfig()
_page_size_default: int = _dashboard_defaults.page_size_default
_page_size_options: list[int] = list(_dashboard_defaults.page_size_options)


def initialise_data(config: AuditConfig) -> None:
    """Initialise the data dictionary by loading all available sources."""
    global _data, _page_size_default, _page_size_options
    _page_size_default = config.dashboard.page_size_default
    _page_size_options = list(config.dashboard.page_size_options)
    _data = load_available_data(config)


def get_dashboard_page_size_default() -> int:
    """Return the configured default dashboard page size."""
    return _page_size_default


def get_dashboard_page_size_options() -> list[int]:
    """Return the configured dashboard page size options."""
    return _page_size_options


def get(source: str) -> pd.DataFrame | None:
    """Get the DataFrame for a given source, or None if the source is not available."""
    return _data.get(source)


def get_available_sources(config: AuditConfig) -> dict[str, bool]:
    """Return a dict of available sources and whether they are present in the database."""
    # Resolve database paths relative to the project root if they are not absolute

    project_root = Path(__file__).resolve().parents[2]

    def resolve(db_path: str) -> Path:
        path = Path(db_path)
        return path if path.is_absolute() else (project_root / path)

    return {
        "list_repos": resolve(config.list_repos.database_path).exists(),
        "archive_repos": resolve(config.archive_repos.database_path).exists(),
        "alert_metrics": resolve(config.alert_metrics.database_path).exists(),
        "lfs": resolve(config.lfs_script.database_path).exists(),
        "org_security_posture": resolve(
            config.org_security_posture.database_path
        ).exists(),
        "github_workflow": resolve(config.workflow_audit.database_path).exists(),
    }


def load_list_repos(config: AuditConfig) -> pd.DataFrame | None:
    """Load list_repos data from the database and return a DataFrame."""
    global _list_repos_storage

    project_root = Path(__file__).resolve().parents[2]
    db_path = Path(config.list_repos.database_path)
    db_path = db_path if db_path.is_absolute() else (project_root / db_path)
    if not db_path.exists():
        print(f"Warning: list_repos database not found at {db_path}")
        return None
    try:
        storage = SqliteRepoStorage(str(db_path))
        storage.init()
        _list_repos_storage = storage
        return build_dashboard_dataframe(storage)
    except Exception as e:
        print(f"Error loading list_repos data from {db_path}: {e}")
        return None


# Stubbed Loader Functions - Extend as Each Script is Added
def load_archive_repos(config: AuditConfig) -> pd.DataFrame | None:
    """Stubbed archive_repos loader function. Extend this function to load data from the archive_repos script."""
    return None


def load_alert_metrics(config: AuditConfig) -> pd.DataFrame | None:
    """Stubbed alert_metrics loader function. Extend this function to load data from the alert_metrics script."""
    return None


def load_lfs(config: AuditConfig) -> pd.DataFrame | None:
    """Stubbed lfs loader function. Extend this function to load data from the lfs script."""
    return None


def load_org_security_posture(config: AuditConfig) -> pd.DataFrame | None:
    """Stubbed org_security_posture loader function. Extend this function to load data from the org_security_posture script."""
    return None


def load_github_workflow(config: AuditConfig) -> pd.DataFrame | None:
    """Stubbed github_workflow loader function. Extend this function to load data from the github_workflow script."""
    return None


# Load all available sources
def load_available_data(config: AuditConfig) -> dict[str, pd.DataFrame | None]:
    """Load all available sources into a dictionary of DataFrames."""
    sources = get_available_sources(config)
    data = {
        "list_repos": load_list_repos(config) if sources["list_repos"] else None,
        "archive_repos": load_archive_repos(config)
        if sources["archive_repos"]
        else None,
        "alert_metrics": load_alert_metrics(config)
        if sources["alert_metrics"]
        else None,
        "lfs": load_lfs(config) if sources["lfs"] else None,
        "org_security_posture": load_org_security_posture(config)
        if sources["org_security_posture"]
        else None,
        "github_workflow": load_github_workflow(config)
        if sources["github_workflow"]
        else None,
    }
    if all(value is None for value in data.values()):
        raise RuntimeError(
            "No available sources found in the database. - Run at least one audit-cli script to generate data before starting the dashboard."
        )
    return data


def _load_repo_audit_result(full_name: str) -> dict | None:
    """Load a single repo's audit result dict from core storage."""
    if _list_repos_storage is None:
        return None

    repo_data = _list_repos_storage.read(full_name)
    if repo_data is None:
        return None
    return repo_data_to_audit_result(repo_data)
