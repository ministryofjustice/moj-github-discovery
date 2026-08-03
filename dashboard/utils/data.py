"""Data-access helpers for the dashboard.

``db_path`` is set by the entry-point (``dashboard/main.py``) before any helper is
called, so all functions pick up the correct database at runtime.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from core.config import AuditConfig
from core.presenters import build_dashboard_dataframe, repo_data_to_audit_result
from core.storage import SqliteRepoStorage

# Top-level data dictionary to hold loaded DataFrames for each source. Keys are source names, values are DataFrames or None if the source is not available.

_data: dict[str, pd.DataFrame | None] = {}
_list_repos_storage: SqliteRepoStorage | None = None


def initialise_data(config: AuditConfig) -> None:
    """Initialise the data dictionary by loading all available sources."""
    global _data
    _data = load_available_data(config)


def get(source: str) -> pd.DataFrame | None:
    """Get the DataFrame for a given source, or None if the source is not available."""
    return _data.get(source)


def get_available_sources(config: AuditConfig) -> dict[str, bool]:
    """Return a dict of available sources and whether they are present in the database."""
    return {
        "list_repos": Path(config.list_repos.database_path).exists(),
        "archive_repos": Path(config.archive_repos.database_path).exists(),
        "alert_metrics": Path(config.alert_metrics.database_path).exists(),
        "lfs": Path(config.lfs_script.database_path).exists(),
        "org_security_posture": Path(
            config.org_security_posture.database_path
        ).exists(),
        "github_workflow": Path(config.workflow_audit.database_path).exists(),
    }


def load_list_repos(config: AuditConfig) -> pd.DataFrame | None:
    """Load list_repos data from the database and return a DataFrame."""
    global _list_repos_storage
    db_path = config.list_repos.database_path
    if not Path(db_path).exists():
        print(f"Warning: list_repos Database not found at {db_path}")
    print(f"Loading list_repos data from {db_path}")
    try:
        storage = SqliteRepoStorage(db_path)
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
    return {
        "list_repos": load_list_repos(config) if sources["list_repos"] else None,
        "archive_repos": load_archive_repos(config)
        if sources.get("archive_repos")
        else None,
        "alert_metrics": load_alert_metrics(config)
        if sources.get("alert_metrics")
        else None,
        "lfs": load_lfs(config) if sources.get("lfs") else None,
        "org_security_posture": load_org_security_posture(config)
        if sources.get("org_security_posture")
        else None,
        "github_workflow": load_github_workflow(config)
        if sources.get("github_workflow")
        else None,
    }


def _load_repo_audit_result(full_name: str) -> dict | None:
    """Load a single repo's audit result dict from core storage."""
    if _list_repos_storage is None:
        return None

    repo_data = _list_repos_storage.read(full_name)
    if repo_data is None:
        return None
    return repo_data_to_audit_result(repo_data)
