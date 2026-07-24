"""Data-access helpers for the dashboard.

``db_path`` is set by the entry-point (``dashboard.py``) before any helper is
called, so all functions pick up the correct database at runtime.
"""

from __future__ import annotations

from core.presenters import build_dashboard_dataframe, repo_data_to_audit_result
from core.storage import SqliteRepoStorage

# Set by dashboard.py before the app starts.
db_path: str | None = None


def _get_storage():
    """Return an initialised SqliteRepoStorage instance."""

    if not db_path:
        raise RuntimeError(
            "dashboard_utils.data.db_path is not set; set it before calling data helpers."
        )

    storage = SqliteRepoStorage(db_path)
    storage.init()
    return storage


def load_data():
    """Load the full repo summary DataFrame from core storage."""
    return build_dashboard_dataframe(_get_storage())


def _load_repo_audit_result(full_name: str) -> dict | None:
    """Load a single repo's audit result dict from core storage."""

    repo_data = _get_storage().read(full_name)
    if repo_data is None:
        return None
    return repo_data_to_audit_result(repo_data)
