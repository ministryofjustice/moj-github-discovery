"""Data-access helpers for the dashboard.

``db_path`` is set by the entry-point (``dashboard.py``) before any helper is
called, so all functions pick up the correct database at runtime.
"""

from __future__ import annotations

# Set by dashboard.py before the app starts.
db_path: str | None = None


def _get_storage():
    """Return an initialised SqliteRepoStorage instance."""
    from core.storage import SqliteRepoStorage

    storage = SqliteRepoStorage(db_path)
    storage.init()
    return storage


def load_data():
    """Load the full repo summary DataFrame from core storage."""
    from core.presenters import build_dashboard_dataframe

    return build_dashboard_dataframe(_get_storage())


def _load_repo_audit_result(full_name: str) -> dict | None:
    """Load a single repo's audit result dict from core storage."""
    from core.presenters import repo_data_to_audit_result

    repo_data = _get_storage().read(full_name)
    if repo_data is None:
        return None
    return repo_data_to_audit_result(repo_data)
