"""Persistence layer — SQLite single-table storage.

All data for a repo lives in one row keyed by ``full_name``.  The ``data``
column holds a JSON serialisation of a :class:`~core.models.RepoData` object.
Endpoint results are merged incrementally so a mid-run interruption never
loses collected data.

Schema
------
::

    CREATE TABLE IF NOT EXISTS repo_data (
        full_name TEXT PRIMARY KEY,
        data      TEXT NOT NULL   -- JSON blob (RepoData)
    );

Extending
---------
Subclass ``BaseStorage`` to use a different backend (PostgreSQL, S3, …).
The only invariant is that ``upsert`` **merges** incoming data rather than
replacing the existing row, so partial collection stays safe.

See ``CONTRIBUTING.md § 3`` for a walkthrough.

Migration notes
---------------
Replaces the dual-table schema (``audits`` + ``repo_rows``) and legacy
ad-hoc cache files used by older scripts.
"""

from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from typing import Any, Optional

from core.models import RepoData


# ── Schema ────────────────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS repo_data (
    full_name TEXT PRIMARY KEY,
    data      TEXT NOT NULL
);
"""

_CREATE_ORG_CACHE_TABLE = """
CREATE TABLE IF NOT EXISTS org_cache (
    org        TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""


# ── Abstract base ─────────────────────────────────────────────────────


class BaseStorage(ABC):
    """Persistence contract used by the collector and compiler.

    Subclass this to use a different storage backend.  The critical
    invariant: ``upsert`` must *merge* the incoming ``RepoData`` into the
    existing record at the field level, not overwrite the entire row.  This
    ensures that fields collected in previous API calls are never lost.

    Example (merge via Pydantic)::

        existing = self.read(full_name) or RepoData()
        merged = existing.model_copy(
            update=update.model_dump(exclude_none=True)
        )
        # write merged.model_dump_json() to storage
    """

    @abstractmethod
    def init(self) -> None:
        """Create the schema if it does not already exist."""

    @abstractmethod
    def upsert(self, full_name: str, update: RepoData) -> None:
        """Merge ``update`` into the existing record for ``full_name``.

        Fields present in the existing record but absent from ``update``
        (i.e. set to ``None``) are preserved.  Fields present in both are
        overwritten with the new value.

        Args:
            full_name: Repository identifier, e.g. ``"ministryofjustice/foo"``.
            update:    Partial ``RepoData`` carrying one or more new fields.
        """

    @abstractmethod
    def read(self, full_name: str) -> Optional[RepoData]:
        """Return the stored data for one repo, or ``None`` if not found.

        Args:
            full_name: Repository identifier.
        """

    @abstractmethod
    def read_all(self) -> list[tuple[str, RepoData]]:
        """Return all rows as ``(full_name, RepoData)`` tuples, ordered by name."""

    @abstractmethod
    def delete(self, full_name: str) -> None:
        """Remove the record for ``full_name`` (no-op if absent)."""


# ── Concrete implementation ───────────────────────────────────────────


class SqliteRepoStorage(BaseStorage):
    """Single-table SQLite storage backend.

    Serialises ``RepoData`` via Pydantic's ``model_dump_json()`` and
    deserialises via ``model_validate_json()``, so no manual
    ``json.dumps`` / ``json.loads`` is needed anywhere.

    Upsert uses ``model_copy(update=…)`` so each endpoint's result is
    merged at the Pydantic-field level — running::

        storage.upsert("org/repo", RepoData(alerts=AlertData(dependabot_alerts=3)))

    will update only the ``alerts`` key, leaving all other existing fields
    untouched.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE)

    def upsert(self, full_name: str, update: RepoData) -> None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM repo_data WHERE full_name = ?",
                (full_name,),
            ).fetchone()

            if row:
                existing = RepoData.model_validate_json(row["data"])
                merged_payload = existing.model_dump(exclude_none=True)
                merged_payload.update(update.model_dump(exclude_none=True))
                # Re-validate merged payload so nested fields keep typed Pydantic models.
                merged = RepoData.model_validate(merged_payload)
            else:
                merged = update

            conn.execute(
                "INSERT OR REPLACE INTO repo_data (full_name, data) VALUES (?, ?)",
                (full_name, merged.model_dump_json()),
            )

    def read(self, full_name: str) -> Optional[RepoData]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM repo_data WHERE full_name = ?",
                (full_name,),
            ).fetchone()
        return RepoData.model_validate_json(row["data"]) if row else None

    def read_all(self) -> list[tuple[str, RepoData]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT full_name, data FROM repo_data ORDER BY full_name"
            ).fetchall()
        return [(r["full_name"], RepoData.model_validate_json(r["data"])) for r in rows]

    def delete(self, full_name: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM repo_data WHERE full_name = ?",
                (full_name,),
            )


class SqliteOrgStorage:
    """SQLite storage for organisation-level posture cache data."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        with self._connect() as conn:
            conn.execute(_CREATE_ORG_CACHE_TABLE)

    def read_cache(self, org: str) -> tuple[dict[str, Any], float] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data, updated_at FROM org_cache WHERE org = ?",
                (org,),
            ).fetchone()
        if row is None:
            return None

        data = json.loads(row["data"])
        if not isinstance(data, dict):
            return {}, float(row["updated_at"])
        return data, float(row["updated_at"])

    def upsert_cache(self, org: str, cache: dict[str, Any], updated_at: float) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO org_cache (org, data, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(org) DO UPDATE SET
                    data = excluded.data,
                    updated_at = excluded.updated_at
                """,
                (org, json.dumps(cache, default=str), updated_at),
            )
