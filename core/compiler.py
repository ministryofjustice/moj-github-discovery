"""Compiler — reads the database and writes output files.

The compiler:

1. Loads and **validates** ``fields.yaml`` via Pydantic.
2. Reads all rows from the database via :class:`~core.storage.BaseStorage`.
3. Applies registered transforms (:data:`~core.transforms.TRANSFORMS`).
4. Extracts the configured fields using dot-path resolution.
5. Writes the output file.

This separation means reports can be regenerated in seconds from the
already-collected database without touching the GitHub API.

Extending
---------
Subclass :class:`BaseCompiler` to add a new output format.  Register the
instance in :data:`COMPILERS` and add the corresponding CLI flag in
``compile.py``.

See ``CONTRIBUTING.md § 4`` for a walkthrough.

Migration notes
---------------
Replaces the DataFrame-to-Excel / DataFrame-to-CSV logic spread across
``list_repos.py``, ``archive_repos.py``, and ``org_security_posture.py``.
"""

from __future__ import annotations

import csv
import json
import sys
from abc import ABC, abstractmethod
from functools import reduce
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from core.models import FieldDefinition, FieldsConfig, FieldType, RepoData
from core.storage import BaseStorage
from core.transforms import TRANSFORMS, BaseTransform


# ── Fields config loader ──────────────────────────────────────────────


def load_fields_config(path: str | Path) -> FieldsConfig:
    """Load and validate a ``fields.yaml`` file.

    Uses Pydantic's ``FieldsConfig.model_validate`` so any typo in ``type``
    or missing required key raises a clear ``ValidationError`` immediately,
    before any database reads happen.

    Args:
        path: Path to the YAML file (absolute or relative to cwd).

    Returns:
        Validated :class:`~core.models.FieldsConfig` instance.

    Raises:
        pydantic.ValidationError: if the YAML does not match the schema.
        FileNotFoundError: if the file does not exist.
    """
    with open(path) as f:
        raw = yaml.safe_load(f)
    return FieldsConfig.model_validate(raw)


# ── Internal helpers ──────────────────────────────────────────────────


def _get_nested(data: dict, dot_path: str, default: Any = None) -> Any:
    """Resolve a dot-separated key path into a nested dict.

    Example::

        _get_nested({"alerts": {"dependabot_alerts": 3}}, "alerts.dependabot_alerts")
        # → 3
    """
    try:
        return reduce(lambda d, k: d[k], dot_path.split("."), data)
    except (KeyError, TypeError):
        return default


def _coerce(value: Any, field: FieldDefinition) -> Any:
    """Coerce a value to the column type declared in the field definition."""
    if value is None:
        return field.default

    if field.type == FieldType.integer:
        try:
            return int(value)
        except (ValueError, TypeError):
            return field.default

    if field.type == FieldType.boolean:
        return bool(value)

    if field.type == FieldType.date:
        try:
            from datetime import datetime

            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d")
        except Exception:
            return str(value)

    if field.type == FieldType.json:
        return json.dumps(value)

    return str(value) if value is not None else field.default


def _apply_transforms(data: RepoData, transforms: list[BaseTransform]) -> RepoData:
    for transform in transforms:
        try:
            data = transform.apply(data)
        except Exception as exc:
            print(
                f"[transform:{transform.name}] {exc}",
                file=sys.stderr,
            )
    return data


def build_dataframe(
    storage: BaseStorage,
    config: FieldsConfig,
    transforms: list[BaseTransform] | None = None,
) -> pd.DataFrame:
    """Read all rows, apply transforms, and build a DataFrame.

    This is the core function used by all concrete compilers.  It can also
    be used directly (e.g. in notebooks or dashboards) without going through
    a compiler.

    Args:
        storage:    Initialised storage backend.
        config:     Validated field definitions.
        transforms: List of transform instances to apply in order.  Defaults
                    to instantiating every class in ``TRANSFORMS``.

    Returns:
        DataFrame with one row per repo and one column per field definition.
    """
    active_transforms = [t() for t in TRANSFORMS] if transforms is None else transforms

    rows = []
    for full_name, repo_data in storage.read_all():
        data = _apply_transforms(repo_data, active_transforms)
        flat = data.model_dump()
        row: dict[str, Any] = {}
        for field in config.fields:
            raw = _get_nested(flat, field.source, field.default)
            row[field.column] = _coerce(raw, field)
        rows.append(row)

    return pd.DataFrame(rows)


# ── Abstract base ─────────────────────────────────────────────────────


class BaseCompiler(ABC):
    """Extend to add a new output format.

    Subclasses receive an already-initialised :class:`~core.storage.BaseStorage`
    and a validated :class:`~core.models.FieldsConfig`.  The compiler must
    not make any API calls or mutations to the database.

    Example::

        class JsonCompiler(BaseCompiler):
            @property
            def format_name(self) -> str:
                return "json"

            def compile(self, storage, output_path, config):
                df = build_dataframe(storage, config)
                df.to_json(output_path, orient="records", indent=2)

    Register in :data:`COMPILERS` and add a ``--json`` flag in ``compile.py``.
    """

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Short identifier for this format, e.g. ``"excel"`` or ``"csv"``."""

    @abstractmethod
    def compile(
        self,
        storage: BaseStorage,
        output_path: str | Path,
        config: FieldsConfig,
    ) -> None:
        """Read the database and write output to ``output_path``.

        Args:
            storage:     Initialised storage backend to read data from.
            output_path: Destination file path.
            config:      Validated field definitions loaded from ``fields.yaml``.
        """


# ── Concrete compilers ────────────────────────────────────────────────


class ExcelCompiler(BaseCompiler):
    """Write audit data to an Excel (``.xlsx``) workbook.

    Requires the ``openpyxl`` package (already in ``requirements.txt``).
    """

    @property
    def format_name(self) -> str:
        return "excel"

    def compile(
        self,
        storage: BaseStorage,
        output_path: str | Path,
        config: FieldsConfig,
    ) -> None:
        df = build_dataframe(storage, config)
        with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Repos")
        print(f"Wrote {output_path}", file=sys.stderr)


class CsvCompiler(BaseCompiler):
    """Write audit data to a CSV file."""

    @property
    def format_name(self) -> str:
        return "csv"

    def compile(
        self,
        storage: BaseStorage,
        output_path: str | Path,
        config: FieldsConfig,
    ) -> None:
        df = build_dataframe(storage, config)
        df.to_csv(output_path, index=False)
        print(f"Wrote {output_path}", file=sys.stderr)

    @staticmethod
    def write_rows(
        output_path: str | Path,
        rows: list[dict[str, Any]],
    ) -> int:
        """Write dict rows to CSV preserving first-seen key order.

        Returns:
            Number of rows written. If *rows* is empty, an empty file is created.
        """
        path = Path(output_path)
        if not rows:
            path.write_text("", encoding="utf-8")
            return 0

        fieldnames: list[str] = []
        seen: set[str] = set()
        for row in rows:
            for key in row:
                if key not in seen:
                    fieldnames.append(key)
                    seen.add(key)

        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return len(rows)


# ── Compiler registry ─────────────────────────────────────────────────
# Maps format name → compiler instance.  Add new compilers here and in
# the compile.py CLI argument parser.

COMPILERS: dict[str, BaseCompiler] = {
    "excel": ExcelCompiler(),
    "csv": CsvCompiler(),
}
