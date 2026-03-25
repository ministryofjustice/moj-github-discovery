"""Helpers for reading repository selection files.

The preferred format is YAML with a top-level ``repos`` list:

repos:
  - owner/repo-a
  - owner/repo-b
"""

from __future__ import annotations

from pathlib import Path

import yaml


def _normalize_repo_names(values: list[object], source: str) -> list[str]:
    repos: list[str] = []
    seen: set[str] = set()

    for index, value in enumerate(values, start=1):
        if not isinstance(value, str):
            raise ValueError(
                f"Invalid repo entry at position {index} in {source}: expected string"
            )

        name = value.strip()
        if not name:
            continue

        owner, sep, repo = name.partition("/")
        if sep != "/" or not owner or not repo:
            raise ValueError(
                f"Invalid repo entry at position {index} in {source}: {name!r}"
            )

        if name not in seen:
            seen.add(name)
            repos.append(name)

    return repos


def load_repo_list_yaml(path: str | Path) -> list[str]:
    """Read a YAML repo list file and return normalized ``owner/repo`` values.

    Supported YAML structures:
    1) ``repos: ["owner/repo", ...]``
    2) ``["owner/repo", ...]``
    """
    file_path = Path(path)
    with file_path.open(encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)

    if loaded is None:
        return []

    if isinstance(loaded, dict):
        values = loaded.get("repos")
    elif isinstance(loaded, list):
        values = loaded
    else:
        raise ValueError(
            f"Invalid YAML structure in {file_path}: expected mapping or list"
        )

    if values is None:
        return []

    if not isinstance(values, list):
        raise ValueError(f"Invalid 'repos' value in {file_path}: expected a YAML list")

    return _normalize_repo_names(values, str(file_path))


def load_repo_list_file(path: str | Path) -> list[str]:
    """Read repositories from a YAML file, or plain text for compatibility."""
    file_path = Path(path)
    if file_path.suffix.lower() in {".yaml", ".yml"}:
        return load_repo_list_yaml(file_path)

    values: list[str] = []
    with file_path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            values.append(stripped)
    return _normalize_repo_names(values, str(file_path))
