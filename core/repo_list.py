"""Helpers for reading repository selection files.

The preferred format is YAML with a top-level ``repos`` list:

repos:
  - owner/repo-a
  - owner/repo-b
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Literal

import yaml

from core.collector import RepoListCollector
from core.config import AuditConfig


def _normalize_repo_names(values: list[object], source: str) -> list[str]:
    repos: list[str] = []
    seen: set[str] = set()

    for index, value in enumerate(values, start=1):
        if not isinstance(value, str):
            raise TypeError(
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
        raise TypeError(
            f"Invalid YAML structure in {file_path}: expected mapping or list"
        )

    if values is None:
        return []

    if not isinstance(values, list):
        raise TypeError(f"Invalid 'repos' value in {file_path}: expected a YAML list")

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


def _apply_repo_limit(repos: list[str], limit: int | None, source: str) -> list[str]:
    if limit is None:
        return repos
    if limit < 0:
        raise ValueError("repo_limit must be >= 0")
    if limit > len(repos):
        print(
            f"[warn] repo_limit ({limit}) is greater than repositories resolved from {source} ({len(repos)}). Loading all available repos.",
            file=sys.stderr,
        )
    return repos[:limit]


def resolve_repo_selection(
    config: AuditConfig,
    auth: Literal["pat", "app", "cli"] | None,
    *,
    repos: list[str] | None = None,
    repo_file: str | Path | None = None,
) -> list[str]:
    """Resolve repositories using CLI overrides or global config scope.

    Resolution order:
    1. ``repos`` explicit list from CLI.
    2. ``repo_file`` explicit file path from CLI.
    3. Config-driven ``repo_search_scope`` (``file`` or ``org``).
    """
    if repos and repo_file:
        raise ValueError("--repos and --repo-file are mutually exclusive")

    if repos:
        selected = _normalize_repo_names(repos, "--repos")
        return _apply_repo_limit(selected, config.repo_limit, "--repos")

    if repo_file:
        repo_file_path = Path(repo_file)
        if not repo_file_path.exists():
            raise FileNotFoundError(f"Repo file not found: {repo_file_path}")
        selected = load_repo_list_file(repo_file_path)
        return _apply_repo_limit(selected, config.repo_limit, str(repo_file_path))

    if config.repo_search_scope == "file":
        default_file = Path(config.default_repo_list)
        if not default_file.exists():
            raise FileNotFoundError(
                f"Configured default_repo_list does not exist: {default_file}"
            )
        selected = load_repo_list_file(default_file)
        return _apply_repo_limit(selected, config.repo_limit, str(default_file))

    repo_list_collector = RepoListCollector(auth_method=auth)
    selected = repo_list_collector.collect(
        config.github_organization,
        sort="pushed",
        direction="asc",
    )
    return _apply_repo_limit(selected, config.repo_limit, "org API")


def iter_repo_batches(repos: list[str], batch_size: int) -> Iterator[list[str]]:
    """Yield deterministic repository batches of up to ``batch_size`` entries."""
    if batch_size <= 0:
        raise ValueError(f"batch_size must be > 0, got {batch_size}")
    for start in range(0, len(repos), batch_size):
        yield repos[start : start + batch_size]
