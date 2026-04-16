#!/usr/bin/env python3

"""Find archive candidates using the shared core collector stack.

This script keeps the familiar archive_repos.py CLI while delegating API fetch,
pagination, retries, and persistence to the core package.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import sys
import time
from typing import Any

import pandas as pd

from core.collector import RepoCollector, RepoListCollector
from core.github_api import (
    CodeSearchEndpoint,
    DependencyGraphEndpoint,
    RepoDetailsEndpoint,
)
from core.models import RepoData
from core.storage import SqliteRepoStorage

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(SCRIPT_DIR, "repo_audit.db")

__start_time: float | None = None


def _report_elapsed() -> None:
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)


atexit.register(_report_elapsed)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build an archive-candidate inventory using shared core collectors."
        )
    )
    parser.add_argument("org", help="GitHub organisation login.")
    parser.add_argument("--csv", help="Export results to CSV.")
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit the number of repositories loaded from the organisation.",
    )
    parser.add_argument(
        "--page-num",
        type=int,
        help="Process one page only (100 repos per page, 0-indexed).",
    )
    parser.add_argument(
        "--sort",
        help=(
            "Sort by column. Prefix with '-' for descending or '+' for ascending. "
            "Default: days_since_push ascending."
        ),
    )
    parser.add_argument(
        "--audit-db",
        nargs="?",
        const=DEFAULT_DB_PATH,
        help=(
            "SQLite path for core storage persistence. "
            "If provided without a path, defaults to repo_audit.db."
        ),
    )
    parser.add_argument(
        "--cache-only",
        action="store_true",
        help="Skip API collection and use only existing data from the SQLite store.",
    )
    return parser.parse_args()


def _derive_sort(raw_sort: str | None) -> tuple[str, bool]:
    if not raw_sort:
        return "days_since_push", True
    if raw_sort.startswith("-"):
        return raw_sort[1:], False
    if raw_sort.startswith("+"):
        return raw_sort[1:], True
    return raw_sort, True


def _list_repos_from_storage(org: str, storage: SqliteRepoStorage) -> list[str]:
    repo_rows = [
        (full_name, data)
        for full_name, data in storage.read_all()
        if full_name.startswith(f"{org}/")
    ]

    # Preserve old behavior as closely as possible: process stale repos first.
    repo_rows.sort(
        key=lambda row: (
            row[1].repo_details.pushed_at if row[1].repo_details else "",
            row[0],
        )
    )
    return [full_name for full_name, _ in repo_rows]


def _build_row(org: str, full_name: str, data: RepoData) -> dict[str, Any]:
    repo = data.repo_details
    refs = data.references.items if data.references else []

    references = []
    active_references: set[str] = set()
    archive_references: set[str] = set()
    for item in refs:
        if item.full_name == full_name:
            continue
        references.append(
            {
                "full_name": item.full_name,
                "path": item.path,
                "archived": item.archived,
            }
        )
        if item.archived:
            archive_references.add(item.full_name)
        else:
            active_references.add(item.full_name)

    row: dict[str, Any] = {
        "org": org,
        "repo": repo.name if repo else full_name.split("/", 1)[-1],
        "full_name": full_name,
        "private": repo.private if repo else None,
        "archived": repo.archived if repo else None,
        "disabled": repo.disabled if repo else None,
        "fork": repo.fork if repo else None,
        "dependency_graph_enabled": (
            data.dependency_graph.enabled if data.dependency_graph else False
        ),
        "references": references,
        "archive_references": sorted(archive_references),
        "archived_at": repo.archived_at if repo else None,
        "active_references": sorted(active_references),
        "pushed_at": repo.pushed_at if repo else None,
        "default_branch": repo.default_branch if repo else None,
        "language": repo.language if repo else None,
        "open_issues": repo.open_issues_count if repo else None,
        "stargazers": repo.stargazers_count if repo else None,
        "watchers": repo.watchers_count if repo else None,
        "forks": repo.forks_count if repo else None,
        "description": repo.description if repo else None,
        "created_at": repo.created_at if repo else None,
        "updated_at": repo.updated_at if repo else None,
        "size": repo.size if repo else None,
        "is_template": repo.is_template if repo else None,
        "security_and_analysis": repo.security_and_analysis if repo else None,
    }

    flags: list[str] = []
    if row["archived"]:
        flags.append("archived")
        if (row.get("open_issues") or 0) > 0:
            flags.append("archived_open_issues")
        if (row.get("stargazers") or 0) > 0:
            flags.append("archived_has_stars")
        if (row.get("watchers") or 0) > 0:
            flags.append("archived_has_watchers")
        if (row.get("forks") or 0) > 0:
            flags.append("archived_has_forks")
        if row.get("disabled"):
            flags.append("archived_and_disabled")
    if row["fork"]:
        flags.append("fork")
    row["flags"] = ", ".join(flags)

    return row


def _compute_derived_columns(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    out = df.copy()
    now = pd.Timestamp.now("UTC")

    for col in ("pushed_at", "created_at", "updated_at", "archived_at"):
        if col in out.columns:
            out[col] = pd.to_datetime(out[col], errors="coerce", utc=True)

    if "pushed_at" in out.columns:
        out["days_since_push"] = (now - out["pushed_at"]).dt.days
    if "created_at" in out.columns:
        out["age_days"] = (now - out["created_at"]).dt.days
    if "archived_at" in out.columns:
        out["days_since_archived"] = (now - out["archived_at"]).dt.days

    for col in ("pushed_at", "created_at", "updated_at", "archived_at"):
        if col in out.columns:
            out[col] = out[col].dt.strftime("%Y-%m-%d %H:%M:%S")

    return out


def main() -> None:
    global __start_time
    __start_time = time.monotonic()

    args = _parse_args()

    if args.limit is not None and args.limit < 0:
        print("--limit must be >= 0", file=sys.stderr)
        sys.exit(2)
    if args.page_num is not None and args.page_num < 0:
        print("--page-num must be >= 0", file=sys.stderr)
        sys.exit(2)

    storage_db_path = args.audit_db or DEFAULT_DB_PATH
    storage = SqliteRepoStorage(storage_db_path)
    storage.init()

    if args.cache_only:
        repo_list = _list_repos_from_storage(args.org, storage)
    else:
        repo_list = RepoListCollector().collect(
            args.org,
            sort="pushed",
            direction="asc",
        )

    if args.limit is not None:
        repo_list = repo_list[: args.limit]

    if args.page_num is not None:
        page_size = 100
        start_idx = args.page_num * page_size
        end_idx = start_idx + page_size
        print(
            f"Processing page {args.page_num} (repos {start_idx}-{end_idx})",
            file=sys.stderr,
        )
        repo_list = repo_list[start_idx:end_idx]

    if not repo_list:
        print("No repositories found for the given selection.", file=sys.stderr)
        return

    if not args.cache_only:
        collector = RepoCollector(
            storage=storage,
            endpoints=[
                RepoDetailsEndpoint,
                DependencyGraphEndpoint,
                CodeSearchEndpoint,
            ],
        )
        collector.collect(args.org, repos=repo_list, resume=True)

    rows: list[dict[str, Any]] = []
    for full_name in repo_list:
        print(f"Collecting data for repo: {full_name}", file=sys.stderr)
        data = storage.read(full_name)
        if data is None:
            continue
        rows.append(_build_row(args.org, full_name, data))

    df = _compute_derived_columns(pd.DataFrame(rows))

    sort_key, sort_asc = _derive_sort(args.sort)
    if not df.empty and sort_key in df.columns:
        df = df.sort_values(by=sort_key, ascending=sort_asc, na_position="last")
    elif sort_key:
        print(f"Warning: sort key '{sort_key}' not a column", file=sys.stderr)

    records = df.to_dict(orient="records")

    if args.csv:
        df.to_csv(args.csv, index=False)
        print(f"Wrote {args.csv}", file=sys.stderr)
    elif not args.audit_db:
        print(json.dumps(records, indent=2))

    print(f"Processed {len(records)} repositories", file=sys.stderr)


if __name__ == "__main__":
    main()
