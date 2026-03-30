#!/usr/bin/env python3

from __future__ import annotations

import argparse
import atexit
import json
import os
import sys
import time
from typing import Any

import pandas as pd

from core.collector import RepoCollector
from core.github_api import (
    AlertsEndpoint,
    BranchProtectionEndpoint,
    CodeownersEndpoint,
    CommunityProfileEndpoint,
    ForkTemplateEndpoint,
    RepoDetailsEndpoint,
    WorkflowsEndpoint,
)
from core.presenters import build_repo_summary_table, repo_data_to_list_row
from core.repo_list import load_repo_list_file
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
            "Collect audit data for repositories listed in a repo file "
            "and optionally export to Excel."
        )
    )
    parser.add_argument(
        "--repo-file",
        required=True,
        help="Path to repo list file (YAML preferred).",
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
        help=f"SQLite path for core storage (default: {DEFAULT_DB_PATH}).",
    )
    parser.add_argument(
        "--excel",
        help="Write an Excel workbook with Repos and Summary sheets.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Only process the first N repos from --repo-file.",
    )
    parser.add_argument(
        "--sort",
        help=(
            "Sort field for output rows. Prefix with '-' for descending "
            "or '+' for ascending. Default: pushed_at descending."
        ),
    )
    return parser.parse_args()


def _derive_sort(raw_sort: str | None) -> tuple[str, bool]:
    if not raw_sort:
        return "pushed_at", False
    if raw_sort.startswith("-"):
        return raw_sort[1:], False
    if raw_sort.startswith("+"):
        return raw_sort[1:], True
    return raw_sort, True


def main() -> None:
    global __start_time
    __start_time = time.monotonic()

    args = _parse_args()

    try:
        repo_list = load_repo_list_file(args.repo_file)
    except Exception as exc:
        print(f"Failed to read repo file: {exc}", file=sys.stderr)
        sys.exit(2)

    if args.limit is not None:
        if args.limit < 0:
            print("--limit must be >= 0", file=sys.stderr)
            sys.exit(2)
        repo_list = repo_list[: args.limit]

    if not repo_list:
        print("No repositories found in repo file after applying --limit.")
        return

    storage = SqliteRepoStorage(args.db)
    collector = RepoCollector(
        storage=storage,
        endpoints=[
            RepoDetailsEndpoint,
            BranchProtectionEndpoint,
            AlertsEndpoint,
            CommunityProfileEndpoint,
            CodeownersEndpoint,
            ForkTemplateEndpoint,
            WorkflowsEndpoint,
        ],
    )

    primary_org = repo_list[0].split("/", 1)[0]
    collector.collect(primary_org, repos=repo_list, resume=False)

    rows: list[dict[str, Any]] = []
    for full_name in repo_list:
        data = storage.read(full_name)
        if data is not None:
            rows.append(repo_data_to_list_row(full_name, data))

    df = pd.DataFrame(rows)
    sort_key, sort_asc = _derive_sort(args.sort)
    if not df.empty and sort_key in df.columns:
        df = df.sort_values(by=sort_key, ascending=sort_asc, na_position="last")
    elif sort_key:
        print(f"Warning: sort key '{sort_key}' not a column", file=sys.stderr)

    summary = build_repo_summary_table(df)

    if args.excel:
        try:
            with pd.ExcelWriter(args.excel, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="Repos")
                summary.to_excel(writer, index=False, sheet_name="Summary")
            print(f"Wrote {args.excel}", file=sys.stderr)
        except ImportError:
            print(
                "Excel export requires the openpyxl package. "
                "Install it with `pip install openpyxl` and retry.",
                file=sys.stderr,
            )
            sys.exit(1)

    if not args.excel:
        print(json.dumps(df.to_dict(orient="records"), indent=2))


if __name__ == "__main__":
    main()
