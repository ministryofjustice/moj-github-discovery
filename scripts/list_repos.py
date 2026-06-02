#!/usr/bin/env python3

from __future__ import annotations

import argparse
import atexit
import os
import sys
import time
from pathlib import Path
from typing import Any

# add project root to path for core imports
# TODO: Remove once pyproject.toml is build-system configured
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd

from core.collector import RepoCollector
from core.config import AuditConfig, load_audit_config
from core.github_api import (
    REPO_ENDPOINTS,
    STANDARD_REPO_AUDIT_ENDPOINTS,
)
from core.presenters import build_repo_summary_table, repo_data_to_list_row
from core.repo_list import load_repo_list_file
from core.storage import SqliteRepoStorage
from core.utils import base_directory_setup

section_break = "\n" + ("=" * 80) + "\n"
sub_section_break = "\n" + ("-" * 80) + "\n"

# TODO: PROJECT_ROOT will be removed as an output of base_directory_setup once all scripts updated to use audit_config.yaml for repo_list loading
BASE_OUTPUT_DIR, BASE_INTERNAL_DIR, PROJECT_ROOT = base_directory_setup()

OUTPUT_DIR = os.path.join(BASE_OUTPUT_DIR, "list_repos")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Set Default Config File Path
DEFAULT_CONFIG_PATH = os.path.join(PROJECT_ROOT, "config", "audit_config.yaml")
# Set Default Database Path
DEFAULT_DB_PATH = os.path.join(BASE_INTERNAL_DIR, "repo_audit.db")


__start_time: float | None = None


# TODO: Consider moving to core.utils as repeated across scripts or to main.py when shared entrypoint developed
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
        help="Path to repo list file (YAML preferred).",
    )
    parser.add_argument(
        "--db-path",
        default=DEFAULT_DB_PATH,
        help=f"SQLite path for core storage (default: {DEFAULT_DB_PATH}).",
    )
    parser.add_argument(
        "--output-filename",
        help="Output filename for Excel export (default: list_repos.xlsx in output directory).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Only process the first N repos from --repo-file.",
    )
    parser.add_argument(
        "--sort-by",
        help=("Field to sort by.  Default: pushed_at descending."),
    )
    parser.add_argument(
        "--sort-ascending",
        type=bool,
        help="Sort order for --sort-by field (default: false [descending]).",
    )
    parser.add_argument(
        "--standard-endpoints",
        action="store_true",
        help=(
            "Use the reduced standard endpoint set (faster). "
            "By default, all repo endpoints are collected."
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Skip endpoints already collected in the database for each repo. "
            "Safe to use after an interrupted run."
        ),
    )
    parser.add_argument(
        "--auth",
        choices=["pat", "app", "cli"],
        default=None,
        help="Select GitHub authentication method explicitly",
    )
    parser.add_argument(
        "--config-file",
        default=DEFAULT_CONFIG_PATH,
        type=Path,
        help=(
            "Path to audit config YAML file. If not provided, the script will "
            "look for the default config at config/audit_config.yaml. If the "
            "default config file is missing, a fully-defaulted config will be "
            "used (all stages on)."
        ),
    )
    return parser.parse_args()


def main() -> None:
    global __start_time
    __start_time = time.monotonic()

    args = _parse_args()
    config: AuditConfig = load_audit_config(args.config_file)

    list_repos_config = config.list_repos

    # Define Variables from Config and/or Args
    database_path = args.db_path if args.db_path else list_repos_config.database_path
    output_filename = (
        args.output_filename
        if args.output_filename
        else list_repos_config.output_filename
    )
    repo_file = args.repo_file if args.repo_file else config.repo_list_file
    repo_limit = args.limit if args.limit is not None else list_repos_config.repo_limit
    resume = args.resume if args.resume else list_repos_config.resume
    sort_by_field = args.sort_by if args.sort_by else list_repos_config.sort_by_field
    sort_asc = (
        args.sort_ascending
        if args.sort_ascending is not None
        else list_repos_config.sort_ascending
    )

    # List Repos Config Debug
    print(section_break, file=sys.stderr)

    print(
        "list_repos to be executed with the following config values:", file=sys.stderr
    )

    print(section_break, file=sys.stderr)
    print(f"Database Path: {database_path}", file=sys.stderr)
    print(f"Using repo file: {repo_file}", file=sys.stderr)
    print(f"Repo limit: {repo_limit}", file=sys.stderr)
    print(f"Resume: {resume}", file=sys.stderr)
    print(f"Sort by field: {sort_by_field}", file=sys.stderr)
    print(f"Sort ascending: {sort_asc}", file=sys.stderr)

    print(sub_section_break, file=sys.stderr)

    try:
        repo_list = load_repo_list_file(repo_file)
    except Exception as exc:
        print(f"Failed to read repo file: {exc}", file=sys.stderr)
        sys.exit(2)

    if repo_limit is not None:
        if repo_limit < 0:
            print("--limit must be >= 0", file=sys.stderr)
            sys.exit(2)
        repo_list = repo_list[:repo_limit]

    if not repo_list:
        print(
            "No repositories found in repo file after applying --limit.",
            file=sys.stderr,
        )
        return

    storage = SqliteRepoStorage(database_path)
    selected_endpoints = (
        STANDARD_REPO_AUDIT_ENDPOINTS if args.standard_endpoints else REPO_ENDPOINTS
    )
    collector = RepoCollector(
        storage=storage, endpoints=selected_endpoints, auth_method=args.auth
    )

    primary_org = repo_list[0].split("/", 1)[0]
    collector.collect(primary_org, repos=repo_list, resume=resume)

    rows: list[dict[str, Any]] = []
    for full_name in repo_list:
        data = storage.read(full_name)
        if data is not None:
            rows.append(repo_data_to_list_row(full_name, data))

    df = pd.DataFrame(rows)
    if not df.empty and sort_by_field in df.columns:
        df = df.sort_values(by=sort_by_field, ascending=sort_asc, na_position="last")
    elif sort_by_field:
        print(f"Warning: sort key '{sort_by_field}' not a column", file=sys.stderr)

    summary = build_repo_summary_table(df)

    excel_path = os.path.join(OUTPUT_DIR, args.output_filename)
    try:
        with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Repos")
            summary.to_excel(writer, index=False, sheet_name="Summary")
        print(f"Wrote {excel_path}", file=sys.stderr)
    except ImportError:
        print(
            "Excel export requires the openpyxl package. "
            "Install it with `pip install openpyxl` and retry.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
