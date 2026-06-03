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
        "--config-file",
        default=None,
        type=Path,
        help=("Path to audit config YAML. Defaults to config/audit_config.yaml."),
    )
    parser.add_argument(
        "--auth",
        choices=["pat", "app", "cli"],
        default=None,
        help="Select GitHub authentication method explicitly",
    )
    return parser.parse_args()


def main() -> None:
    global __start_time
    __start_time = time.monotonic()

    args = _parse_args()
    config: AuditConfig = load_audit_config(args.config_file)

    list_repos_config = config.list_repos

    # Define Variables from Config and/or Args
    database_path = list_repos_config.database_path
    if database_path is not None and not Path(database_path).is_absolute():
        database_path = str(Path(PROJECT_ROOT) / database_path)
    output_filename = list_repos_config.output_filename
    repo_file = config.repo_list_file
    if repo_file is not None and not Path(repo_file).is_absolute():
        repo_file = str(Path(PROJECT_ROOT) / repo_file)
    repo_limit = list_repos_config.repo_limit
    resume = list_repos_config.resume
    sort_by_field = list_repos_config.sort_by_field
    sort_asc = list_repos_config.sort_ascending

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
    print(
        f"Standard endpoints only: {list_repos_config.standard_endpoints}",
        file=sys.stderr,
    )

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
            "No repositories found in repo file (after applying any limit).",
            file=sys.stderr,
        )
        return

    storage = SqliteRepoStorage(database_path)
    selected_endpoints = (
        STANDARD_REPO_AUDIT_ENDPOINTS
        if list_repos_config.standard_endpoints
        else REPO_ENDPOINTS
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

    excel_path = os.path.join(OUTPUT_DIR, output_filename)
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
