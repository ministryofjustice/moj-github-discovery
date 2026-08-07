"""
Assess repository compliance for default branch protection, branch naming, and branch security settings.
"""

from __future__ import annotations

import sys
from typing import Any

import pandas as pd

from core.collector import RepoCollector
from core.config import AuditConfig
from core.github_api import (
    REPO_ENDPOINTS,
    STANDARD_REPO_AUDIT_ENDPOINTS,
)
from core.output_paths import OutputPathResolver
from core.presenters import build_repo_summary_table, repo_data_to_list_row
from core.repo_list import iter_repo_batches, resolve_repo_selection
from core.storage import SqliteRepoStorage
from core.validation import direct_invocation_guard

section_break = "\n" + ("=" * 80) + "\n"
sub_section_break = "\n" + ("-" * 80) + "\n"


def run(
    config: AuditConfig,
    auth: str | None,
    base_output_dir: str,
    base_internal_dir: str,
    **kwargs,
) -> None:
    resolver = OutputPathResolver(config, base_output_dir, base_internal_dir)
    list_repos_config = config.list_repos

    # Define Variables from Config and CLI Args
    database_path = resolver.database_path(list_repos_config.database_path)
    output_filename = list_repos_config.output_filename
    repo_file = config.default_repo_list
    repo_limit = config.repo_limit
    repo_batch_size = config.repo_batch_size
    repo_search_scope = config.repo_search_scope
    use_cache = list_repos_config.use_cache
    sort_by_field = list_repos_config.sort_by_field
    sort_asc = list_repos_config.sort_ascending

    # List Repos Config Debug
    print(section_break, file=sys.stderr)

    print(
        "list_repos to be executed with the following config values:", file=sys.stderr
    )

    print(section_break, file=sys.stderr)

    print(f"Database Path: {database_path}", file=sys.stderr)
    print(f"Repo Search Scope: {repo_search_scope}", file=sys.stderr)
    print(f"Repo limit: {repo_limit}", file=sys.stderr)
    print(f"Repo batch size: {repo_batch_size}", file=sys.stderr)
    if repo_search_scope == "file":
        print(f"Using repo file: {repo_file}", file=sys.stderr)
    print(f"use_cache: {use_cache}", file=sys.stderr)
    print(f"Sort by field: {sort_by_field}", file=sys.stderr)
    print(f"Sort ascending: {sort_asc}", file=sys.stderr)
    print(
        f"Standard endpoints only: {list_repos_config.standard_endpoints_only}",
        file=sys.stderr,
    )

    print(sub_section_break, file=sys.stderr)

    # Resolve Repository List Scope and Apply Limit
    try:
        repo_list = resolve_repo_selection(
            config,
            auth,
            repos=kwargs.get("repos"),
            repo_file=kwargs.get("repo_file"),
        )
    except (FileNotFoundError, TypeError, ValueError) as exc:
        print(f"Failed to resolve repository list: {exc}", file=sys.stderr)
        sys.exit(2)

    if not repo_list:
        print(
            "No repositories found in repo file (after applying any limit).",
            file=sys.stderr,
        )
        return

    storage = SqliteRepoStorage(str(database_path))
    selected_endpoints = (
        STANDARD_REPO_AUDIT_ENDPOINTS
        if list_repos_config.standard_endpoints_only
        else REPO_ENDPOINTS
    )

    collector = RepoCollector(
        storage=storage, endpoints=selected_endpoints, auth_method=auth
    )

    total_batches = (len(repo_list) + repo_batch_size - 1) // repo_batch_size
    for idx, batch in enumerate(iter_repo_batches(repo_list, repo_batch_size), start=1):
        batch_label = f"batch {idx}/{total_batches}"
        print(
            f"Collecting batch {idx}/{total_batches} ({len(batch)} repos)",
            file=sys.stderr,
        )
        primary_org = batch[0].split("/", 1)[0]
        collector.collect(
            primary_org,
            repos=batch,
            resume=use_cache,
            batch_label=batch_label,
        )

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

    excel_path = resolver.script_output_file(
        list_repos_config.output_subdir, output_filename
    )
    try:
        with pd.ExcelWriter(str(excel_path), engine="openpyxl") as writer:
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
    direct_invocation_guard(__file__)
