#!/usr/bin/env python3

"""Find archive candidates using the shared core collector stack.

This script keeps the familiar archive_repos.py CLI while delegating API fetch,
pagination, retries, and persistence to the core package.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pandas as pd

from core.config import AuditConfig
from core.collector import RepoCollector, RepoListCollector
from core.github_api import (
    CodeSearchEndpoint,
    DependencyGraphEndpoint,
    GetRepoTreeEndpoint,
    RepoArchivedAtEndpoint,
    RepoDetailsEndpoint,
)
from core.github_client import GitHubHttpClient
from core.models import RepoData, RepoDetails
from core.output_paths import OutputPathResolver
from core.storage import SqliteRepoStorage

section_break = "\n" + ("=" * 80) + "\n"
sub_section_break = "\n" + ("-" * 80) + "\n"


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


def _list_archived_repo_names_from_storage(
    org: str,
    storage: SqliteRepoStorage,
) -> set[str]:
    """Extract names of archived repositories for the given organization from storage.

    Args:
        org: GitHub organization name to filter repos by.
        storage: SqliteRepoStorage instance to read repo data from.

    Returns:
        Set of archived repository names (without org prefix) for the given org.
    """
    archived_repo_names: set[str] = set()
    for full_name, data in storage.read_all():
        if not full_name.startswith(f"{org}/"):
            continue
        repo = data.repo_details
        if repo and repo.archived:
            archived_repo_names.add(full_name.split("/", 1)[-1])
    return archived_repo_names


def _extract_namespace_folders(
    paths: list[tuple[str, str | None]],
    namespace_root: str,
) -> set[str]:
    """Extract namespace folder names from a list of repository tree paths.

    Expects paths to be in format 'namespace_root/folder_name' and filters
    for directory items (type='tree') only.

    Args:
        paths: List of (path, item_type) tuples from a GitHub repo tree.
        namespace_root: Root folder name to search within (e.g., 'namespaces').

    Returns:
        Set of namespace folder names found under namespace_root.
    """
    namespace_folders: set[str] = set()
    root = namespace_root.strip("/")
    if not root:
        return namespace_folders

    for path, item_type in paths:
        if item_type != "tree":
            continue
        parts = path.split("/")
        if len(parts) == 2 and parts[0] == root:
            namespace_folders.add(parts[1])

    return namespace_folders


def _load_namespace_folders(
    org: str,
    namespace_repo: str,
    namespace_branch: str,
    namespace_root: str,
    auth_method: str | None,
) -> set[str]:
    """Load namespace folder names from a GitHub repository tree.

    Fetches the tree structure of a specified repository and branch, then
    extracts folder names from within the namespace_root directory.

    Args:
        org: GitHub organization name.
        namespace_repo: Repository name containing namespace folders.
        namespace_branch: Branch to inspect in the namespace repository.
        namespace_root: Top-level folder containing namespace directories.
        auth_method: GitHub authentication method (e.g., 'github_app', 'token').

    Returns:
        Set of namespace folder names from the repository.

    Raises:
        RuntimeError: If the repository tree cannot be accessed.
    """
    client = GitHubHttpClient(auth_method=auth_method)
    endpoint = GetRepoTreeEndpoint(client)
    repo_details = RepoDetails(
        full_name=f"{org}/{namespace_repo}",
        name=namespace_repo,
        default_branch=namespace_branch,
    )
    repo_tree = endpoint.fetch(
        org,
        namespace_repo,
        repo_details=repo_details,
    )

    if repo_tree.access != "ok":
        raise RuntimeError(
            f"Unable to load namespace tree for {org}/{namespace_repo}@{namespace_branch}: "
            f"{repo_tree.access}"
        )

    tree_entries = [(item.path, item.type) for item in repo_tree.tree]
    return _extract_namespace_folders(tree_entries, namespace_root)


def _append_flag(flag_text: str | None, flag: str) -> str:
    """Append a flag to a comma-separated flag string, avoiding duplicates.

    Args:
        flag_text: Existing comma-separated flags or None.
        flag: Flag to append.

    Returns:
        Updated comma-separated flag string.
    """
    existing = [part.strip() for part in (flag_text or "").split(",") if part.strip()]
    if flag not in existing:
        existing.append(flag)
    return ", ".join(existing)


def _apply_namespace_crossref(
    rows: list[dict[str, Any]],
    namespace_folders: set[str],
) -> None:
    """Apply namespace cross-reference logic to repository rows.

    For each row, checks if the repository has a corresponding namespace
    folder and marks archived repos that still have namespace folders with
    the 'archived_with_namespace_folder' flag.

    Args:
        rows: List of repository record dictionaries to augment.
        namespace_folders: Set of known namespace folder names.

    Side effects:
        Modifies each row to add 'has_namespace_folder' and
        'archived_with_namespace_folder' keys and updates 'flags'.
    """
    for row in rows:
        repo_name = row.get("repo") or row.get("full_name", "").split("/", 1)[-1]
        has_namespace_folder = repo_name in namespace_folders
        archived_with_namespace_folder = (
            bool(row.get("archived")) and has_namespace_folder
        )

        row["has_namespace_folder"] = has_namespace_folder
        row["archived_with_namespace_folder"] = archived_with_namespace_folder

        if archived_with_namespace_folder:
            row["flags"] = _append_flag(
                row.get("flags"),
                "archived_with_namespace_folder",
            )


def _build_namespace_crossref_summary(
    rows: list[dict[str, Any]],
    namespace_folders: set[str],
    orphaned: list[str],
) -> dict[str, Any]:
    """Build a summary of namespace cross-reference analysis results.

    Args:
        rows: Repository records (typically after _apply_namespace_crossref).
        namespace_folders: Set of known namespace folder names.
        orphaned: List of archived repository names with namespace folders.

    Returns:
        Dictionary with keys:
            - namespace_folders_total: Total number of namespace folders.
            - archived_repos_with_namespace_folder: Count of archived repos
              with matching namespace folders.
            - orphaned_namespaces: List of archived repo names with folders.
    """
    archived_rows = [row for row in rows if bool(row.get("archived"))]
    archived_with_namespace = [
        row for row in archived_rows if bool(row.get("archived_with_namespace_folder"))
    ]

    return {
        "namespace_folders_total": len(namespace_folders),
        "archived_repos_with_namespace_folder": len(archived_with_namespace),
        "orphaned_namespaces": orphaned,
    }


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
        "archived_at": data.repo_archived_at.archived_at
        if data.repo_archived_at
        else None,
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


def run(
    config: AuditConfig,
    auth: str | None,
    base_output_dir: str,
    base_internal_dir: str,
    **kwargs,
) -> None:
    resolver = OutputPathResolver(config, base_output_dir, base_internal_dir)
    archive_repos_config = config.archive_repos

    # Define Variables from Config and/or Args
    github_org = config.github_organization
    output_filename = archive_repos_config.output_filename
    page_num = archive_repos_config.page_num
    repo_limit = archive_repos_config.repo_limit
    sort_by_field = archive_repos_config.sort_by_field
    sort_asc = archive_repos_config.sort_ascending
    storage_db_path = resolver.database_path(archive_repos_config.database_path)
    use_cache = archive_repos_config.use_cache

    # Debug Config
    print(section_break, file=sys.stderr)

    print(
        "archive_repos to be executed with the following config values:",
        file=sys.stderr,
    )

    print(section_break, file=sys.stderr)

    print(f"GitHub Organization: {github_org}", file=sys.stderr)
    print(f"Output Filename: {output_filename}", file=sys.stderr)
    print(f"Page Number: {page_num}", file=sys.stderr)
    print(f"Repo Limit: {repo_limit}", file=sys.stderr)
    print(f"Sort By Field: {sort_by_field}", file=sys.stderr)
    print(f"Sort Ascending: {sort_asc}", file=sys.stderr)
    print(f"Storage DB Path: {storage_db_path}", file=sys.stderr)
    print(f"Use Cache: {use_cache}", file=sys.stderr)

    print(sub_section_break, file=sys.stderr)

    # Namespace cross-ref config
    if archive_repos_config.namespace_crossref.enabled:
        namespace_repo = archive_repos_config.namespace_crossref.target_repo
        namespace_branch = archive_repos_config.namespace_crossref.target_branch
        namespace_root = archive_repos_config.namespace_crossref.root_folder

        print("Namespace cross-reference enabled with config:", file=sys.stderr)
        print(f"- Namespace Repo: {namespace_repo}", file=sys.stderr)
        print(f"- Namespace Branch: {namespace_branch}", file=sys.stderr)
        print(f"- Namespace Root Folder: {namespace_root}", file=sys.stderr)

    else:
        print("Namespace cross-reference disabled", file=sys.stderr)

    print(section_break, file=sys.stderr)

    storage = SqliteRepoStorage(storage_db_path)
    storage.init()

    print("Storage initialized at", storage_db_path, file=sys.stderr)

    print("Starting repository list collection...", file=sys.stderr)

    if use_cache:
        print("Loading repository list from cache...", file=sys.stderr)
        repo_list = _list_repos_from_storage(github_org, storage)
    else:
        print("Collecting repository list from GitHub API...", file=sys.stderr)
        repo_list_collector = RepoListCollector(auth_method=auth)
        repo_list = repo_list_collector.collect(
            github_org,
            sort="pushed",
            direction="asc",
        )

    if repo_limit is not None:
        print(f"Limiting to first {repo_limit} repositories", file=sys.stderr)
        repo_list = repo_list[:repo_limit]

    if page_num is not None:
        page_size = 100
        start_idx = page_num * page_size
        end_idx = start_idx + page_size
        print(
            f"Processing page {page_num} (repos {start_idx}-{end_idx})",
            file=sys.stderr,
        )
        repo_list = repo_list[start_idx:end_idx]

    if not repo_list:
        print("No repositories found for the given selection.", file=sys.stderr)
        return

    print(f"Collected {len(repo_list)} repositories to process", file=sys.stderr)

    if not use_cache:
        print(
            "use_cache is False, starting API collection for repository details...",
            file=sys.stderr,
        )
        collector = RepoCollector(
            storage=storage,
            auth_method=auth,
            endpoints=[
                RepoDetailsEndpoint,
                DependencyGraphEndpoint,
                CodeSearchEndpoint,
                RepoArchivedAtEndpoint,
            ],
        )
        collector.collect(github_org, repos=repo_list, resume=True)

    rows: list[dict[str, Any]] = []
    namespace_crossref_summary: dict[str, Any] | None = None
    for full_name in repo_list:
        print(f"Collecting data for repo: {full_name}", file=sys.stderr)
        data = storage.read(full_name)
        if data is None:
            continue
        rows.append(_build_row(github_org, full_name, data))

    if archive_repos_config.namespace_crossref.enabled:
        namespace_folders = _load_namespace_folders(
            org=github_org,
            namespace_repo=namespace_repo,
            namespace_branch=namespace_branch,
            namespace_root=namespace_root,
            auth_method=auth,
        )
        _apply_namespace_crossref(rows, namespace_folders)

        archived_repo_names = _list_archived_repo_names_from_storage(
            github_org, storage
        )
        orphaned = sorted(namespace_folders.intersection(archived_repo_names))

        print(
            f"Namespace cross-reference enabled: {len(orphaned)} archived repo(s) "
            "still have namespace folders",
            file=sys.stderr,
        )
        if orphaned:
            print("Archived repos with namespace folders:", file=sys.stderr)
            for repo_name in orphaned:
                print(f"- {repo_name}", file=sys.stderr)

        namespace_crossref_summary = _build_namespace_crossref_summary(
            rows=rows,
            namespace_folders=namespace_folders,
            orphaned=orphaned,
        )

    df = _compute_derived_columns(pd.DataFrame(rows))

    if not df.empty and sort_by_field in df.columns:
        df = df.sort_values(by=sort_by_field, ascending=sort_asc, na_position="last")
    elif sort_by_field:
        print(f"Warning: sort key '{sort_by_field}' not a column", file=sys.stderr)

    records = df.to_dict(orient="records")

    output_path = resolver.script_output_file(
        archive_repos_config.output_subdir, output_filename
    )
    if output_path.suffix.lower() == ".xlsx":
        df.to_excel(str(output_path), index=False)
    else:
        df.to_csv(str(output_path), index=False)
    print(f"Wrote {output_path}", file=sys.stderr)
    if archive_repos_config.namespace_crossref.enabled:
        print(
            json.dumps(
                {
                    "records": records,
                    "namespace_crossref_summary": namespace_crossref_summary
                    or {
                        "namespace_folders_total": 0,
                        "archived_repos_with_namespace_folder": 0,
                        "orphaned_namespaces": [],
                    },
                },
                indent=2,
            )
        )
    else:
        print(json.dumps(records, indent=2))

    print(f"Processed {len(records)} repositories", file=sys.stderr)
