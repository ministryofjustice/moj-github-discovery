#!/usr/bin/env python3
"""GitHub Actions workflow posture discovery.

Refactored to use core modules:
  - Repo discovery / loading     core.github_api.list_org_repos, core.repo_list
  - HTTP transport               core.github_client.GitHubHttpClient
  - Workflow + repo data         WorkflowsEndpoint + RepoDetailsEndpoint via RepoCollector

Not yet in core (local implementations retained):
  - Repo-level Actions permissions  GET /repos/{owner}/{repo}/actions/permissions
  - Latest workflow run timestamp   GET /repos/{owner}/{repo}/actions/runs
  - Workflow YAML uses: parsing
"""

import argparse
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.collector import RepoCollector
from core.compiler import CsvCompiler
from core.github_api import (
    RepoDetailsEndpoint,
    WorkflowsEndpoint,
    check_workflow_permissions,
    fetch_latest_workflow_run_created_at,
    fetch_repo_actions_permissions,
    fetch_repo_file_text,
    list_org_repos,
)
from core.github_client import GitHubHttpClient
from core.models import RepoData
from core.repo_list import load_repo_list_file
from core.storage import SqliteRepoStorage
from core.transforms import parse_actions_from_content

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(SCRIPT_DIR, "github_workflow_posture.db")


def parse_actions_from_workflow(
    client: GitHubHttpClient,
    owner: str,
    repo_name: str,
    workflow_path: str,
) -> List[Dict[str, Any]]:
    """Fetch a workflow file and extract all ``uses:`` references."""
    content = fetch_repo_file_text(client, owner, repo_name, workflow_path)
    if content is None:
        print(
            f"  Skipped {repo_name}/{workflow_path}: could not load file",
            file=sys.stderr,
        )
        return []

    return parse_actions_from_content(content, repo_name, workflow_path)


# ── Row builders ─────────────────────────────────────────────────────


def build_repo_row(
    full_name: str,
    data: RepoData,
    actions_permissions: Dict[str, Any],
    latest_run_date: Optional[str],
) -> Dict[str, Any]:
    """Build a posture summary row from RepoData and locally fetched supplements."""
    repo = data.repo_details
    workflows = data.workflows
    owner, _, repo_name = full_name.partition("/")

    archived = repo.archived if repo else False
    default_branch = (repo.default_branch if repo else "") or "main"
    visibility = "private" if (repo and repo.private) else "public"

    workflow_count = workflows.count if workflows else 0
    has_workflows = workflow_count > 0
    workflow_names = ",".join(
        sorted(wf.get("name", "") for wf in (workflows.workflows if workflows else []))
    )

    actions_enabled = actions_permissions.get("enabled")
    allowed_actions = actions_permissions.get("allowed_actions", "")

    if archived and has_workflows:
        posture = "archived_with_workflows"
    elif archived:
        posture = "archived_no_workflows"
    elif has_workflows:
        posture = "active_with_workflows"
    else:
        posture = "active_no_workflows"

    disable_candidate = (archived and has_workflows) or (
        not has_workflows and actions_enabled is True
    )

    return {
        "repo": full_name,
        "owner": owner,
        "repo_name": repo_name,
        "visibility": visibility,
        "archived": archived,
        "default_branch": default_branch,
        "actions_enabled": actions_enabled,
        "allowed_actions": allowed_actions,
        "has_workflows": has_workflows,
        "workflow_count": workflow_count,
        "workflow_names": workflow_names,
        "latest_workflow_run": latest_run_date or "",
        "posture": posture,
        "disable_candidate": disable_candidate,
    }


def build_workflow_detail_rows(
    full_name: str,
    data: RepoData,
) -> List[Dict[str, Any]]:
    """Build one detail row per workflow from WorkflowData."""
    owner, _, repo_name = full_name.partition("/")
    workflows = data.workflows
    rows = []
    for wf in workflows.workflows if workflows else []:
        rows.append(
            {
                "repo": full_name,
                "owner": owner,
                "repo_name": repo_name,
                "workflow_name": wf.get("name", ""),
                "path": wf.get("path", ""),
                "state": wf.get("state", ""),
            }
        )
    return rows


# ── Summary report ────────────────────────────────────────────────────


def write_summary(
    path: str,
    repo_rows: List[Dict[str, Any]],
    detail_rows: List[Dict[str, Any]],
) -> None:
    """Write a human-readable summary report."""
    total = len(repo_rows)
    with_wf = [r for r in repo_rows if r.get("has_workflows")]
    without_wf = [r for r in repo_rows if not r.get("has_workflows")]
    archived_with = [
        r for r in repo_rows if r.get("archived") and r.get("has_workflows")
    ]
    archived_without = [
        r for r in repo_rows if r.get("archived") and not r.get("has_workflows")
    ]
    active_with = [
        r for r in repo_rows if not r.get("archived") and r.get("has_workflows")
    ]
    active_without = [
        r for r in repo_rows if not r.get("archived") and not r.get("has_workflows")
    ]
    disable_candidates = [r for r in repo_rows if r.get("disable_candidate")]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "=" * 70,
        "GITHUB ACTIONS WORKFLOW POSTURE - DISCOVERY REPORT",
        f"Generated: {now}",
        "=" * 70,
        "",
        "OVERVIEW",
        "_" * 40,
        f"  Total repositories scanned:       {total}",
        f"  Repos using GitHub Actions:        {len(with_wf)} ({len(with_wf) / max(total, 1) * 100:.1f}%)",
        f"  Repos NOT using GitHub Actions:    {len(without_wf)} ({len(without_wf) / max(total, 1) * 100:.1f}%)",
        f"  Total workflow files found:        {len(detail_rows)}",
        "",
        "BREAKDOWN",
        "_" * 40,
        f"  Active repos with workflows:       {len(active_with)}",
        f"  Active repos without workflows:    {len(active_without)}",
        f"  Archived repos with workflows:     {len(archived_with)}",
        f"  Archived repos without workflows:  {len(archived_without)}",
        "",
        f"  Candidates for disabling Actions:  {len(disable_candidates)}",
        "  (archived repos with workflows + active repos with Actions enabled but no workflow files)",
        "",
    ]

    top_repos = sorted(with_wf, key=lambda x: -x.get("workflow_count", 0))[:15]
    if top_repos:
        lines.append("TOP REPOSITORIES BY WORKFLOW COUNT")
        lines.append("-" * 40)
        for r in top_repos:
            lines.append(f"  {r['repo']:<55} workflows={r.get('workflow_count', 0):>3}")
        lines.append("")

    if archived_with:
        lines.append("ARCHIVED REPOS WITH WORKFLOWS (DISABLE CANDIDATES)")
        lines.append("-" * 40)
        lines.append(
            "  (Actions should be disabled on archived repos to reduce attack surface)"
        )
        lines.append("")
        for r in archived_with:
            lines.append(f"  {r['repo']:<55} workflows={r.get('workflow_count', 0):>3}")
        lines.append("")

    actions_no_wf = [r for r in active_without if r.get("actions_enabled") is True]
    if actions_no_wf:
        lines.append("ACTIVE REPOS: ACTIONS ENABLED BUT NO WORKFLOWS")
        lines.append("-" * 40)
        lines.append("  (Consider disabling Actions if not needed)")
        lines.append("")
        for r in actions_no_wf[:20]:
            lines.append(f"  {r['repo']}")
        if len(actions_no_wf) > 20:
            lines.append(f"  ... and {len(actions_no_wf) - 20} more")
        lines.append("")

    lines += ["=" * 70, "END OF REPORT", "=" * 70]

    report = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"Wrote {path}")
    print()
    print(report)


# ── Main ──────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identify repositories using GitHub Actions across the MoJ estate"
    )
    parser.add_argument(
        "--org",
        default=os.getenv("GITHUB_ORG", "ministryofjustice"),
        help="GitHub organisation to scan (default: env GITHUB_ORG or ministryofjustice)",
    )
    parser.add_argument(
        "--repos",
        nargs="*",
        help="Specific repos to scan, e.g. owner/repo owner/repo",
    )
    parser.add_argument(
        "--repo-file",
        help="Repo list file (YAML or plain text, one owner/repo per line)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=500,
        help="Max repos to scan (default: 500)",
    )
    parser.add_argument(
        "--out-prefix",
        default="github_workflow_posture",
        help="Prefix for output files (default: github_workflow_posture)",
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB,
        help=f"SQLite path for collection cache (default: {DEFAULT_DB})",
    )
    args = parser.parse_args()

    client = GitHubHttpClient()

    # 1. Resolve repo list
    if args.repos:
        repo_list = args.repos[: args.limit]
    elif args.repo_file:
        repo_list = load_repo_list_file(args.repo_file)[: args.limit]
    else:
        print("Listing org repositories...", file=sys.stderr)
        try:
            repo_list = list_org_repos(args.org, client)[: args.limit]
        except Exception as exc:
            raise SystemExit(
                f"Unable to list repos for org '{args.org}': {exc}. "
                "Use --repos or --repo-file with repos you can access."
            )

    if not repo_list:
        raise SystemExit("No repositories found to scan.")
    print(f"Found {len(repo_list)} repositories to scan.", file=sys.stderr)

    # 2. Collect repo details + workflow inventory via core
    storage = SqliteRepoStorage(args.db)
    collector = RepoCollector(
        storage=storage,
        client=client,
        endpoints=[RepoDetailsEndpoint, WorkflowsEndpoint],
    )
    primary_org = repo_list[0].split("/", 1)[0]
    collector.collect(primary_org, repos=repo_list, resume=False)

    # 3. Augment with local-only endpoints and build output rows
    repo_rows: List[Dict[str, Any]] = []
    detail_rows: List[Dict[str, Any]] = []
    total = len(repo_list)
    for idx, full_name in enumerate(repo_list, start=1):
        owner, _, repo_name = full_name.partition("/")
        print(f"[{idx}/{total}] Augmenting {full_name}...", file=sys.stderr)

        data = storage.read(full_name) or RepoData()
        actions_permissions = fetch_repo_actions_permissions(client, owner, repo_name)
        latest_run = (
            fetch_latest_workflow_run_created_at(client, owner, repo_name)
            if data.workflows and data.workflows.count > 0
            else None
        )

        repo_rows.append(
            build_repo_row(full_name, data, actions_permissions, latest_run)
        )
        detail_rows.extend(build_workflow_detail_rows(full_name, data))

    # 4. Write posture outputs
    prefix = args.out_prefix
    repo_count = CsvCompiler.write_rows(f"{prefix}_repo_summary.csv", repo_rows)
    details_count = CsvCompiler.write_rows(
        f"{prefix}_workflow_details.csv", detail_rows
    )
    print(f"Wrote {prefix}_repo_summary.csv ({repo_count} rows)")
    print(f"Wrote {prefix}_workflow_details.csv ({details_count} rows)")
    write_summary(f"{prefix}_summary.txt", repo_rows, detail_rows)

    print(
        f"\nDone. Scanned {total} repos, "
        f"found {sum(1 for r in repo_rows if r.get('has_workflows'))} using GitHub Actions "
        f"with {len(detail_rows)} total workflow files.",
        file=sys.stderr,
    )

    # 5. Analyse most common GitHub Actions used
    print("\n--- Analysing actions used across workflows ---")

    all_actions: List[Dict[str, Any]] = []
    for i, row in enumerate(detail_rows):
        actions = parse_actions_from_workflow(
            client, row["owner"], row["repo_name"], row["path"]
        )
        all_actions.extend(actions)
        if (i + 1) % 100 == 0:
            print(f"  Parsed {i + 1} / {len(detail_rows)} workflow files")
        time.sleep(0.1)

    print(f"Total action references found: {len(all_actions)}")

    usage_detail_count = CsvCompiler.write_rows(
        "github_actions_usage_detail.csv", all_actions
    )
    print(f"Wrote github_actions_usage_detail.csv ({usage_detail_count} rows)")

    action_counts = Counter(a["action_name"] for a in all_actions)
    usage_summary = [
        {"action_name": name, "times_used": count}
        for name, count in action_counts.most_common()
    ]
    usage_summary_count = CsvCompiler.write_rows(
        "github_actions_usage_summary.csv", usage_summary
    )
    print(f"Wrote github_actions_usage_summary.csv ({usage_summary_count} rows)")

    owner_counts = Counter(a["owner"] for a in all_actions)
    owner_summary = [
        {"owner": o, "actions_referenced": count}
        for o, count in owner_counts.most_common()
    ]
    owner_summary_count = CsvCompiler.write_rows(
        "github_actions_owner_summary.csv", owner_summary
    )
    print(f"Wrote github_actions_owner_summary.csv ({owner_summary_count} rows)")

    print(f"Unique actions: {len(usage_summary)}")
    print(f"Unique owners: {len(owner_summary)}")

    # 6. Workflow permissions check
    print("\n--- Analysing workflow permissions ---")

    all_permissions: List[Dict[str, Any]] = []
    for i, row in enumerate(detail_rows):
        perm = check_workflow_permissions(
            client, row["owner"], row["repo_name"], row["path"]
        )
        all_permissions.append(perm.model_dump())

        if (i + 1) % 100 == 0:
            print(f" Checked {i + 1} / {len(detail_rows)} workflow files")
            time.sleep(0.1)
    perms_count = CsvCompiler.write_rows(
        "github_workflow_permissions.csv", all_permissions
    )
    print(f"Wrote github_workflow_permissions.csv ({perms_count} rows)")

    no_block = sum(1 for p in all_permissions if p["finding"] == "no_permissions_block")
    write_all = sum(1 for p in all_permissions if p["finding"] == "write-all")
    has_write_count = sum(
        1 for p in all_permissions if p["finding"] == "has_write_scope"
    )
    compliant_count = sum(1 for p in all_permissions if p["finding"] == "compliant")
    skipped = sum(1 for p in all_permissions if p["finding"] == "could_not_load")

    print(f"No permissions block: {no_block}")
    print(f"permissions: write-all: {write_all}")
    print(f"Has write scope: {has_write_count}")
    print(f"Compliant (read-only): {compliant_count}")
    print(f"Could not load: {skipped}")

    print("--- Complete ---")


if __name__ == "__main__":
    main()
