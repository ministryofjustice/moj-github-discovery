#!/usr/bin/env python3
"""GitHub Actions workflow posture discovery.

Refactored to use core modules:
    - Repo discovery / loading      core.github_api.list_org_repos, core.repo_list
    - HTTP transport                core.github_client.GitHubHttpClient
    - Workflow + repo data          RepoCollector with typed repo-scoped endpoints
    - Stage toggles                 core.config.load_audit_config

Not yet in core (local implementations retained):
    - Workflow YAML uses: parsing
"""

import argparse
import os
import sys
import time
import sqlite3
import pandas as pd
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

# add project root to path for core imports
# TODO: Remove once pyproject.toml is build-system configured
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.collector import RepoCollector
from core.compiler import CsvCompiler
from core.config import AuditConfig, load_audit_config
from core.github_api import (
    LatestWorkflowRunEndpoint,
    RepoDetailsEndpoint,
    RepoActionsPermissionsEndpoint,
    WorkflowsEndpoint,
    check_workflow_permissions,
    check_credential_posture,
    check_trigger_risk,
    fetch_repo_file_text,
    list_org_repos,
)
from core.github_client import GitHubHttpClient
from core.models import RepoActionsPermissionsData, RepoData
from core.repo_list import load_repo_list_file
from core.storage import SqliteRepoStorage
from core.transforms import parse_actions_from_content

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(SCRIPT_DIR, "github_workflow_posture.db")


# --- Workflow file parsing ------------------------------------------------


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


# --- Row builders ---------------------------------------------------------


def build_repo_row(full_name: str, data: RepoData) -> Dict[str, Any]:
    """Build a posture summary row from collected RepoData."""
    repo = data.repo_details
    workflows = data.workflows
    actions_permissions = data.repo_actions_permissions or RepoActionsPermissionsData()
    owner, _, repo_name = full_name.partition("/")

    archived = repo.archived if repo else False
    default_branch = (repo.default_branch if repo else "") or "main"
    visibility = "private" if (repo and repo.private) else "public"

    workflow_count = workflows.count if workflows else 0
    has_workflows = workflow_count > 0
    workflow_names = ",".join(
        sorted(wf.get("name", "") for wf in (workflows.workflows if workflows else []))
    )

    actions_enabled = actions_permissions.enabled
    allowed_actions = actions_permissions.allowed_actions or ""

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
        "latest_workflow_run": (
            data.latest_workflow_run.created_at if data.latest_workflow_run else ""
        )
        or "",
        "posture": posture,
        "disable_candidate": disable_candidate,
    }


def build_workflow_detail_rows(full_name: str, data: RepoData) -> List[Dict[str, Any]]:
    """Build one detail row per workflow from WorkflowData."""
    owner, _, repo_name = full_name.partition("/")
    workflows = data.workflows
    rows: List[Dict[str, Any]] = []
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


# --- Summary report -------------------------------------------------------


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
        "-" * 40,
        f"  Total repositories scanned:       {total}",
        f"  Repos using GitHub Actions:       {len(with_wf)} ({len(with_wf) / max(total, 1) * 100:.1f}%)",
        f"  Repos NOT using GitHub Actions:   {len(without_wf)} ({len(without_wf) / max(total, 1) * 100:.1f}%)",
        f"  Total workflow files found:       {len(detail_rows)}",
        "",
        "BREAKDOWN",
        "-" * 40,
        f"  Active repos with workflows:      {len(active_with)}",
        f"  Active repos without workflows:   {len(active_without)}",
        f"  Archived repos with workflows:    {len(archived_with)}",
        f"  Archived repos without workflows: {len(archived_without)}",
        "",
        f"  Candidates for disabling Actions: {len(disable_candidates)}",
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


# --- CLI ------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
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
        nargs="+",
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
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume collection by skipping endpoint data already cached in the database",
    )
    parser.add_argument(
        "--auth",
        choices=["pat", "app", "cli"],
        default=None,
        help="Select GitHub authentication method explicitly",
    )
    parser.add_argument(
        "--config-file",
        type=Path,
        default=None,
        help=(
            "Path to audit config YAML. Defaults to config/audit_config.yaml "
            "if present, otherwise all stages run with built-in defaults."
        ),
    )
    return parser.parse_args()


# --- Stage functions ------------------------------------------------------


def resolve_repo_list(
    args: argparse.Namespace,
    client: GitHubHttpClient,
    config: AuditConfig,
) -> List[str]:
    """Stage 1: Resolve the repository list to scan (mandatory).

    Resolution order:
      1. ``--repos`` CLI arg (explicit list)
      2. ``--repo-file`` CLI arg (explicit path)
      3. ``repo_list_file`` from the loaded audit config, if that path exists
      4. ``repo_list.yaml`` in the current working directory, if present
      5. Fall back to listing the org via the GitHub API
    """
    if args.repos:
        repo_list = args.repos[: args.limit]
    elif args.repo_file:
        repo_list = load_repo_list_file(args.repo_file)[: args.limit]
    elif config.repo_list_file and Path(config.repo_list_file).exists():
        print(
            f"Using repo list from config: {config.repo_list_file}",
            file=sys.stderr,
        )
        repo_list = load_repo_list_file(config.repo_list_file)[: args.limit]
    elif Path("repo_list.yaml").exists():
        print(
            "Using repo_list.yaml from current directory",
            file=sys.stderr,
        )
        repo_list = load_repo_list_file("repo_list.yaml")[: args.limit]
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
    return repo_list


def collect_baseline(
    args: argparse.Namespace,
    client: GitHubHttpClient,
    repo_list: List[str],
    storage: SqliteRepoStorage,
) -> None:
    """Stage 2: Collect baseline repo metadata and workflow inventory."""
    collector = RepoCollector(
        storage=storage,
        client=client,
        endpoints=[
            RepoDetailsEndpoint,
            WorkflowsEndpoint,
        ],
    )
    primary_org = repo_list[0].split("/", 1)[0]
    collector.collect(primary_org, repos=repo_list, resume=args.resume)


def collect_additional(
    args: argparse.Namespace,
    client: GitHubHttpClient,
    repo_list: List[str],
    storage: SqliteRepoStorage,
) -> None:
    """Stage 3: Collect remaining workflow posture data."""
    primary_org = repo_list[0].split("/", 1)[0]

    # 3.1 Collect repo-level Actions permissions for all repos
    collector = RepoCollector(
        storage=storage,
        client=client,
        endpoints=[RepoActionsPermissionsEndpoint],
    )
    collector.collect(primary_org, repos=repo_list, resume=args.resume)

    # 3.2 Collect latest workflow run only for repos that have workflows
    repos_with_workflows: List[str] = []
    for full_name in repo_list:
        data = storage.read(full_name) or RepoData()
        if data.workflows and data.workflows.count > 0:
            repos_with_workflows.append(full_name)
    if repos_with_workflows:
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[LatestWorkflowRunEndpoint],
        )
        collector.collect(
            primary_org,
            repos=repos_with_workflows,
            resume=args.resume,
        )


def build_rows(
    repo_list: List[str], storage: SqliteRepoStorage
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Stage 4: Read collected data and build output row sets.

    Always runs — downstream stages need ``detail_rows``. Reads are cheap
    (SQLite only) so there is no gain from toggling this off. if the
    cache is empty ( e.g Stages 2/3 were skipped before any prior run
    populated it), this returns empty rows for the affected repos and
    lets later stages no-op gracefully, rather than crash.
    """
    repo_rows: List[Dict[str, Any]] = []
    detail_rows: List[Dict[str, Any]] = []
    total = len(repo_list)
    for idx, full_name in enumerate(repo_list, start=1):
        print(f"[{idx}/{total}] Augmenting {full_name}...", file=sys.stderr)
        try:
            data = storage.read(full_name) or RepoData()
        except sqlite3.OperationalError as exc:
            print(
                f" Cache unavailable for {full_name} ({exc}). "
                "Skipping row build - likely Stages 2/3 were disabled "
                "before the cache was populated.",
                file=sys.stderr,
            )
            data = RepoData()
        repo_rows.append(build_repo_row(full_name, data))
        detail_rows.extend(build_workflow_detail_rows(full_name, data))
    return repo_rows, detail_rows


def write_posture_reports(
    args: argparse.Namespace,
    repo_rows: List[Dict[str, Any]],
    detail_rows: List[Dict[str, Any]],
) -> None:
    """Stage 5: Write repo-level posture reports."""
    prefix = args.out_prefix
    repo_count = CsvCompiler.write_rows(f"{prefix}_repo_summary.csv", repo_rows)
    details_count = CsvCompiler.write_rows(
        f"{prefix}_workflow_details.csv", detail_rows
    )
    print(f"Wrote {prefix}_repo_summary.csv ({repo_count} rows)")
    print(f"Wrote {prefix}_workflow_details.csv ({details_count} rows)")
    write_summary(f"{prefix}_summary.txt", repo_rows, detail_rows)

    total = len(repo_rows)
    print(
        f"\nDone. Scanned {total} repos, "
        f"found {sum(1 for r in repo_rows if r.get('has_workflows'))} using GitHub Actions "
        f"with {len(detail_rows)} total workflow files.",
        file=sys.stderr,
    )


def actions_analysis(
    client: GitHubHttpClient, detail_rows: List[Dict[str, Any]]
) -> None:
    """Stage 6: Parse workflow files to inventory action usage + SHA pinning."""
    # 6. Analyse most common GitHub Actions used
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

    # If nothing was parsed, write empty CSVs with the right headers and bail.
    if not all_actions:
        empty_usage = pd.DataFrame(columns=["action_name", "times_used"])
        empty_owner = pd.DataFrame(columns=["owner", "actions_referenced"])
        empty_pinning = pd.DataFrame(
            columns=[
                "repo",
                "total_refs",
                "pinned",
                "unpinned",
                "compliance_pct",
            ]
        )
        empty_usage.to_csv(
            "github_actions_usage_summary.csv", index=False, lineterminator="\r\n"
        )
        empty_owner.to_csv(
            "github_actions_owner_summary.csv", index=False, lineterminator="\r\n"
        )
        empty_pinning.to_csv(
            "github_actions_pinning_per_repo.csv", index=False, lineterminator="\r\n"
        )
        print("Wrote github_actions_usage_summary.csv (0 rows)")
        print("Wrote github_actions_owner_summary.csv (0 rows)")
        print("Wrote github_actions_pinning_per_repo.csv (0 rows)")
        print("Unique actions: 0")
        print("Unique owners: 0")
        print("\n--- Analysing SHA pinning compliance ---")
        print("Total action references: 0")
        print("Pinned to SHA: 0")
        print("Unpinned (mutable tag): 0")
        print("Wrote github_actions_unpinned_detail.csv (0 rows)")
        print("Repos with unpinned actions: 0")
        print("Repos fully pinned: 0")
        return

    # Build the master DataFrame once and reuse for every aggregation.
    df = pd.DataFrame(all_actions)

    # Action usage summary: count references per action_name, sort descending.
    usage_summary_df = (
        df.groupby("action_name", sort=False)
        .size()
        .reset_index(name="times_used")
        .sort_values(by="times_used", ascending=False, kind="stable")
        .reset_index(drop=True)
    )
    usage_summary_df.to_csv(
        "github_actions_usage_summary.csv", index=False, lineterminator="\r\n"
    )
    print(f"Wrote github_actions_usage_summary.csv ({len(usage_summary_df)} rows)")

    # Owner summary: count references per owner, sort descending.
    owner_summary_df = (
        df.groupby("owner", sort=False)
        .size()
        .reset_index(name="actions_referenced")
        .sort_values(by="actions_referenced", ascending=False, kind="stable")
        .reset_index(drop=True)
    )
    owner_summary_df.to_csv(
        "github_actions_owner_summary.csv", index=False, lineterminator="\r\n"
    )
    print(f"Wrote github_actions_owner_summary.csv ({len(owner_summary_df)} rows)")

    print(f"Unique actions: {len(usage_summary_df)}")
    print(f"Unique owners: {len(owner_summary_df)}")

    # 6b. SHA pinning compliance
    print("\n--- Analysing SHA pinning compliance ---")

    # Unpinned detail: rows that have a version but aren't pinned to a SHA.
    versioned = df[df["version"] != "none"]
    unpinned_df = versioned[~versioned["is_pinned"]]
    pinned_df = df[df["is_pinned"]]

    print(f"Total action references: {len(df)}")
    print(f"Pinned to SHA: {len(pinned_df)}")
    print(f"Unpinned (mutable tag): {len(unpinned_df)}")

    unpinned_count = CsvCompiler.write_rows(
        "github_actions_unpinned_detail.csv", unpinned_df.to_dict("records")
    )
    print(f"Wrote github_actions_unpinned_detail.csv ({unpinned_count} rows)")

    # Per-repo pinning compliance: total / pinned / unpinned / pct, sorted by
    # most unpinned first.
    if versioned.empty:
        pinning_df = pd.DataFrame(
            columns=[
                "repo",
                "total_refs",
                "pinned",
                "unpinned",
                "compliance_pct",
            ]
        )
    else:
        pinning_df = (
            versioned.groupby("repo", sort=False)
            .agg(
                total_refs=("is_pinned", "size"),
                pinned=("is_pinned", "sum"),
            )
            .reset_index()
        )
        pinning_df["unpinned"] = pinning_df["total_refs"] - pinning_df["pinned"]
        pinning_df["compliance_pct"] = (
            (pinning_df["pinned"] / pinning_df["total_refs"].clip(lower=1)) * 100
        ).round(1)
        pinning_df = pinning_df[
            ["repo", "total_refs", "pinned", "unpinned", "compliance_pct"]
        ]
        pinning_df = pinning_df.sort_values(
            by="unpinned", ascending=False, kind="stable"
        ).reset_index(drop=True)

    pinning_df.to_csv(
        "github_actions_pinning_per_repo.csv", index=False, lineterminator="\r\n"
    )
    print(f"Wrote github_actions_pinning_per_repo.csv ({len(pinning_df)} rows)")
    print(
        f"Repos with unpinned actions: "
        f"{int((pinning_df['unpinned'] > 0).sum()) if not pinning_df.empty else 0}"
    )
    print(
        f"Repos fully pinned: "
        f"{int((pinning_df['unpinned'] == 0).sum()) if not pinning_df.empty else 0}"
    )


def permissions_analysis(
    client: GitHubHttpClient, detail_rows: List[Dict[str, Any]]
) -> None:
    """Stage 7: Parse workflow files for permissions posture."""
    print("\n--- Analysing workflow permissions ---")

    all_permissions: List[Dict[str, Any]] = []
    for i, row in enumerate(detail_rows):
        perm = check_workflow_permissions(
            client, row["owner"], row["repo_name"], row["path"]
        )
        all_permissions.append(perm.model_dump())
        if (i + 1) % 100 == 0:
            print(f"  Checked {i + 1} / {len(detail_rows)} workflow files")
            time.sleep(0.1)

    perms_count = CsvCompiler.write_rows(
        "github_workflow_permissions.csv", all_permissions
    )
    print(f"Wrote github_workflow_permissions.csv ({perms_count} rows)")

    # Tally findings via pandas value_counts for clarity.
    if all_permissions:
        finding_counts = pd.DataFrame(all_permissions)["finding"].value_counts()
    else:
        finding_counts = pd.Series(dtype=int)

    no_block = int(finding_counts.get("no_permissions_block", 0))
    write_all = int(finding_counts.get("write-all", 0))
    has_write_count = int(finding_counts.get("has_write_scope", 0))
    compliant_count = int(finding_counts.get("compliant", 0))
    skipped = int(finding_counts.get("could_not_load", 0))

    print(f"No permissions block: {no_block}")
    print(f"permissions: write-all: {write_all}")
    print(f"Has write scope: {has_write_count}")
    print(f"Compliant (read-only): {compliant_count}")
    print(f"Could not load: {skipped}")


def credentials_analysis(
    client: GitHubHttpClient, detail_rows: List[Dict[str, Any]]
) -> None:
    """Stage 8: Assess OIDC vs long-lived credentials."""
    print("\n--- Assessing OIDC vs long-lived credentials ---")

    all_credential_findings: List[Dict[str, Any]] = []
    for i, row in enumerate(detail_rows):
        finding = check_credential_posture(
            client, row["owner"], row["repo_name"], row["path"]
        )
        all_credential_findings.append(finding.model_dump())
        if (i + 1) % 100 == 0:
            print(f"  Checked {i + 1} / {len(detail_rows)} workflow files")
            time.sleep(0.1)

    cred_count = CsvCompiler.write_rows(
        "github_workflow_credential_posture.csv", all_credential_findings
    )
    print(f"Wrote github_workflow_credential_posture.csv ({cred_count} rows)")

    repo_cred_summary: Dict[str, Dict[str, int]] = {}
    for f in all_credential_findings:
        repo = f["repo"]
        if repo not in repo_cred_summary:
            repo_cred_summary[repo] = {
                "oidc": 0,
                "long_lived_credentials": 0,
                "mixed": 0,
                "no_cloud_auth_detected": 0,
                "could_not_load": 0,
                "total_workflows": 0,
            }
        repo_cred_summary[repo]["total_workflows"] += 1
        repo_cred_summary[repo][f["posture"]] += 1

    cred_repo_rows = [
        {
            "repo": repo,
            "total_workflows": counts["total_workflows"],
            "oidc": counts["oidc"],
            "long_lived_credentials": counts["long_lived_credentials"],
            "mixed": counts["mixed"],
            "no_cloud_auth_detected": counts["no_cloud_auth_detected"],
            "could_not_load": counts["could_not_load"],
        }
        for repo, counts in sorted(
            repo_cred_summary.items(),
            key=lambda x: x[1]["long_lived_credentials"],
            reverse=True,
        )
    ]

    cred_repo_count = CsvCompiler.write_rows(
        "github_workflow_credential_posture_per_repo.csv", cred_repo_rows
    )
    print(
        f"Wrote github_workflow_credential_posture_per_repo.csv "
        f"({cred_repo_count} rows)"
    )

    oidc_only = sum(1 for f in all_credential_findings if f["posture"] == "oidc")
    long_lived = sum(
        1 for f in all_credential_findings if f["posture"] == "long_lived_credentials"
    )
    mixed = sum(1 for f in all_credential_findings if f["posture"] == "mixed")
    no_cloud = sum(
        1 for f in all_credential_findings if f["posture"] == "no_cloud_auth_detected"
    )
    skipped = sum(
        1 for f in all_credential_findings if f["posture"] == "could_not_load"
    )

    print(f"OIDC only: {oidc_only}")
    print(f"Long-lived credentials only: {long_lived}")
    print(f"Mixed (both): {mixed}")
    print(f"No cloud auth detected: {no_cloud}")
    print(f"Could not load: {skipped}")


def trigger_risk_analysis(
    client: GitHubHttpClient, detail_rows: List[Dict[str, Any]]
) -> None:
    """Stage 9: Analyse workflow trigger config risk."""
    print("\n--- Analysing workflow trigger risk ---")

    all_trigger_findings: List[Dict[str, Any]] = []
    for i, row in enumerate(detail_rows):
        finding = check_trigger_risk(
            client, row["owner"], row["repo_name"], row["path"]
        )
        all_trigger_findings.append(finding.model_dump())
        if (i + 1) % 100 == 0:
            print(f"  Checked {i + 1} / {len(detail_rows)} workflow files")
            time.sleep(0.1)

    trigger_count = CsvCompiler.write_rows(
        "github_workflow_trigger_risk.csv", all_trigger_findings
    )
    print(f"Wrote github_workflow_trigger_risk.csv ({trigger_count} rows)")

    repo_trigger_summary: Dict[str, Dict[str, int]] = {}
    for f in all_trigger_findings:
        repo = f["repo"]
        if repo not in repo_trigger_summary:
            repo_trigger_summary[repo] = {
                "total_workflows": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "no_risk": 0,
                "could_not_load": 0,
            }
        repo_trigger_summary[repo]["total_workflows"] += 1
        if f["posture"] == "could_not_load":
            repo_trigger_summary[repo]["could_not_load"] += 1
        elif f["risk_level"] == "high":
            repo_trigger_summary[repo]["high_risk"] += 1
        elif f["risk_level"] == "medium":
            repo_trigger_summary[repo]["medium_risk"] += 1
        elif f["risk_level"] == "low":
            repo_trigger_summary[repo]["low_risk"] += 1
        else:
            repo_trigger_summary[repo]["no_risk"] += 1

    trigger_repo_rows = [
        {
            "repo": repo,
            "total_workflows": counts["total_workflows"],
            "high_risk": counts["high_risk"],
            "medium_risk": counts["medium_risk"],
            "low_risk": counts["low_risk"],
            "no_risk": counts["no_risk"],
            "could_not_load": counts["could_not_load"],
        }
        for repo, counts in sorted(
            repo_trigger_summary.items(),
            key=lambda x: x[1]["high_risk"],
            reverse=True,
        )
    ]

    trigger_summary_count = CsvCompiler.write_rows(
        "github_workflow_trigger_risk_per_repo.csv", trigger_repo_rows
    )
    print(
        f"Wrote github_workflow_trigger_risk_per_repo.csv "
        f"({trigger_summary_count} rows)"
    )

    high_count = sum(1 for f in all_trigger_findings if f["risk_level"] == "high")
    medium_count = sum(1 for f in all_trigger_findings if f["risk_level"] == "medium")
    low_count = sum(1 for f in all_trigger_findings if f["risk_level"] == "low")
    no_risk_count = sum(1 for f in all_trigger_findings if f["risk_level"] == "none")
    could_not_load_count = sum(
        1 for f in all_trigger_findings if f["posture"] == "could_not_load"
    )

    print(f"High risk: {high_count}")
    print(f"Medium risk: {medium_count}")
    print(f"Low risk: {low_count}")
    print(f"No risk: {no_risk_count}")
    print(f"Could not load: {could_not_load_count}")


# --- Main orchestrator ----------------------------------------------------


def _skip(stage_label: str, toggle_name: str) -> None:
    print(
        f"Skipping {stage_label}: {toggle_name} disabled in config",
        file=sys.stderr,
    )


def main() -> None:
    args = _parse_args()
    config: AuditConfig = load_audit_config(args.config_file)
    toggles = config.workflow_audit

    client = GitHubHttpClient(auth_method=args.auth)
    storage = SqliteRepoStorage(args.db)

    # Stage 1 - resolve_repo_lis. (mandatory)
    repo_list = resolve_repo_list(args, client, config)

    # Stage 2 - collect_baseline
    if toggles.collect_baseline_data:
        collect_baseline(args, client, repo_list, storage)
    else:
        _skip("Stage 2", "collect_baseline_data")

    # Stage 3 - collect_additional
    if toggles.collect_additional_data:
        collect_additional(args, client, repo_list, storage)
    else:
        _skip("Stage 3", "collect_additional_data")

    # Stage 4 - always runs; reads from SQLite and produces detail_rows
    # that later stages depend on. Cheap enough that a toggle adds no value.
    repo_rows, detail_rows = build_rows(repo_list, storage)

    # Stage 5 - write_posture_reports
    if toggles.gen_posture_reports:
        write_posture_reports(args, repo_rows, detail_rows)
    else:
        _skip("Stage 5", "gen_posture_reports")

    # Stage 6 - actions_analysis
    if toggles.actions_analysis:
        actions_analysis(client, detail_rows)
    else:
        _skip("Stage 6", "actions_analysis")

    # Stage 7 - permissions_analysis
    if toggles.permissions_analysis:
        permissions_analysis(client, detail_rows)
    else:
        _skip("Stage 7", "permissions_analysis")

    # Stage 8 - credentials_analysis
    if toggles.credentials_analysis:
        credentials_analysis(client, detail_rows)
    else:
        _skip("Stage 8", "credentials_analysis")

    # Stage 9 - trigger_risk_analysis
    if toggles.trigger_risk_analysis:
        trigger_risk_analysis(client, detail_rows)
    else:
        _skip("Stage 9", "trigger_risk_analysis")

    print("--- Complete ---")


if __name__ == "__main__":
    main()
