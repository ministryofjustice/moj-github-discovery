#!/usr/bin/env python3
"""GitHub Actions workflow posture discovery.

Refactored to use core modules:
  - Repo discovery / loading     core.github_api.list_org_repos, core.repo_list
  - HTTP transport               core.github_client.GitHubHttpClient
    - Workflow + repo data         RepoCollector with typed repo-scoped endpoints

Not yet in core (local implementations retained):
  - Workflow YAML uses: parsing
"""

import argparse
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List

from core.collector import RepoCollector
from core.compiler import CsvCompiler
from core.github_api import (
    LatestWorkflowRunEndpoint,
    RepoDetailsEndpoint,
    RepoActionsPermissionsEndpoint,
    WorkflowsEndpoint,
    check_workflow_permissions,
    check_credential_posture,
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
) -> Dict[str, Any]:
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
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume collection by skipping endpoint data already cached in the database",
    )
    args = parser.parse_args()

    client = GitHubHttpClient()

    # ================================================================
    # Stage 1: Resolve the repository list to scan
    # ================================================================

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

    # ================================================================
    # Stage 2: Collect baseline repo metadata and workflow inventory
    # ================================================================

    # 2. Collect repo details + workflow inventory via core
    storage = SqliteRepoStorage(args.db)
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

    # ================================================================
    # Stage 3: Collect remaining workflow posture data
    # ================================================================

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

    # ================================================================
    # Stage 4: Read collected data and build output row sets
    # ================================================================

    # 4. Read collected data and build output rows
    repo_rows: List[Dict[str, Any]] = []
    detail_rows: List[Dict[str, Any]] = []
    total = len(repo_list)
    for idx, full_name in enumerate(repo_list, start=1):
        print(f"[{idx}/{total}] Augmenting {full_name}...", file=sys.stderr)

        data = storage.read(full_name) or RepoData()
        repo_rows.append(build_repo_row(full_name, data))
        detail_rows.extend(build_workflow_detail_rows(full_name, data))

    # ================================================================
    # Stage 5: Write repo-level posture reports
    # ================================================================

    # 5. Write posture outputs
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

    # ================================================================
    # Stage 6: Parse workflow files to inventory action usage
    # ================================================================

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

    # 6b. SHA pinning compliance
    print("\n--- Analysing SHA pinning compliance ---")

    unpinned_actions = [
        a for a in all_actions if not a["is_pinned"] and a["version"] != "none"
    ]
    pinned_actions = [a for a in all_actions if a["is_pinned"]]

    print(f"Total action references: {len(all_actions)}")
    print(f"Pinned to SHA: {len(pinned_actions)}")
    print(f"Unpinned (mutable tag): {len(unpinned_actions)}")

    unpinned_count = CsvCompiler.write_rows(
        "github_actions_unpinned_detail.csv", unpinned_actions
    )
    print(f"Wrote github_actions_unpinned_detail.csv ({unpinned_count} rows)")

    repo_pinning: Dict[str, Dict[str, int]] = {}
    for a in all_actions:
        if a["version"] == "none":
            continue
        repo = a["repo"]
        if repo not in repo_pinning:
            repo_pinning[repo] = {"total": 0, "pinned": 0, "unpinned": 0}
        repo_pinning[repo]["total"] += 1
        if a["is_pinned"]:
            repo_pinning[repo]["pinned"] += 1
        else:
            repo_pinning[repo]["unpinned"] += 1

    pinning_summary = [
        {
            "repo": repo,
            "total_refs": counts["total"],
            "pinned": counts["pinned"],
            "unpinned": counts["unpinned"],
            "compliance_pct": round(
                counts["pinned"] / max(counts["total"], 1) * 100, 1
            ),
        }
        for repo, counts in sorted(
            repo_pinning.items(), key=lambda x: x[1]["unpinned"], reverse=True
        )
    ]

    pinning_count = CsvCompiler.write_rows(
        "github_actions_pinning_per_repo.csv", pinning_summary
    )
    print(f"Wrote github_actions_pinning_per_repo.csv ({pinning_count} rows)")
    print(
        f"Repos with unpinned actions: "
        f"{sum(1 for s in pinning_summary if s['unpinned'] > 0)}"
    )
    print(
        f"Repos fully pinned: {sum(1 for s in pinning_summary if s['unpinned'] == 0)}"
    )

    # ================================================================
    # Stage 7: Parse workflow files for permissions posture
    # ================================================================

    # 7. Workflow permissions check
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

    # ================================================================
    # Stage 8: Assess OIDC vs long-lived credentials
    # ================================================================

    # 8. OIDC vs long-lived credentials assessment
    print("\n--- Assessing OIDC vs long-lived credentials ---")

    all_credential_findings: List[Dict[str, Any]] = []
    for i, row in enumerate(detail_rows):
        finding = check_credential_posture(
            client, row["owner"], row["repo_name"], row["path"]
        )
        all_credential_findings.append(finding.model_dump())

        if (i + 1) % 100 == 0:
            print(f" Checked {i + 1} / {len(detail_rows)} workflow files")
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
        f"Wrote github_workflow_credential_posture_per_repo.csv"
        f" ({cred_repo_count} rows)"
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

    print("--- Complete ---")


if __name__ == "__main__":
    main()
