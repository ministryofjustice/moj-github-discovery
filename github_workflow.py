#!/usr/bin/env python3
import argparse
import csv
import datetime as dt
import os
import sys
import re
import time
import requests
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter


from utils import (
    gh_api,
)


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_repo_full_name(value: str) -> Tuple[str, str]:
    parts = value.strip().split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Expected owner/repo format, got: {value}")
    return parts[0], parts[1]


def load_targets_from_repo_file(path: str) -> List[str]:
    repos: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            repos.append(line)
    return repos


# ----------------------------------------------------------------------------------------------------------------------
# Github API calls
# ----------------------------------------------------------------------------------------------------------------------


def list_target_repos(args: argparse.Namespace) -> List[Dict[str, Any]]:
    if args.repos:
        repo_names = args.repos
    elif args.repo_file:
        repo_names = load_targets_from_repo_file(args.repo_file)
    else:
        try:
            repos = gh_api(
                f"/orgs/{args.org}/repos",
                paginate=True,
                params=["type=all", "sort=updated", "direction=desc"],
            )
        except requests.exceptions.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else "unknown"
            raise SystemExit(
                f"Unable to list repos for org '{args.org}' (HTTP {code}). "
                f"Use --repos owner/repo ... or --repo-file repos.txt with repos you can access."
            )

        if not isinstance(repos, list):
            raise SystemExit("Repo listing did not return a list.")
        repo_infos = repos
        return repo_infos[: args.limit]

    repo_infos: List[Dict[str, Any]] = []
    for full_name in repo_names[: args.limit]:
        owner, repo = parse_repo_full_name(full_name)
        try:
            repo_info = gh_api(f"/repos/{owner}/{repo}")
            if isinstance(repo_info, dict):
                repo_infos.append(repo_info)
        except Exception as exc:
            print(f"Skipping {full_name}: {exc}", file=sys.stderr)

    if not args.include_archived:
        repo_infos = [r for r in repo_infos if not r.get("archived")]
    return repo_infos


def parse_actions_from_workflow(org, repo_name, workflow_path):
    """Fetch a workflow file and extract all uses: references."""
    token = os.getenv("GITHUB_TOKEN", "")
    url = f"https://api.github.com/repos/{org}/{repo_name}/contents/{workflow_path}"
    resp = requests.get(
        url,
        headers={
            "Authorization": "token " + os.getenv("GITHUB_TOKEN", ""),
            "Accept": "application/vnd.github.raw+json",
        },
    )
    if resp.status_code != 200:
        print(f" Skipped {repo_name}/{workflow_path}: {resp.status_code}")
        return []

    content = resp.text
    actions = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("uses:") or line.startswith("- uses:"):
            match = re.search(r'uses:\s*["\']?([^"\'#\s]+)', line)
            if match:
                ref = match.group(1)
                # Skip local workflow references like ./.github/actions/...
                if ref.startswith("./"):
                    continue
                # Split into action name and version
                if "@" in ref:
                    action_name, version = ref.rsplit("@", 1)
                else:
                    action_name, version = ref, "none"
                actions.append(
                    {
                        "repo": repo_name,
                        "workflow_path": workflow_path,
                        "action_name": action_name,
                        "version": version,
                        "owner": action_name.split("/")[0]
                        if "/" in action_name
                        else action_name,
                    }
                )
    return actions


def fetch_workflow_files(owner: str, repo: str) -> List[Dict[str, Any]]:
    """
    Fetch the list of files in .github/workflows/ for a repo.
    Returns a list of file objects from the github contents api.
    Returns empty list if the directory doesn't exist or is inaccessible
    """
    try:
        data = gh_api(f"/repos/{owner}/{repo}/contents/.github/workflows")
        if isinstance(data, list):
            return [
                f
                for f in data
                if isinstance(f, dict) and f.get("name", "").endswith((".yml", ".yaml"))
            ]
        return []
    except Exception as exc:
        print(
            f" DEBUG workflow fetch failed for {owner}/{repo}: {exc}", file=sys.stderr
        )
        return []


def fetch_repo_actions_permissions(owner: str, repo: str) -> Dict[str, Any]:
    """
    Check if  GitHub Actions is enabled for the repo.
    Get /repos/{owner}/{repo}/actions/permissions
    Returns permissions dict or empty dict on failure.
    """
    try:
        data = gh_api(f"/repos/{owner}/{repo}/actions/permissions")
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}


def fetch_latest_workflow_run(owner: str, repo: str) -> Optional[str]:
    """
    Fetch the most recent workflow run date for the repo.
    Return ISO date string or None.
    """
    try:
        data = gh_api(
            f"/repos/{owner}/{repo}/actions/runs",
            params=["per_page=1"],
        )
        if isinstance(data, dict):
            runs = data.get("workflow_runs", [])
            if runs and isinstance(runs, list) and len(runs) > 0:
                return runs[0].get("created_at", "")
        return None
    except Exception:
        return None


# ----------------------------------------------------------------------------------------------------------------------
# Build rows
# ----------------------------------------------------------------------------------------------------------------------


def build_repo_row(
    repo_info: Dict[str, Any],
    workflow_files: List[Dict[str, Any]],
    actions_permissions: Dict[str, Any],
    latest_run_date: Optional[str],
) -> Dict[str, Any]:
    """Build a summary row for one repository."""
    owner = ""
    if isinstance(repo_info.get("owner"), dict):
        owner = repo_info["owner"].get("login", "")
    else:
        owner = repo_info.get("owner", "")

    repo_name = repo_info.get("name", "")
    full_name = repo_info.get("full_name", "") or f"{owner}/{repo_name}"
    archived = repo_info.get("archived", False)
    visibility = "private" if repo_info.get("private") else "public"
    default_branch = repo_info.get("default_branch", "") or "main"

    has_workflows = len(workflow_files) > 0
    workflow_count = len(workflow_files)
    workflow_names = ",".join(sorted(f.get("name", "") for f in workflow_files))

    actions_enabled = actions_permissions.get("enable", None)
    allowed_actions = actions_permissions.get("allowed_actions", "")

    # Determine posture category
    if archived and has_workflows:
        posture = "archived_with_workflows"
    elif archived and not has_workflows:
        posture = "archived_no_workflows"
    elif has_workflows:
        posture = "active_with_workflows"
    else:
        posture = "active_no_workflows"

    # Flag: candidate for disabling Actions
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
        "workflow_files": workflow_names,
        "latest_workflow_run": latest_run_date or "",
        "posture": posture,
        "disable_candidate": disable_candidate,
    }


def build_workflow_detail_rows(
    repo_full_name: str,
    owner: str,
    repo_name: str,
    workflow_files: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build one details row per workflow file found."""
    rows = []
    for wf in workflow_files:
        rows.append(
            {
                "repo": repo_full_name,
                "owner": owner,
                "repo_name": repo_name,
                "workflow_file": wf.get("name", ""),
                "path": wf.get("path", ""),
                "sha": wf.get("sha", ""),
                "download_url": wf.get("download_url", ""),
            }
        )
    return rows


# ----------------------------------------------------------------------------------------------------------------------
# CSV writer
# ----------------------------------------------------------------------------------------------------------------------


def csv_write(path: str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        with open(path, "w", encoding="utf-8") as f:
            pass
        print(f"No rows to write for {path}")
        return

    fieldnames: List[str] = []
    seen = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                fieldnames.append(key)
                seen.add(key)

    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {path} ({len(rows)} rows)")


# ----------------------------------------------------------------------------------------------------------------------
# Summary report
# ----------------------------------------------------------------------------------------------------------------------


def write_summary(
    path: str,
    repo_rows: List[Dict[str, Any]],
    detail_rows: List[Dict[str, Any]],
) -> None:
    """Write a human-readable summary report."""
    total = len(repo_rows)
    with_workflows = [r for r in repo_rows if r.get("has_workflows")]
    without_workflows = [r for r in repo_rows if not r.get("has_workflows")]
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
        f"  Repos using GITHUB Actions:        {len(with_workflows)} ({len(with_workflows) / max(total, 1) * 100:.1f}%)",
        f"  Repos NOT using GITHUB Actions:    {len(without_workflows)} ({len(without_workflows) / max(total, 1) * 100:.1f}%)",
        f"  Total workflow files found:        {len(detail_rows)}",
        "",
        "BREAKDOWN",
        "_" * 40,
        f" Active repos with workflows:      {len(active_with)}",
        f" Active repos without workflows:      {len(active_without)}",
        f" Archived repos with workflows:      {len(archived_with)}",
        f" Archived repos without workflows:      {len(archived_without)}",
        "",
        f"  Candidates for disabling Actions:    {len(disable_candidates)}",
        " (archived repos with workflows + active repos with Actions enabled but no workflow files)",
        "",
    ]

    # Top repos by workflow count
    top_repos = sorted(with_workflows, key=lambda x: -x.get("workflow_count", 0))[:15]
    if top_repos:
        lines.append("TOP REPOSITORIES BY WORKFLOW COUNT")
        lines.append("-" * 40)
        for r in top_repos:
            lines.append(f" {r['repo']:<55} workflows={r.get('workflow_count', 0):>3} ")
        lines.append("")

    # Archived repo with workflows (security concern)
    if archived_with:
        lines.append("ARCHIVED REPOS WITH WORKFLOWS (DISABLE CANDIDATES)")
        lines.append("-" * 40)
        lines.append(
            " (Actions should be disabled on archived repo to reduce attack surface)"
        )
        lines.append("")
        for r in archived_with:
            lines.append(f" {r['repo']:<55} workflows={r.get('workflow_count', 0):>3} ")
        lines.append("")

    # Archived repos with no workflows but Actions enabled
    actions_enabled_no_wf = [
        r for r in active_without if r.get("actions_enabled") is True
    ]
    if actions_enabled_no_wf:
        lines.append("ACTIVE REPOS: ACTIONS ENABLED BUT NO WORKFLOWS")
        lines.append("-" * 40)
        lines.append(" (Consider disabling Actions if not needed)")
        lines.append("")
        for r in actions_enabled_no_wf[:20]:
            lines.append(f"  {r['repo']}")
        if len(actions_enabled_no_wf) > 20:
            lines.append(f"  ... and {len(actions_enabled_no_wf) - 20} more")
        lines.append("")

    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    report = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"Wrote {path}")
    # Also print to stdout
    print()
    print(report)


# ----------------------------------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identify repositories using Github Actions across the MoJ estate"
    )
    parser.add_argument(
        "--org",
        default=os.getenv("GITHUB_ORG", "ministryofjustice"),
        help="GitHub organisation to scan (default: env GITHUB_ORG or ministryofjustice)",
    )
    parser.add_argument(
        "--repos",
        nargs="*",
        help="Specific repos to scan, e.g owner/repo owner/repo",
    )
    parser.add_argument(
        "--repo-file",
        help="Text file containing owner/repo entries, one per line",
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
    args = parser.parse_args()

    # 1. List target repos
    print("Listing target repositories...", file=sys.stderr)
    repo_infos = list_target_repos(args)
    if not repo_infos:
        raise SystemExit("No repositories found to scan.")
    print(f"FOUND {len(repo_infos)} repository to scan.", file=sys.stderr)

    # Scan each repo
    repo_rows: List[Dict[str, Any]] = []
    detail_rows: List[Dict[str, Any]] = []
    total = len(repo_infos)
    for idx, repo_info in enumerate(repo_infos, start=1):
        owner = ""
        if isinstance(repo_info.get("owner"), dict):
            owner = repo_info["owner"].get("login", "")
        repo_name = repo_info.get("name", "")
        full_name = repo_info.get("full_name", f"{owner}/{repo_name}")

        print(f"[{idx}/{total}] Scanning {full_name}...", file=sys.stderr)

        # Fetch workflow files
        workflow_files = fetch_workflow_files(owner, repo_name)

        # Fetch Actions permissions
        actions_permissions = fetch_repo_actions_permissions(owner, repo_name)

        # Fetch latest workflow run date
        latest_run = None
        if workflow_files:
            latest_run = fetch_latest_workflow_run(owner, repo_name)

        # Build rows
        repo_row = build_repo_row(
            repo_info, workflow_files, actions_permissions, latest_run
        )
        repo_rows.append(repo_row)

        # Build detail rows for each workflows file
        wf_details = build_workflow_detail_rows(
            full_name, owner, repo_name, workflow_files
        )
        detail_rows.extend(wf_details)

    # 3. Write outputs
    prefix = args.out_prefix
    csv_write(f"{prefix}_repo_summary.csv", repo_rows)
    csv_write(f"{prefix}_workflow_details.csv", detail_rows)
    write_summary(f"{prefix}_summary.txt", repo_rows, detail_rows)

    print(
        f"\nDone. Scanned {total} repos, "
        f"found {len([r for r in repo_rows if r.get('has_workflows')])} using GitHub Actions "
        f"with {len(detail_rows)} total workflow files.",
        file=sys.stderr,
    )

    # Analyse most common github actions used
    print("\n--- Analysing actions used across workflows ---")

    all_actions = []
    for i, row in enumerate(detail_rows):
        actions = parse_actions_from_workflow(args.org, row["repo_name"], row["path"])
        all_actions.extend(actions)
        if (i + 1) % 100 == 0:
            print(f" Parsed {i + 1} / {len(detail_rows)} workflow files")
        time.sleep(0.1)

    print(f"Total action references found: {len(all_actions)}")

    csv_write("github_actions_usage_detail.csv", all_actions)

    action_counts = Counter(a["action_name"] for a in all_actions)
    usage_summary = [
        {"action_name": name, "times_used": count}
        for name, count in action_counts.most_common()
    ]
    csv_write("github_actions_usage_summary.csv", usage_summary)

    owner_counts = Counter(a["owner"] for a in all_actions)
    owner_summary = [
        {"owner": owner, "actions_referenced": count}
        for owner, count in owner_counts.most_common()
    ]
    csv_write("github_actions_owner_summary.csv", owner_summary)

    print(f"Unique actions: {len(usage_summary)}")
    print(f"Unique owners: {len(owner_summary)}")
    print("--- #35 complete ---")


if __name__ == "__main__":
    main()
