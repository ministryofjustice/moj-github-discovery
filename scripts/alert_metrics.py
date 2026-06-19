#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import pandas as pd
import sys
from typing import Any, Callable

from core.config import AuditConfig
from core.compiler import CsvCompiler
from core.github_api import (
    fetch_repo_alerts,
    list_org_repos_with_archive_status,
)
from core.github_client import GitHubHttpClient
from core.output_paths import OutputPathResolver

# Alerts Config
AlertSpec = tuple[str, Callable[[dict[str, Any]], str]]
ALERT_SPECS: list[AlertSpec] = [
    (
        "code_scanning",
        lambda a: (a.get("rule") or {}).get("security_severity_level", "not_found"),
    ),
    (
        "dependabot",
        lambda a: (a.get("security_advisory") or {}).get("severity", "not_found"),
    ),
    ("secret_scanning", lambda _: "critical"),
]


def parse_iso(value: str | None) -> dt.datetime | None:
    """Utility function: convert ISO 8601 datetime strings into readable datetime object"""
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def build_archive_status_lookup(
    client: GitHubHttpClient,
    org: str,
    repos: list[str],
    pre_fetched_status: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return repo archive status keyed by full repo name.

    Archive status is used to annotate alerts, helping analysts understand whether
    issues were found in active or archived repositories. This function accepts
    optional pre-fetched status data to avoid duplicate API calls. If not provided,
    it will perform individual repo lookups for any repos not in the pre-fetched data.

    Args:
        client: GitHub HTTP client
        org: Organization name
        repos: List of full repo names (owner/repo format)
        pre_fetched_status: Optional dict mapping repo full names to archive status.
                           If provided, this is used as the primary source.
    """
    status_lookup: dict[str, str] = (
        pre_fetched_status.copy() if pre_fetched_status else {}
    )

    # Stage 1: If pre-fetched data was not provided, populate from the org-wide
    # paginated listing. This preserves standalone helper behavior for tests and
    # non-optimized call sites.
    repo_set = set(repos)
    if pre_fetched_status is None and repo_set:
        try:
            repo_items = client.get_paginated(f"/orgs/{org}/repos?type=all&sort=pushed")
        except Exception:
            repo_items = []

        for repo_item in repo_items:
            if not isinstance(repo_item, dict):
                continue
            full_name = repo_item.get("full_name")
            if not isinstance(full_name, str) or full_name not in repo_set:
                continue
            status_lookup[full_name] = (
                "archived" if repo_item.get("archived", False) else "non_archived"
            )

    # Stage 2: For any repos not yet resolved, try individual API calls.
    # This handles edge cases where a repo may not be in the pre-fetched data
    # (e.g., private repos, recently created repos, or API permission issues).
    for repo_full in repos:
        if repo_full in status_lookup:
            continue
        owner, repo = repo_full.split("/", 1)
        try:
            repo_item = client.get(f"/repos/{owner}/{repo}")
        except Exception:
            # If the individual request fails, mark status as unknown.
            # Alerts from unknown-status repos will still be tracked but flagged.
            status_lookup[repo_full] = "unknown"
            continue
        if isinstance(repo_item, dict):
            status_lookup[repo_full] = (
                "archived" if repo_item.get("archived", False) else "non_archived"
            )
        else:
            # Mark as unknown if the response is not a valid dictionary.
            status_lookup[repo_full] = "unknown"

    return status_lookup


def summarise_results(output_file: str) -> None:
    """Utility function: print summary of results to console after processing"""
    # Load the CSV file containing GitHub alert data
    df = pd.read_csv(output_file)

    # Normalise column names:
    # - strip whitespace
    # - convert to lowercase
    # This prevents KeyErrors if the CSV has inconsistent formatting
    df.columns = df.columns.str.strip().str.lower()

    # Define which alert states count as "closed"
    closed_states = ["resolved", "fixed"]

    # --- High‑level counts ---
    print("Total alerts:", len(df))
    print("Open alerts:", len(df[df["state"] == "open"]))
    print("Closed alerts:", len(df[df["state"].isin(closed_states)]))

    # --- Severity breakdown ---
    print("\nAlerts by severity:")
    print(df["severity"].value_counts())

    # --- Type breakdown ---
    print("\nAlerts by type:")
    print(df["type"].value_counts())

    if "archive_status" in df.columns:
        print("\nAlerts by repo archive status:")
        print(df["archive_status"].value_counts())

    # --- Time‑to‑Remediate (TTR) statistics ---
    # Assumes the CSV includes a numeric column `ttr_days`
    print("\nAverage TTR:", df["ttr_days"].mean())
    print("Max TTR:", df["ttr_days"].max())
    print("Min TTR:", df["ttr_days"].min())

    # --- Open alerts by severity ---
    print("\nOpen alerts by severity:")
    print(df[df["state"] == "open"]["severity"].value_counts())

    # --- Combined grouping: severity + type ---
    # This helps identify patterns, e.g. which severity/type combinations are most common
    print("\nGrouped by severity + type:")
    print(df.groupby(["severity", "type"]).size())


def run(
    config: AuditConfig,
    auth: str | None,
    base_output_dir: str,
    base_internal_dir: str,
    **kwargs,
) -> None:
    resolver = OutputPathResolver(config, base_output_dir, base_internal_dir)
    alert_metrics_config = config.alert_metrics

    github_organization = config.github_organization
    output_filename = alert_metrics_config.output_filename
    max_alerts = alert_metrics_config.max_alerts
    repo_limit = alert_metrics_config.repo_limit

    # Debug

    print(f"Using GitHub organization: {github_organization}", file=sys.stderr)
    print(f"Output file name: {output_filename}", file=sys.stderr)
    print(f"Max alerts: {max_alerts}", file=sys.stderr)
    print(f"Repo limit: {repo_limit}", file=sys.stderr)

    # Configure GitHub connection and gather Repo Information
    client = GitHubHttpClient(auth_method=auth)
    if kwargs.get("repo"):
        print(f"Scanning single repository: {kwargs['repo']}")
        repos = [kwargs["repo"]]
        # For single repo, build archive status lookup (may use org listing + per-repo fallback)
        archive_status_lookup = build_archive_status_lookup(
            client, github_organization, repos, pre_fetched_status=None
        )
    else:
        print(f"Fetching repositories for organization: {github_organization}")
        # Single paginated call returns both the repo list and archive status,
        # replacing the previous pattern of calling list_org_repos + a second
        # pagination for archive status.
        repos, pre_fetched_status = list_org_repos_with_archive_status(
            github_organization, client
        )
        if repo_limit:
            repos = repos[:repo_limit]

        # Fall back to individual lookups only for repos not covered by the bulk fetch
        # (e.g. edge cases like recently created or permission-restricted repos).
        archive_status_lookup = build_archive_status_lookup(
            client, github_organization, repos, pre_fetched_status=pre_fetched_status
        )

    rows: list[dict[str, Any]] = []
    repos_with_alerts: set[str] = set()

    for repo_full in repos:
        if max_alerts is not None and len(rows) >= max_alerts:
            break

        # Split Repo Owner and Name from list i.e. owner/repo-name
        owner, repo = repo_full.split("/", 1)
        print(f"Scanning {repo_full}...", file=sys.stderr)

        # Assess repository information for each alert category and severity criteria to be logged
        for kind, severity_of in ALERT_SPECS:
            if max_alerts is not None and len(rows) >= max_alerts:
                break
            try:
                # Gather repo alerts information for assessment
                alerts = fetch_repo_alerts(client, owner, repo, kind)
            except Exception as exc:
                print(f"  [warn] {kind} failed: {exc}", file=sys.stderr)
                continue

            # Review alerts found for given repo and extract creation/remediation timestamps and lifecycle
            for alert in alerts:
                if max_alerts is not None and len(rows) >= max_alerts:
                    break
                if not isinstance(alert, dict):
                    continue

                # Extract alert lifecycle
                created = parse_iso(alert.get("created_at"))
                remediated = parse_iso(alert.get("fixed_at")) or parse_iso(
                    alert.get("dismissed_at")
                )
                ttr_days = (
                    (remediated - created).days if created and remediated else None
                )

                # Write alert data as row ready for compilation
                rows.append(
                    {
                        "id": alert.get("number") or alert.get("id"),
                        "type": kind,
                        "repo": repo_full,
                        # Include archive status from pre-built lookup; defaults to "unknown" if not found.
                        # Archived repos may have different SLA or remediation expectations.
                        "archive_status": archive_status_lookup.get(
                            repo_full, "unknown"
                        ),
                        "created_at": created.isoformat() if created else "",
                        "remediated_at": remediated.isoformat() if remediated else "",
                        "state": alert.get("state"),
                        "severity": severity_of(alert),
                        "ttr_days": ttr_days,
                    }
                )
                repos_with_alerts.add(repo_full)

    # Write rows to final output file
    output_file_path = resolver.script_output_file(
        alert_metrics_config.output_subdir, output_filename
    )
    if rows:
        CsvCompiler.write_rows(str(output_file_path), rows)

    # Summary logging
    print(f"Done! Wrote {len(rows)} alerts to {output_file_path}")
    print(f"Repos with alerts: {len(repos_with_alerts)}")

    if rows:
        summarise_results(output_file_path)
