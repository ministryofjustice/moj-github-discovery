#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import pandas as pd
import sys
from typing import Any, Callable

from core.config import AuditConfig
from core.compiler import CsvCompiler
from core.github_api import fetch_repo_alerts, list_org_repos
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
    client: GitHubHttpClient, org: str, repos: list[str]
) -> dict[str, str]:
    """Return repo archive status keyed by full repo name.

    Archive status is used to annotate alerts, helping analysts understand whether
    issues were found in active or archived repositories. This function uses a
    two-stage lookup: first attempt bulk fetch via org/repos endpoint, then fall back
    to individual repo lookups for any repos not found in the bulk response.
    """
    status_lookup: dict[str, str] = {}
    repo_set = set(repos)

    if repo_set:
        # Stage 1: Bulk fetch all org repos and match against the repos we need.
        # This is more efficient than individual requests when available.
        try:
            repo_items = client.get_paginated(f"/orgs/{org}/repos?type=all&sort=pushed")
        except Exception:
            # If the bulk fetch fails, gracefully continue with individual lookups below.
            repo_items = []

        # Extract archive status from the bulk response for matching repos.
        for repo_item in repo_items:
            if not isinstance(repo_item, dict):
                continue
            full_name = repo_item.get("full_name")
            if not isinstance(full_name, str) or full_name not in repo_set:
                continue
            # Store as "archived" or "non_archived" based on the API response.
            status_lookup[full_name] = (
                "archived" if repo_item.get("archived", False) else "non_archived"
            )

    # Stage 2: For any repos not yet resolved, try individual API calls.
    # This handles edge cases where a repo may not be in the bulk response
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
    else:
        print(f"Fetching repositories for organization: {github_organization}")
        repos = list_org_repos(github_organization, client)
        if repo_limit:
            repos = repos[:repo_limit]

    # Pre-build archive status lookup so we can annotate each alert with repo status.
    # This helps distinguish between alerts in active vs. archived repositories.
    archive_status_lookup = build_archive_status_lookup(
        client, github_organization, repos
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
