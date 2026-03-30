#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import sys
from typing import Any, Callable

from core.compiler import CsvCompiler
from core.github_api import fetch_repo_alerts, list_org_repos
from core.github_client import GitHubHttpClient

DEFAULT_ORG = "ministryofjustice"
DEFAULT_MAX_ALERTS = 400
DEFAULT_OUTPUT = "github_alerts_limited.csv"

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export repository-level alert metrics via core GitHub modules."
    )
    parser.add_argument("--org", default=DEFAULT_ORG, help="GitHub organisation login.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="CSV output path.")
    parser.add_argument(
        "--max-alerts",
        type=int,
        default=DEFAULT_MAX_ALERTS,
        help="Maximum number of alert rows to export.",
    )
    parser.add_argument("--repo-limit", type=int, help="Limit scanned repositories.")
    return parser.parse_args()


def parse_iso(value: str | None) -> dt.datetime | None:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def main() -> None:
    args = parse_args()
    if args.max_alerts <= 0:
        print("--max-alerts must be > 0", file=sys.stderr)
        sys.exit(2)
    if args.repo_limit is not None and args.repo_limit <= 0:
        print("--repo-limit must be > 0", file=sys.stderr)
        sys.exit(2)

    client = GitHubHttpClient()
    repos = list_org_repos(args.org, client)
    if args.repo_limit:
        repos = repos[: args.repo_limit]

    rows: list[dict[str, Any]] = []
    repos_with_alerts: set[str] = set()

    for repo_full in repos:
        if len(rows) >= args.max_alerts:
            break

        owner, repo = repo_full.split("/", 1)
        print(f"Scanning {repo_full}...", file=sys.stderr)

        for kind, severity_of in ALERT_SPECS:
            if len(rows) >= args.max_alerts:
                break
            try:
                alerts = fetch_repo_alerts(client, owner, repo, kind)
            except Exception as exc:
                print(f"  [warn] {kind} failed: {exc}", file=sys.stderr)
                continue

            for alert in alerts:
                if len(rows) >= args.max_alerts:
                    break
                if not isinstance(alert, dict):
                    continue

                created = parse_iso(alert.get("created_at"))
                remediated = parse_iso(alert.get("fixed_at")) or parse_iso(
                    alert.get("dismissed_at")
                )
                ttr_days = (
                    (remediated - created).days if created and remediated else None
                )

                rows.append(
                    {
                        "id": alert.get("number") or alert.get("id"),
                        "type": kind,
                        "repo": repo_full,
                        "created_at": created.isoformat() if created else "",
                        "remediated_at": remediated.isoformat() if remediated else "",
                        "state": alert.get("state"),
                        "severity": severity_of(alert),
                        "ttr_days": ttr_days,
                    }
                )
                repos_with_alerts.add(repo_full)

    if rows:
        CsvCompiler.write_rows(args.output, rows)

    print(f"Done! Wrote {len(rows)} alerts to {args.output}")
    print(f"Repos with alerts: {len(repos_with_alerts)}")


if __name__ == "__main__":
    main()
