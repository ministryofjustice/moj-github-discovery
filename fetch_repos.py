#!/usr/bin/env python3
"""Fetch and store full repository metadata for an organization.

This utility is intentionally minimal compared to the other helpers in this
workspace; the goal is simply to make a complete grab of every field returned
by GitHub for each repo in an org and then optionally persist the results.

Usage:
    python fetch_repos.py <org> [--limit N] [--db path]

Arguments:
    org          - the GitHub organization whose repositories should be
                   queried (e.g. ``github``).

Options:
    --limit N    - stop after N repositories (default 5000, essentially
                   unlimited for most orgs).
    --db path    - path to a SQLite database.  When supplied the script will
                   create a table named ``full_repos`` and write one row per
                   repository with the raw JSON returned by GitHub.  If the
                   option is omitted the list of repo objects is dumped as a
                   JSON array to stdout.

The database schema mirrors the helper used elsewhere in this workspace;
``full_name`` is the primary key and ``repo_json`` holds the payload.  This
makes the resulting file easy to query later using the ``sqlite3`` CLI or
other tools.
"""

import atexit
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

from utils import gh_api
import sqlite3

# track start time for an elapsed-report convenience
__start_time: Optional[float] = None

def _report_elapsed() -> None:
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)

atexit.register(_report_elapsed)


def list_org_repos(org: str, limit: int = 5000) -> List[Dict[str, Any]]:
    """Retrieve repositories for an organization and respect ``limit``.

    The implementation mirrors the pagination logic used elsewhere in the
    project so that a small limit results in only the necessary API calls.
    """
    collected: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    while len(collected) < limit:
        batch = gh_api(
            f"/orgs/{org}/repos?per_page={per_page}&page={page}&sort=pushed&direction=desc"
        )
        if not batch or not isinstance(batch, list):
            break
        collected.extend(batch)
        if len(batch) < per_page:
            break
        page += 1
    return collected[:limit]


def main() -> None:
    global __start_time
    __start_time = time.monotonic()

    if len(sys.argv) < 2:
        print("Usage: python fetch_repos.py <org> [--limit N] [--db path]")
        sys.exit(2)

    org = sys.argv[1]
    limit: Optional[int] = None
    db_path: Optional[str] = None

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--limit" and i + 1 < len(sys.argv):
            try:
                limit = int(sys.argv[i + 1])
            except ValueError:
                print("--limit requires an integer")
                sys.exit(2)
            i += 2
        elif arg == "--db" and i + 1 < len(sys.argv):
            db_path = sys.argv[i + 1]
            i += 2
        else:
            print(f"Unknown argument: {arg}")
            sys.exit(2)

    if limit is None:
        effective_limit = 5000
    else:
        effective_limit = limit

    repos = list_org_repos(org, limit=effective_limit)

    # when a database is requested, create a simple table and write the
    # raw JSON for each repository.  we avoid the generic helpers here so the
    # column is named appropriately (`repo_json`) instead of the generic
    # `audit_json` used elsewhere.
    if db_path:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS full_repos (
                full_name TEXT PRIMARY KEY,
                repo_json TEXT
            )
            """
        )
        for r in repos:
            full = r.get("full_name")
            if full:
                cursor.execute(
                    "INSERT OR REPLACE INTO full_repos (full_name, repo_json) VALUES (?, ?)",
                    (full, json.dumps(r)),
                )
        conn.commit()
        conn.close()
        print(f"Wrote {len(repos)} repos to {db_path}", file=sys.stderr)
    else:
        # output as a JSON list to stdout
        print(json.dumps(repos, indent=2))
        print(f"Fetched {len(repos)} repos", file=sys.stderr)


if __name__ == "__main__":
    main()
