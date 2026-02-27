import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from utils import gh_api, try_get, count_alerts, branch_protection, init_db, save_to_db

# This script lists (and optionally audits) every repository in an organization.
# By default it prints the most recent 10 repos to stdout.  Use `--audit-db`
# to write audit rows to a SQLite database, or `--excel` to export an Excel file.
# Filtering, sorting and specific repo selection are also supported.


def list_org_repos(org: str, limit: int = 400) -> List[Dict[str, Any]]:
    """Fetch repositories from a GitHub organization."""
    repos: List[Dict[str, Any]] = []
    page = 1
    per_page = 100

    while len(repos) < limit:
        batch = gh_api(
            f"/orgs/{org}/repos?per_page={per_page}&page={page}&sort=pushed&direction=desc"
        )
        if not batch:
            break
        if isinstance(batch, list):
            repos.extend(batch)
        else:
            break
        page += 1

    return repos[:limit]


def main():
    if len(sys.argv) < 2:
        print("Usage: python list_repos.py <org> [--excel path] [--limit N] [--sort [-]column] [--repo-file file] [--audit-db path]")
        sys.exit(2)

    org = sys.argv[1]
    # defaults – paths alongside script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_db_path = os.path.join(script_dir, "repo_audit.db")
    excel_path: Optional[str] = None
    limit: Optional[int] = None
    repo_list: Optional[List[str]] = None
    sort_key: Optional[str] = None
    sort_asc: bool = False  # default to descending last-updated
    audit_db_path: Optional[str] = None  # None means don't write to DB

    # parse additional args
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--excel" and i + 1 < len(sys.argv):
            excel_path = sys.argv[i + 1]
            i += 2
        elif arg == "--limit" and i + 1 < len(sys.argv):
            try:
                limit = int(sys.argv[i + 1])
            except ValueError:
                print("--limit requires an integer")
                sys.exit(2)
            i += 2
        elif arg == "--sort" and i + 1 < len(sys.argv):
            # sort field, prefix with - for descending
            raw = sys.argv[i + 1]
            if raw.startswith("-"):
                sort_key = raw[1:]
                sort_asc = False
            elif raw.startswith("+" ):
                sort_key = raw[1:]
                sort_asc = True
            else:
                sort_key = raw
                sort_asc = True
            i += 2
        elif arg == "--repo-file" and i + 1 < len(sys.argv):
            path = sys.argv[i + 1]
            try:
                with open(path) as f:
                    repo_list = [line.strip() for line in f if "/" in line]
            except Exception as e:
                print(f"Failed to read repo file: {e}")
                sys.exit(2)
            i += 2
        elif arg == "--audit-db":
            # --audit-db with optional path; if no path, use default repo_audit.db
            if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("--"):
                audit_db_path = sys.argv[i + 1]
                i += 2
            else:
                # no path provided; use default
                audit_db_path = default_db_path
                i += 1
        else:
            print(f"Unknown argument: {arg}")
            sys.exit(2)

    # if audit database given, ensure table is created
    if audit_db_path:
        init_db(audit_db_path, table_name="repo_rows")

    if repo_list is not None:
        repos = []
        # fetch metadata for each repo listed in file
        for full in repo_list:
            owner, name = full.split("/", 1)
            try:
                info = gh_api(f"/repos/{owner}/{name}")
                repos.append(info)
            except Exception:
                # skip if lookup fails
                pass
    else:
        # determine how many repos to fetch
        # default behavior when no options: print 10 to stdout
        # if exporting (--excel) or writing DB (--audit-db) and the user
        # hasn't supplied --limit, we want the full list (default 400)
        if limit is None:
            if excel_path or audit_db_path:
                effective_limit = 400
            else:
                effective_limit = 10
        else:
            effective_limit = limit
        repos = list_org_repos(org, limit=effective_limit)

    rows: List[Dict[str, Any]] = []
    for r in repos:
        name = r["name"]
        owner = r["owner"]["login"]
        default_branch = r.get("default_branch")
        row = {
            "org": org,
            "repo": name,
            "full_name": r.get("full_name"),
            "private": r.get("private"),
            "archived": r.get("archived"),
            "fork": r.get("fork"),
            "pushed_at": r.get("pushed_at"),
            "default_branch": default_branch,
            "language": r.get("language"),
            "open_issues": r.get("open_issues_count"),
            "stargazers": r.get("stargazers_count"),
        }

        row.update(count_alerts(owner, name))
        if default_branch:
            row.update(branch_protection(owner, name, default_branch))

        # Simple heuristic risk flags (tune these)
        flags = []
        if row["archived"]:
            flags.append("archived")
        if row["fork"]:
            flags.append("fork")
        if row["private"] is False and not row.get("default_branch_protected"):
            flags.append("public_unprotected_default_branch")
        if (row.get("dependabot_alerts") or 0) > 0:
            flags.append("dependabot_alerts_present")
        if (row.get("secret_scanning_alerts") or 0) > 0:
            flags.append("secret_alerts_present")
        if (row.get("code_scanning_alerts") or 0) > 0:
            flags.append("code_scanning_alerts_present")

        row["flags"] = ", ".join(flags)
        rows.append(row)

    df = pd.DataFrame(rows)
    # apply sorting if requested; default to pushed_at descending
    if sort_key is None:
        sort_key = "pushed_at"
        sort_asc = False
    if sort_key in df.columns:
        df = df.sort_values(by=sort_key, ascending=sort_asc, na_position='last')
    else:
        if sort_key is not None:
            print(f"Warning: sort key '{sort_key}' not a column", file=sys.stderr)

    # write rows to audit database if requested
    if audit_db_path:
        for _, row in df.iterrows():
            full = row.get("full_name")
            if full:
                save_to_db(audit_db_path, full, row.to_dict(), table_name="repo_rows")

    # Report how many repositories we ended up processing
    print(f"Processed {len(rows)} repositories", file=sys.stderr)

    # Summary dataframe (optional excel export)
    summary = pd.DataFrame(
        {
            "metric": [
                "repos_total",
                "repos_public",
                "repos_private",
                "repos_archived",
                "repos_with_dependabot_alerts",
                "repos_with_secret_alerts",
                "repos_with_code_scanning_alerts",
                "repos_unprotected_default_branch",
            ],
            "value": [
                len(df),
                int((df["private"] == False).sum()),
                int((df["private"] == True).sum()),
                int(df["archived"].sum()),
                int((df["dependabot_alerts"].fillna(0) > 0).sum()),
                int((df["secret_scanning_alerts"].fillna(0) > 0).sum()),
                int((df["code_scanning_alerts"].fillna(0) > 0).sum()),
                int((df["default_branch_protected"] == False).sum()),
            ],
        }
    )

    if excel_path:
        with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Repos")
            summary.to_excel(writer, index=False, sheet_name="Summary")
        print(f"Wrote {excel_path}", file=sys.stderr)

    # when no excel and no repo-file and no audit-db, output recent results
    if not excel_path and repo_list is None and audit_db_path is None:
        output_data = df.to_dict(orient='records')
        print(json.dumps(output_data, indent=2))


if __name__ == "__main__":
    main()
