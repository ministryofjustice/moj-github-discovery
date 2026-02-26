import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from utils import run_gh, gh_api, try_get, count_alerts, branch_protection, init_db, save_to_db

# This script audits every repository in an organization.  Results are saved
# to a local SQLite database by default (`<org>_security_audit.db` in the same
# directory as the script).  Excel output is optional via `--excel`.


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
        print("Usage: python list_repos.py <org> [--db path] [--excel path] [--limit N] [--repos a/b,c/d] [--repo-file file]")
        sys.exit(2)

    org = sys.argv[1]
    # defaults – database located alongside script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(script_dir, "repo_audit.db")
    excel_path: Optional[str] = None
    limit: Optional[int] = None
    repo_list: Optional[List[str]] = None

    # parse additional args
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--db" and i + 1 < len(sys.argv):
            db_path = sys.argv[i + 1]
            i += 2
        elif arg == "--excel" and i + 1 < len(sys.argv):
            excel_path = sys.argv[i + 1]
            i += 2
        elif arg == "--limit" and i + 1 < len(sys.argv):
            try:
                limit = int(sys.argv[i + 1])
            except ValueError:
                print("--limit requires an integer")
                sys.exit(2)
            i += 2
        elif arg == "--repos" and i + 1 < len(sys.argv):
            repo_list = sys.argv[i + 1].split(",")
            repo_list = [r.strip() for r in repo_list if "/" in r]
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
        else:
            print(f"Unknown argument: {arg}")
            sys.exit(2)

    # ensure database exists before writing rows
    init_db(db_path, table_name="repo_rows")

    if repo_list is not None:
        repos = []
        # fetch metadata for each specified repo
        for full in repo_list:
            owner, name = full.split("/", 1)
            try:
                info = gh_api(f"/repos/{owner}/{name}")
                repos.append(info)
            except Exception:
                # skip if lookup fails
                pass
    else:
        repos = list_org_repos(org, limit=limit if limit is not None else 400)

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

    # write each row into the database
    for _, row in df.iterrows():
        full = row.get("full_name")
        if full:
            save_to_db(db_path, full, row.to_dict(), table_name="repo_rows")

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
        print(f"Wrote {excel_path}")
    else:
        print(f"Database updated: {db_path}")


if __name__ == "__main__":
    main()
