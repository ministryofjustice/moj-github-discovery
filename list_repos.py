import atexit
import json
import os
import sys
import time
import sqlite3
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd

from utils import gh_api, count_alerts, branch_protection, init_db, save_to_db, fork_and_template_info, check_codeowners_exists

# track start time for automatic reporting
__start_time: Optional[float] = None


def _report_elapsed() -> None:
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)


atexit.register(_report_elapsed)

# This script lists (and optionally audits) every repository in an organization.
# By default it prints the most recent 10 repos to stdout.  Use `--audit-db`
# to write audit rows to a SQLite database, or `--excel` to export an Excel file.
# Filtering, sorting and specific repo selection are also supported.


def list_org_repos(org: str, limit: int = 400) -> List[Dict[str, Any]]:
    """Retrieve repositories for an organization, sorted by last push.

    This helper simply delegates to ``gh_api`` with ``paginate=True`` and
    then slices the resulting list to ``limit`` items.  Using the builtin
    paginator keeps the implementation concise and efficient.
    """
    # The ``paginate=True`` helper would fetch the entire list, which is
    # wasteful when ``limit`` is small.  Instead we manually walk pages and
    # stop once we've collected ``limit`` items.
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
        # if fewer than a full page returned, we've reached the end
        if len(batch) < per_page:
            break
        page += 1
    return collected[:limit]


def main():
    global __start_time
    __start_time = time.monotonic()
    if len(sys.argv) < 2:
        print(
            "Usage: python list_repos.py <org> [--excel path] [--limit N] [--sort [-]column] [--repo-file file] [--audit-db path]"
        )
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
    no_alerts = False
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
            elif raw.startswith("+"):
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
        elif arg == "--no-alerts":
            no_alerts = True
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

    # Enrich fork/template data for repos from org listing
    # The org endpoint doesn't include parent/template_repository fields,
    # so fetch full details for forked or template repos
    def enrich_fork_template_info(r: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch full repo details if fork or template to get parent/template info."""
        try:
            owner = r.get("owner", {}).get("login")
            name = r.get("name")
            if not owner or not name:
                return r

            # Only fetch if fork or is_template (otherwise skip to save API calls)
            if not (r.get("fork") or r.get("is_template")):
                return r

            full_info = gh_api(f"/repos/{owner}/{name}")
            # Merge parent and template_repository if present
            if full_info.get("parent"):
                r["parent"] = full_info.get("parent")
            if full_info.get("template_repository"):
                r["template_repository"] = full_info.get("template_repository")
            return r
        except Exception:
            # If enrichment fails, return original repo data
            return r

    # Enrich fork/template data in parallel for org-listed repos (skip if using --repo-file)
    if repo_list is None and repos:
        enriched_repos = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(enrich_fork_template_info, r) for r in repos]
            # Maintain order by iterating through futures in order
            for fut in futures:
                enriched_repos.append(fut.result())
        repos = enriched_repos

    # helper for a single repo; extracted so it can run in a pool
    def process_single(r: Dict[str, Any]) -> Dict[str, Any]:
        start_repo = time.monotonic()
        name = r["name"]
        owner = r["owner"]["login"]
        default_branch = r.get("default_branch")
        fork_template = fork_and_template_info(r)
        row: Dict[str, Any] = {
            "org": org,
            "repo": name,
            "full_name": r.get("full_name"),
            "private": r.get("private"),
            "archived": r.get("archived"),
            "fork": r.get("fork"),
            "fork_source": fork_template.get("fork_source"),
            "is_generated_from_template": fork_template.get(
                "is_generated_from_template"
            ),
            "template_source": fork_template.get("template_source"),
            "pushed_at": r.get("pushed_at"),
            "default_branch": default_branch,
            "language": r.get("language"),
            "open_issues": r.get("open_issues_count"),
            "stargazers": r.get("stargazers_count"),
        }
        if not no_alerts:
            row.update(count_alerts(owner, name))
        else:
            # mark as skipped rather than fetching
            row.update(
                {
                    "dependabot_access": "skipped",
                    "dependabot_alerts": None,
                    "code_scanning_access": "skipped",
                    "code_scanning_alerts": None,
                    "secret_scanning_access": "skipped",
                    "secret_scanning_alerts": None,
                }
            )
        if default_branch:
            row.update(branch_protection(owner, name, default_branch))
            row.update(check_codeowners_exists(owner, name, default_branch))
        flags: List[str] = []
        if row["archived"]:
            flags.append("archived")
        if row["fork"]:
            flags.append("fork")
        if row["private"] is False and not row.get("default_branch_protected"):
            flags.append("public_unprotected_default_branch")
        if (row.get("dependabot_alerts") or 0) > 0:
            flags.append("dependabot_alerts_present")
        if (row.get("secret_scanning_alerts") or 0) > 0:
            flags.append("secret_scanning_alerts_present")
        if (row.get("code_scanning_alerts") or 0) > 0:
            flags.append("code_scanning_alerts_present")
        row["flags"] = ", ".join(flags)
        if os.getenv("DEBUG"):
            elapsed = time.monotonic() - start_repo
            print(f"repo {owner}/{name} took {elapsed:.2f}s", file=sys.stderr)
        return row

    rows: List[Dict[str, Any]] = []
    if repos:
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(process_single, r) for r in repos]
            for fut in as_completed(futures):
                try:
                    rows.append(fut.result())
                except Exception:
                    print("error processing repo", file=sys.stderr)
    else:
        rows = []

    df = pd.DataFrame(rows)
    # apply sorting if requested; default to pushed_at descending
    if sort_key is None:
        sort_key = "pushed_at"
        sort_asc = False
    if sort_key in df.columns:
        df = df.sort_values(by=sort_key, ascending=sort_asc, na_position="last")
    else:
        if sort_key is not None:
            print(f"Warning: sort key '{sort_key}' not a column", file=sys.stderr)

    # write rows to audit database if requested; do it in a single
    # connection/transaction rather than per-row for performance
    if audit_db_path:
        conn = sqlite3.connect(audit_db_path)
        cursor = conn.cursor()
        for record in df.to_dict(orient="records"):
            full = record.get("full_name")
            if full:
                cursor.execute(
                    "INSERT OR REPLACE INTO repo_rows (full_name, audit_json) VALUES (?, ?)",
                    (full, json.dumps(record)),
                )
        conn.commit()
        conn.close()

    # Report how many repositories we ended up processing
    print(f"Processed {len(rows)} repositories", file=sys.stderr)

    # explicit elapsed report (atexit will also fire)
    elapsed = time.monotonic() - __start_time
    print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)
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
        try:
            with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="Repos")
                summary.to_excel(writer, index=False, sheet_name="Summary")
            print(f"Wrote {excel_path}", file=sys.stderr)
        except ImportError:
            print(
                "Excel export requires the openpyxl package.\n"
                "Install it with `pip install openpyxl` and retry.",
                file=sys.stderr,
            )
            sys.exit(1)

    # when no excel and no repo-file and no audit-db, output recent results
    if not excel_path and repo_list is None and audit_db_path is None:
        output_data = df.to_dict(orient="records")
        print(json.dumps(output_data, indent=2))


if __name__ == "__main__":
    main()
