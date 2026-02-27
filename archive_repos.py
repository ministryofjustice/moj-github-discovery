import atexit
import json
import os
import sys
import time
import sqlite3
from typing import Any, Dict, List, Optional

import pandas as pd

from utils import gh_api, init_db, save_to_db

# track start time for automatic reporting
__start_time: Optional[float] = None

def _report_elapsed() -> None:
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)

atexit.register(_report_elapsed)


def old_org_repos(org: str, limit: int = 5000) -> List[Dict[str, Any]]:
    
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
        print("Usage: python old_repos.py <org> [--excel path] [--limit N] [--sort [-]column] [--repo-file file] [--audit-db path]\n(default sort is days_since_push ascending, i.e. newest first)")
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
    # we don't fetch any security alerts or branch protection to keep the run fast
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
        repos = old_org_repos(org, limit=effective_limit)

    # helper for a single repo; extracted so it can run in a pool
    def process_single(r: Dict[str, Any]) -> Dict[str, Any]:
        start_repo = time.monotonic()
        name = r["name"]
        owner = r["owner"]["login"]
        default_branch = r.get("default_branch")
        row: Dict[str, Any] = {
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
            "watchers": r.get("watchers_count"),
            "forks": r.get("forks_count"),
            "description": r.get("description"),
            "created_at": r.get("created_at"),
            "updated_at": r.get("updated_at"),
            "size": r.get("size"),
            "is_template": r.get("is_template"),
            "security_and_analysis": r.get("security_and_analysis"),
        }
        # just note archived/forked status
        flags: List[str] = []
        if row["archived"]:
            flags.append("archived")
        if row["fork"]:
            flags.append("fork")
        row["flags"] = ", ".join(flags)
        if os.getenv("DEBUG"):
            elapsed = time.monotonic() - start_repo
            print(f"repo {owner}/{name} took {elapsed:.2f}s", file=sys.stderr)
        return row

    rows: List[Dict[str, Any]] = []
    if repos:
        for r in repos:
            try:
                rows.append(process_single(r))
            except Exception:
                print("error processing repo", file=sys.stderr)
    else:
        rows = []

    df = pd.DataFrame(rows)

    # compute inactivity/age fields from timestamps so it's easy to identify stale
    now = pd.Timestamp.now("UTC")
    for col in ("pushed_at", "created_at", "updated_at"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")
    if "pushed_at" in df.columns:
        df["days_since_push"] = (now - df["pushed_at"]).dt.days
    if "created_at" in df.columns:
        df["age_days"] = (now - df["created_at"]).dt.days

    # convert timestamp columns to readable date strings for output
    for col in ("pushed_at", "created_at", "updated_at"):
        if col in df.columns:
            df[col] = df[col].dt.strftime("%Y-%m-%d %H:%M:%S")

    # apply sorting if requested; default to most recently pushed
    if sort_key is None:
        sort_key = "days_since_push"
        sort_asc = True
    if sort_key in df.columns:
        df = df.sort_values(by=sort_key, ascending=sort_asc, na_position='last')
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
    # summary metrics; include only simple counts and age
    metrics = [
        "repos_total",
        "repos_public",
        "repos_private",
        "repos_archived",
    ]
    values: List[Any] = [
        len(df),
        int((df["private"] == False).sum()),
        int((df["private"] == True).sum()),
        int(df["archived"].sum()),
    ]
    # add age-based stats if available
    if "days_since_push" in df.columns:
        metrics.append("repos_not_pushed_in_year")
        values.append(int((df["days_since_push"] > 365).sum()))
        metrics.append("max_days_since_push")
        values.append(int(df["days_since_push"].max()))
    if "age_days" in df.columns:
        metrics.append("oldest_repo_days")
        values.append(int(df["age_days"].max()))

    summary = pd.DataFrame({"metric": metrics, "value": values})

    if excel_path:
        try:
            with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="Repos")
                summary.to_excel(writer, index=False, sheet_name="Summary")
            print(f"Wrote {excel_path}", file=sys.stderr)
        except ImportError:
            print("Excel export requires the openpyxl package.\n"
                  "Install it with `pip install openpyxl` and retry.",
                  file=sys.stderr)
            sys.exit(1)

    # when no excel and no repo-file and no audit-db, output recent results
    if not excel_path and repo_list is None and audit_db_path is None:
        output_data = df.to_dict(orient='records')
        print(json.dumps(output_data, indent=2))


if __name__ == "__main__":
    main()
