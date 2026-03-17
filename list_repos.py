import atexit
import json
import os
import pickle
import sys
import time
import sqlite3
import threading
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd

from utils import gh_api, count_alerts, branch_protection, init_db, save_to_db, fork_and_template_info, check_codeowners_exists

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# track start time for automatic reporting
__start_time: Optional[float] = None

def _report_elapsed() -> None:
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)

atexit.register(_report_elapsed)

# ---------------------------------------------------------------------------
# Per-repo alert / enrichment cache
# ---------------------------------------------------------------------------
_ALERT_CACHE_PATH = os.path.join(SCRIPT_DIR, ".list_repos_alert_cache.pkl")
_alert_cache: Dict[str, Dict[str, Any]] = {}
_alert_cache_lock = threading.Lock()
_alert_cache_dirty = False

def _load_alert_cache() -> Dict[str, Dict[str, Any]]:
    if os.path.exists(_ALERT_CACHE_PATH):
        try:
            with open(_ALERT_CACHE_PATH, "rb") as f:
                cache = pickle.load(f)
            print(f"Loaded alert cache: {len(cache)} repos", file=sys.stderr)
            return cache
        except Exception as e:
            print(f"Alert cache load failed: {e}", file=sys.stderr)
    return {}

def _save_alert_cache() -> None:
    if not _alert_cache_dirty:
        return
    try:
        with open(_ALERT_CACHE_PATH, "wb") as f:
            pickle.dump(_alert_cache, f)
        print(f"Saved alert cache: {len(_alert_cache)} repos", file=sys.stderr)
    except Exception as e:
        print(f"Alert cache save failed: {e}", file=sys.stderr)

_alert_cache = _load_alert_cache()
atexit.register(_save_alert_cache)

# This script lists (and optionally audits) every repository in an organization.
# By default it prints the most recent 10 repos to stdout.  Use `--audit-db`
# to write audit rows to a SQLite database, or `--excel` to export an Excel file.
# Filtering, sorting and specific repo selection are also supported.


def list_org_repos(org: str, limit: int = 5000, use_cache: bool = True) -> List[Dict[str, Any]]:
    """Retrieve repositories for an organization, sorted by last push.

    Results are cached to disk so subsequent runs are instant.
    """
    cache_path = os.path.join(SCRIPT_DIR, f".list_repos_cache_{org}.pkl")
    # Also check the archive_repos cache as a fallback
    archive_cache_path = os.path.join(SCRIPT_DIR, f".repos_cache_{org}.pkl")

    if use_cache:
        for cp in (cache_path, archive_cache_path):
            if os.path.exists(cp):
                try:
                    with open(cp, "rb") as f:
                        repos = pickle.load(f)
                    print(f"Loaded {len(repos)} repos from cache ({os.path.basename(cp)})", file=sys.stderr)
                    return repos[:limit]
                except Exception as e:
                    print(f"Cache load failed ({cp}): {e}", file=sys.stderr)

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
        print(f"  page {page}: {len(collected)} repos", file=sys.stderr, flush=True)
        if len(batch) < per_page:
            break
        page += 1

    # Cache results
    try:
        with open(cache_path, "wb") as f:
            pickle.dump(collected, f)
        print(f"Cached {len(collected)} repos", file=sys.stderr)
    except Exception as e:
        print(f"Cache save failed: {e}", file=sys.stderr)

    return collected[:limit]


def main():
    global __start_time
    __start_time = time.monotonic()
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
    no_alerts = False
    no_cache = False
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
        elif arg == "--no-alerts":
            no_alerts = True
            i += 1
        elif arg == "--no-cache":
            no_cache = True
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
                effective_limit = 5000
            else:
                effective_limit = 10
        else:
            effective_limit = limit
        repos = list_org_repos(org, limit=effective_limit, use_cache=not no_cache)
    
    print(f"Loaded {len(repos)} repos total", file=sys.stderr, flush=True)

    # Skip fork/template enrichment — the org listing already has fork/is_template
    # booleans. Fetching parent info per-fork is too slow (hits rate limits).

    # helper for a single repo; extracted so it can run in a pool
    _cached_count = 0
    _fetched_count = 0
    _count_lock = threading.Lock()

    def process_single(r: Dict[str, Any]) -> Dict[str, Any]:
        nonlocal _cached_count, _fetched_count
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
        }
        if no_alerts:
            # Fast path: skip all per-repo API calls
            row.update({
                "fork_source": None,
                "is_generated_from_template": r.get("is_template", False),
                "template_source": None,
                "dependabot_access": "skipped",
                "dependabot_alerts": None,
                "code_scanning_access": "skipped",
                "code_scanning_alerts": None,
                "secret_scanning_access": "skipped",
                "secret_scanning_alerts": None,
                "default_branch_protected": None,
                "codeowners_exists": None,
            })
        else:
            full_name = r.get("full_name", f"{owner}/{name}")
            # Check alert cache first
            with _alert_cache_lock:
                cached = _alert_cache.get(full_name)
            if cached:
                with _count_lock:
                    _cached_count += 1
                row.update(cached)
            else:
                t0 = time.monotonic()
                print(f"  FETCH {full_name} ...", file=sys.stderr, flush=True)
                enrichment: Dict[str, Any] = {}
                enrichment["fork_source"] = None
                enrichment["is_generated_from_template"] = r.get("is_template", False)
                enrichment["template_source"] = None
                enrichment.update(count_alerts(owner, name))
                if default_branch:
                    enrichment.update(branch_protection(owner, name, default_branch))
                    try:
                        enrichment.update(check_codeowners_exists(owner, name, default_branch))
                    except Exception:
                        enrichment["present"] = None
                        enrichment["path"] = None
                row.update(enrichment)
                # Store in cache
                global _alert_cache_dirty
                with _alert_cache_lock:
                    _alert_cache[full_name] = enrichment
                    _alert_cache_dirty = True
                with _count_lock:
                    _fetched_count += 1
                da = enrichment.get("dependabot_alerts", "?")
                cs = enrichment.get("code_scanning_alerts", "?")
                ss = enrichment.get("secret_scanning_alerts", "?")
                bp = enrichment.get("default_branch_protected", "?")
                elapsed_r = time.monotonic() - t0
                print(f"  DONE  {full_name} ({elapsed_r:.1f}s) dependabot={da} code_scan={cs} secrets={ss} protected={bp}", file=sys.stderr, flush=True)
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

    print(f"Processing {len(repos)} repos (no_alerts={no_alerts})...", file=sys.stderr, flush=True)
    rows: List[Dict[str, Any]] = []
    if repos:
        total = len(repos)
        t_start = time.monotonic()
        print(f"\nProcessing {total} repos (alert cache: {len(_alert_cache)} entries)...", file=sys.stderr, flush=True)
        # Use fewer workers for alert fetching to avoid rate limits
        workers = 8 if no_alerts else 4
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(process_single, r) for r in repos]
            for fut in as_completed(futures):
                try:
                    rows.append(fut.result())
                    count = len(rows)
                    if count % 100 == 0 or count == total:
                        elapsed_so_far = time.monotonic() - t_start
                        rate = count / elapsed_so_far if elapsed_so_far > 0 else 0
                        eta = (total - count) / rate if rate > 0 else 0
                        print(f"  [{count}/{total}] {elapsed_so_far:.1f}s elapsed, ~{eta:.0f}s remaining  (cached={_cached_count} fetched={_fetched_count})",
                              file=sys.stderr, flush=True)
                        _save_alert_cache()
                except Exception as e:
                    print(f"  ERROR processing repo: {e}", file=sys.stderr)
        # Final save after all repos processed
        _save_alert_cache()
        elapsed_total = time.monotonic() - t_start
        print(f"\nDone: {len(rows)}/{total} repos in {elapsed_total:.1f}s (cached={_cached_count} fetched={_fetched_count})",
              file=sys.stderr, flush=True)
    else:
        rows = []

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
    metrics = ["repos_total", "repos_public", "repos_private", "repos_archived"]
    values = [
        len(df),
        int((df["private"] == False).sum()) if "private" in df.columns else 0,
        int((df["private"] == True).sum()) if "private" in df.columns else 0,
        int(df["archived"].sum()) if "archived" in df.columns else 0,
    ]
    for col, label in [
        ("dependabot_alerts", "repos_with_dependabot_alerts"),
        ("secret_scanning_alerts", "repos_with_secret_alerts"),
        ("code_scanning_alerts", "repos_with_code_scanning_alerts"),
    ]:
        if col in df.columns:
            metrics.append(label)
            values.append(int((df[col].fillna(0) > 0).sum()))
    if "default_branch_protected" in df.columns and df["default_branch_protected"].notna().any():
        metrics.append("repos_unprotected_default_branch")
        values.append(int((df["default_branch_protected"] == False).sum()))
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
