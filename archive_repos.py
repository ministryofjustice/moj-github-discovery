"""Utilities for finding and evaluating repositories that may be candidates for
archiving.

The ``archive_repos.py`` script fetches metadata for an org and reports on age
and activity.  It already calculated days-since-last-push, but newer versions
also record a few extra criteria that are useful when reviewing *archived*
repositories, such as whether an archived repo still has open issues, stars,
or watchers.  These flags and additional summary metrics help catch cases
where an archive might not be complete or where further cleanup is warranted.
"""

import atexit
import json
import os
import pickle
import sys
import time
import sqlite3
from typing import Any, Dict, List, Optional

import pandas as pd

from utils import gh_api, init_db, save_to_db, try_get

# Store script directory early so it's available in atexit callbacks
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# track start time for automatic reporting
__start_time: Optional[float] = None

def _report_elapsed() -> None:
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)

atexit.register(_report_elapsed)


def _save_all_search_caches() -> None:
    """Save all search caches and repo info cache when the script exits."""
    for org, cache in _search_cache.items():
        _save_search_cache(org, cache)
    _save_repo_info_cache(_repo_info_cache)

atexit.register(_save_all_search_caches)


def _get_repo_cache_path(org: str) -> str:
    """Return the pickle cache filename for a given organization."""
    return os.path.join(SCRIPT_DIR, f".repos_cache_{org}.pkl")


def old_org_repos(org: str, limit: int = 5000, use_cache: bool = True) -> List[Dict[str, Any]]:
    """Fetch repos from GitHub API, caching results to reduce API calls.
    
    If use_cache=True, checks for cached repos first and uses them.
    If cache doesn't exist or use_cache=False, fetches from API and caches.
    """
    cache_path = _get_repo_cache_path(org)
    
    # Try to load from cache if it exists
    if use_cache and os.path.exists(cache_path):
        try:
            with open(cache_path, 'rb') as f:
                repos = pickle.load(f)
                print(f"Loaded {len(repos)} repos from cache: {cache_path}", file=sys.stderr)
                return repos[:limit]
        except Exception as e:
            print(f"Failed to load cache: {e}. Fetching from API.", file=sys.stderr)
    
    # Fetch from API if cache doesn't exist or failed
    collected: List[Dict[str, Any]] = []
    page = 1
    per_page = 10
    while len(collected) < limit:
        print(f"Fetching page {page} from {org}...", file=sys.stderr)
        batch = gh_api(
            f"/orgs/{org}/repos?per_page={per_page}&page={page}&sort=pushed&direction=asc"
        )
        if not batch or not isinstance(batch, list):
            break
        collected.extend(batch)
        print(f"Page {page}: got {len(batch)} repos, total collected: {len(collected)}", file=sys.stderr)
        # if fewer than a full page returned, we've reached the end
        if len(batch) < per_page:
            print(f"Reached end of repo list (fewer than {per_page} repos on page {page})", file=sys.stderr)
            break
        page += 1
    
    # Cache the results
    try:
        with open(cache_path, 'wb') as f:
            pickle.dump(collected, f)
            print(f"Cached {len(collected)} repos to: {cache_path}", file=sys.stderr)
    except Exception as e:
        print(f"Failed to cache repos: {e}", file=sys.stderr)
    
    return collected[:limit]


def _get_search_cache_path(org: str) -> str:
    """Return the pickle cache filename for search references for a given organization."""
    return os.path.join(SCRIPT_DIR, f".search_cache_{org}.pkl")


def _load_search_cache(org: str) -> Dict[str, List[Dict[str, Any]]]:
    """Load the search cache for an organization. Returns empty dict if cache doesn't exist."""
    cache_path = _get_search_cache_path(org)
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'rb') as f:
                cache = pickle.load(f)
                print(f"Loaded search cache for {org}: {len(cache)} repos cached", file=sys.stderr)
                return cache
        except Exception as e:
            print(f"Failed to load search cache: {e}", file=sys.stderr)
    return {}


def _save_search_cache(org: str, cache: Dict[str, List[Dict[str, Any]]]) -> None:
    """Save the search cache for an organization."""
    cache_path = _get_search_cache_path(org)
    try:
        with open(cache_path, 'wb') as f:
            pickle.dump(cache, f)
            print(f"Saved search cache for {org}: {len(cache)} repos cached", file=sys.stderr)
    except Exception as e:
        print(f"Failed to save search cache: {e}", file=sys.stderr)


# Global search cache - populated at script start
_search_cache: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

# When True, skip all API calls and use only cached data
_cache_only: bool = False


def _get_repo_info_cache_path() -> str:
    """Return the pickle cache filename for repo info."""
    return os.path.join(SCRIPT_DIR, ".repo_info_cache.pkl")


def _load_repo_info_cache() -> Dict[str, Dict[str, Any]]:
    """Load the repo info cache. Returns empty dict if cache doesn't exist."""
    cache_path = _get_repo_info_cache_path()
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'rb') as f:
                cache = pickle.load(f)
                print(f"Loaded repo info cache: {len(cache)} repos", file=sys.stderr)
                return cache
        except Exception as e:
            print(f"Failed to load repo info cache: {e}", file=sys.stderr)
    return {}


def _save_repo_info_cache(cache: Dict[str, Dict[str, Any]]) -> None:
    """Save the repo info cache."""
    cache_path = _get_repo_info_cache_path()
    try:
        with open(cache_path, 'wb') as f:
            pickle.dump(cache, f)
            print(f"Saved repo info cache: {len(cache)} repos", file=sys.stderr)
    except Exception as e:
        print(f"Failed to save repo info cache: {e}", file=sys.stderr)


# Global repo info cache - populated at script start
_repo_info_cache: Dict[str, Dict[str, Any]] = _load_repo_info_cache()


def _search_references(org: str, owner: str, repo: str) -> List[Dict[str, Any]]:
    """Return a list of code search hits referencing ``owner/repo`` within the
    same organization.

    GitHub's code search supports qualifiers; we restrict the query to
    ``org:<org>`` so that only repositories belonging to the specified
    organization are examined.  Results are returned as a list of dicts,
    each containing ``full_name`` (the repo doing the referencing) and
    ``path`` (file path where the string was found).
    
    Self-references (hits within the repo itself) are filtered out.
    Results are cached in memory and persisted to disk.
    """
    # Initialize org cache if needed
    if org not in _search_cache:
        _search_cache[org] = _load_search_cache(org)
    
    cache = _search_cache[org]
    repo_key = f"{owner}/{repo}"
    
    # Check if we have cached results for this repo
    if repo_key in cache:
        print(f"Using cached search results for {repo_key}", file=sys.stderr)
        return cache[repo_key]
    
    # In cache-only mode, skip API calls for uncached repos
    if _cache_only:
        return []
    
    print(f"Searching for references to {repo_key} within {org}...", file=sys.stderr)
    hits: List[Dict[str, Any]] = []
    target_full_name = repo_key
    # limit to the organization to avoid unrelated cross‑org noise
    # search for just the repo name to find external references
    query = f'"{repo}" in:file org:{org}'
    try:
        # Manually paginate through search results
        # The search API returns max 100 items per page but may have more total results
        page = 1
        per_page = 10
        total_count = 0
        while True:
            resp = gh_api(f"/search/code?q={query}&per_page={per_page}&page={page}")
            if isinstance(resp, dict):
                total = resp.get("total_count", 0)
                items = resp.get("items", [])
                print(f"Page {page}: got {len(items)} items, total: {total}", file=sys.stderr)
                
                if not items:
                    break
                    
                for item in items:
                    repo_info = item.get("repository") or {}
                    # filter out self-references
                    if repo_info.get("full_name") != target_full_name:
                        hits.append({
                            "full_name": repo_info.get("full_name"),
                            "path": item.get("path"),
                        })
                
                # If we got fewer items than requested, we've reached the end
                if len(items) < per_page:
                    break
                    
                page += 1
            else:
                break
        
        # Cache the results
        cache[repo_key] = hits
        print(f"Cached {len(hits)} references for {repo_key}", file=sys.stderr)
        # Add delay to respect GitHub's rate limit (30 requests/minute)
        time.sleep(2.1)
    except Exception as e:
        import traceback
        print(f"ERROR during search for references to {repo_key}: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        # Don't cache errors - only cache successful results
    
    return hits


def process_single(org: str, r: Dict[str, Any]) -> Dict[str, Any]:
    """Process a single repository and return its audit row.

    Gathers metadata, checks dependency graph status, performs code search
    for references within the organization, and applies risk flags.
    """
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
        "disabled": r.get("disabled"),
        "fork": r.get("fork"),
        # whether GitHub's dependency graph feature is enabled for
        # this repository. We attempt a lightweight lookup; if the
        # endpoint returns data, assume enabled.
        "dependency_graph_enabled": False,
        # references to this repo from other repos (populated later)
        "references": [],
        "archive_references": [],
        "active_references": [],
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
    # check whether the dependency graph endpoint is available
    if not _cache_only:
        try:
            dg, err = try_get(f"/repos/{owner}/{name}/dependency-graph")
            if err is None:
                row["dependency_graph_enabled"] = True
        except Exception:
            # ignore errors; just leave default False
            pass

    # conduct a code search (restricted to the org) to see if other
    # repositories reference this project.  we collect the repo names and
    # paths, then classify the referencing repositories based on their
    # archived status.
    refs = _search_references(org, owner, name)
    print(f"Search for {owner}/{name} returned {len(refs)} refs:", file=sys.stderr)
    for ref in refs:
        print(f"  - {ref.get('full_name')}", file=sys.stderr)
    seen: Dict[str, bool] = {}
    for hit in refs:
        repo_full = hit.get("full_name")
        if not repo_full or repo_full == row.get("full_name"):
            continue
        # avoid repeated lookups for the same repository
        if repo_full not in seen:
            # Check cache first
            if repo_full in _repo_info_cache:
                archived = _repo_info_cache[repo_full].get("archived", False)
                seen[repo_full] = bool(archived)
                print(f"Using cached info for {repo_full}: archived={archived}", file=sys.stderr)
            elif _cache_only:
                # In cache-only mode, skip API calls for uncached repos
                seen[repo_full] = False
            else:
                # Fetch from API if not in cache
                info, err = try_get(f"/repos/{repo_full}")
                if info:
                    archived = info.get("archived")
                    seen[repo_full] = bool(archived)
                    # Cache the result
                    _repo_info_cache[repo_full] = {"archived": archived}
                    print(f"Fetched {repo_full}: archived={archived}", file=sys.stderr)
                else:
                    print(f"ERROR: Could not fetch {repo_full}: {err}", file=sys.stderr)
                    seen[repo_full] = False
                    # Don't cache errors
        archived_flag = seen.get(repo_full)
        row["references"].append({
            "full_name": repo_full,
            "path": hit.get("path"),
            "archived": archived_flag,
        })
        if archived_flag:
            row["archive_references"].append(repo_full)
        else:
            row["active_references"].append(repo_full)
    # deduplicate
    row["archive_references"] = list(set(row["archive_references"]))
    row["active_references"] = list(set(row["active_references"]))

    # several simple flags that make it easy to spot unusual repos
    flags: List[str] = []
    if row["archived"]:
        flags.append("archived")
        # additional criteria for already-archived projects; they should
        # generally be quiet, so note if anything interesting remains.
        if row.get("open_issues", 0) > 0:
            flags.append("archived_open_issues")
        if row.get("stargazers", 0) > 0:
            flags.append("archived_has_stars")
        if row.get("watchers", 0) > 0:
            flags.append("archived_has_watchers")
        if row.get("forks", 0) > 0:
            flags.append("archived_has_forks")
        if row.get("disabled"):
            flags.append("archived_and_disabled")
    if row["fork"]:
        flags.append("fork")
    row["flags"] = ", ".join(flags)
    if os.getenv("DEBUG"):
        elapsed = time.monotonic() - start_repo
        print(f"repo {owner}/{name} took {elapsed:.2f}s", file=sys.stderr)
    return row

def main():
    global __start_time, _cache_only
    __start_time = time.monotonic()
    if len(sys.argv) < 2:
        print("Usage: python archive_repos.py <org> [--csv path] [--limit N] [--page-num N] [--sort [-]column] [--audit-db path] [--cache-only]" \
        "\n(requires --csv or --audit-db; default sort is days_since_push ascending)\n" \
        "--page-num: Get only repos in specified page (page size 100, 0-indexed)\n" \
        "--cache-only: Skip all API calls, use only cached data for fast results")
        sys.exit(2)
    
    org = sys.argv[1]
    # defaults – paths alongside script
    default_db_path = os.path.join(SCRIPT_DIR, "repo_audit.db")
    csv_path: Optional[str] = None
    limit: Optional[int] = None
    page_num: Optional[int] = None
    sort_key: Optional[str] = None
    sort_asc: bool = True  # default to ascending days_since_push
    audit_db_path: Optional[str] = None  # None means don't write to DB
    # we don't fetch any security alerts or branch protection to keep the run fast
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--csv" and i + 1 < len(sys.argv):
            csv_path = sys.argv[i + 1]
            i += 2
        elif arg == "--limit" and i + 1 < len(sys.argv):
            try:
                limit = int(sys.argv[i + 1])
            except ValueError:
                print("--limit requires an integer")
                sys.exit(2)
            i += 2
        elif arg == "--page-num" and i + 1 < len(sys.argv):
            try:
                page_num = int(sys.argv[i + 1])
            except ValueError:
                print("--page-num requires an integer")
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
        elif arg == "--audit-db":
            # --audit-db with optional path; if no path, use default repo_audit.db
            if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("--"):
                audit_db_path = sys.argv[i + 1]
                i += 2
            else:
                # no path provided; use default
                audit_db_path = default_db_path
                i += 1
        elif arg == "--cache-only":
            _cache_only = True
            i += 1
        else:
            print(f"Unknown argument: {arg}")
            sys.exit(2)

    # if audit database given, ensure table is created
    if audit_db_path:
        init_db(audit_db_path, table_name="repo_rows")

    # determine how many repos to fetch (always use full list since we require --csv or --audit-db)
    if limit is None:
        effective_limit = 5000
    else:
        effective_limit = limit
    repos = old_org_repos(org, limit=effective_limit)
    
    # Page size: 100 repos per page
    page_size = 100
    
    rows: List[Dict[str, Any]] = []
    
    # If page_num is specified, only process that page
    if page_num is not None:
        start_idx = page_num * page_size
        end_idx = start_idx + page_size
        repos_to_process = repos[start_idx:end_idx]
        print(f"Processing page {page_num} (repos {start_idx}-{end_idx})", file=sys.stderr)
        for r in repos_to_process:
            try:
                rows.append(process_single(org, r))
            except Exception:
                print("error processing repo", file=sys.stderr)
        
        # Wait 1 minute after pages that are multiples of 10
        if not _cache_only and (page_num + 1) % 10 == 0:
            print(f"Completed page {page_num} (10-page checkpoint), waiting 1 minute...", file=sys.stderr)
            time.sleep(60)
    else:
        # Process all repos in pages with wait time after every 10 pages
        total_pages = (len(repos) + page_size - 1) // page_size
        print(f"Total repos: {len(repos)}, Total pages: {total_pages}", file=sys.stderr)
        for page in range(total_pages):
            start_idx = page * page_size
            end_idx = start_idx + page_size
            repos_to_process = repos[start_idx:end_idx]
            print(f"Processing page {page} (repos {start_idx}-{end_idx})", file=sys.stderr)
            for r in repos_to_process:
                try:
                    rows.append(process_single(org, r))
                except Exception:
                    print("error processing repo", file=sys.stderr)
            
            # Wait 1 minute after every 10 pages
            if not _cache_only and (page + 1) % 10 == 0:
                print(f"Completed 10 pages, waiting 1 minute before next batch...", file=sys.stderr)
                time.sleep(60)
    
    if not rows:
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
    # Summary dataframe (optional csv export)
    # summary metrics; include only simple counts and age
    metrics = [
        "repos_total",
        "repos_public",
        "repos_private",
        "repos_archived",
    ]
    values: List[Any] = [
        len(df),
        int((df["private"] == False).sum()) if "private" in df.columns else 0,
        int((df["private"] == True).sum()) if "private" in df.columns else 0,
        int(df["archived"].sum()) if "archived" in df.columns else 0,
    ]
    # compute some additional counts that apply when a repo is archived
    if "open_issues" in df.columns:
        metrics.append("archived_with_open_issues")
        values.append(int(df.loc[df["archived"] & (df["open_issues"] > 0)].shape[0]))
    if "stargazers" in df.columns:
        metrics.append("archived_with_stars")
        values.append(int(df.loc[df["archived"] & (df["stargazers"] > 0)].shape[0]))
    if "disabled" in df.columns:
        metrics.append("repos_disabled")
        values.append(int(df["disabled"].sum()))
    # dependency graph / reference metrics
    if "dependency_graph_enabled" in df.columns:
        metrics.append("repos_with_dependency_graph")
        values.append(int(df["dependency_graph_enabled"].sum()))
    if "active_references" in df.columns:
        metrics.append("repos_with_active_refs")
        values.append(int(df["active_references"].apply(lambda lst: len(lst) > 0).sum()))
    if "archive_references" in df.columns:
        metrics.append("repos_with_archive_refs")
        values.append(int(df["archive_references"].apply(lambda lst: len(lst) > 0).sum()))
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

    if csv_path:
        try:
            df.to_csv(csv_path, index=False)
            print(f"Wrote {csv_path}", file=sys.stderr)
        except Exception as e:
            print(f"CSV export failed: {e}", file=sys.stderr)
            sys.exit(1)

    # when no csv and no audit-db, output recent results
    if not csv_path and audit_db_path is None:
        output_data = df.to_dict(orient='records')
        print(json.dumps(output_data, indent=2))


if __name__ == "__main__":
    main()
