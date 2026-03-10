import atexit
import json
import os
import sys
import time
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd

from utils import gh_api, try_get, get_full_branch_protection, init_db

# track start time for automatic reporting
__start_time: Optional[float] = None

def _report_elapsed() -> None:
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)

atexit.register(_report_elapsed)

# ---------------------------------------------------------------------------
# Standards compliance checks
# ---------------------------------------------------------------------------
# Each tuple is (check_name, data_path[, expected_value]).
#   - 2-tuple: passes when the value at *data_path* is truthy / non-blank.
#   - 3-tuple: passes when the value equals *expected_value*
#              (for numeric comparisons, value >= expected is also accepted).

STANDARDS: List[Union[Tuple[str, str], Tuple[str, str, Any]]] = [
    ('visibility_public', 'basic.visibility', 'public'),
    ('default_branch_main', 'basic.default_branch_name', 'main'),
    ('repository_description', 'basic.description'),
    ('secret_scanning', 'security_and_analysis.secret_scanning_status', 'enabled'),
    (
        'secret_scanning_push_protection',
        'security_and_analysis.push_protection_status',
        'enabled',
    ),
    ('branch_protection_admins', 'default_branch_protection.enforce_admins', True),
    ('branch_protection_signed', 'default_branch_protection.required_signatures', True),
    (
        'branch_protection_code_owner_review',
        'default_branch_protection.require_code_owner_reviews',
        True,
    ),
    (
        'pull_dismiss_stale_reviews',
        'default_branch_protection.dismiss_stale_reviews',
        True,
    ),
    (
        'pull_requires_review',
        'default_branch_protection.required_approving_review_count',
        1,
    ),
    ('authoritative_owner', 'basic.owner'),
    ('licence_mit', 'basic.license', 'mit'),
    ('issues_section_enabled', 'basic.has_issues', True),
]


# ---------------------------------------------------------------------------
# Data collection helpers
# ---------------------------------------------------------------------------

def _extract_team_from_name(repo_name: str) -> Optional[str]:
    """Extract a team prefix from a repo name like 'team-project-name'."""
    if "-" in repo_name:
        return repo_name.split("-", 1)[0]
    return None


def _get_api_teams(owner: str, repo: str) -> List[str]:
    """Try to fetch teams with access to a repo via the API.

    Returns a list of team slugs, or empty list if the endpoint is
    inaccessible (requires org-level read permissions).
    """
    data, err = try_get(f"/repos/{owner}/{repo}/teams")
    if err or not isinstance(data, list):
        return []
    return [t.get("slug") or t.get("name") for t in data if t.get("slug") or t.get("name")]


def _collect_basic(repo: Dict[str, Any]) -> Dict[str, Any]:
    """Extract basic repo fields into a flat dict keyed for standard lookups."""
    license_info = repo.get("license") or {}
    return {
        "visibility": "private" if repo.get("private") else "public",
        "default_branch_name": repo.get("default_branch"),
        "description": (repo.get("description") or "").strip(),
        "owner": (repo.get("owner") or {}).get("login"),
        "license": (license_info.get("spdx_id") or license_info.get("key") or "").lower(),
        "has_issues": repo.get("has_issues"),
    }


def _collect_security_and_analysis(repo: Dict[str, Any]) -> Dict[str, Any]:
    """Extract security_and_analysis settings from the repo payload."""
    sa = repo.get("security_and_analysis") or {}
    return {
        "secret_scanning_status": (sa.get("secret_scanning") or {}).get("status"),
        "push_protection_status": (
            sa.get("secret_scanning_push_protection") or {}
        ).get("status"),
    }


def _collect_branch_protection(owner: str, repo: str, branch: str) -> Dict[str, Any]:
    """Fetch full branch protection and normalise into flat check fields."""
    result: Dict[str, Any] = {
        "enforce_admins": None,
        "required_signatures": None,
        "require_code_owner_reviews": None,
        "dismiss_stale_reviews": None,
        "required_approving_review_count": None,
    }
    bp = get_full_branch_protection(owner, repo, branch)
    if not bp.get("ok"):
        return result
    prot = bp.get("protection") or {}
    result["enforce_admins"] = bool((prot.get("enforce_admins") or {}).get("enabled"))
    result["required_signatures"] = bool(
        (prot.get("required_signatures") or {}).get("enabled")
    )
    pr_reviews = prot.get("required_pull_request_reviews") or {}
    result["require_code_owner_reviews"] = bool(
        pr_reviews.get("require_code_owner_reviews")
    )
    result["dismiss_stale_reviews"] = bool(pr_reviews.get("dismiss_stale_reviews"))
    result["required_approving_review_count"] = pr_reviews.get(
        "required_approving_review_count", 0
    )
    return result


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _resolve_path(data: Dict[str, Dict[str, Any]], path: str) -> Any:
    """Resolve a dotted path like 'basic.visibility' against collected data."""
    parts = path.split(".", 1)
    if len(parts) != 2:
        return None
    category, field = parts
    return (data.get(category) or {}).get(field)


def _evaluate_standards(
    data: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Evaluate every standard and return a list of result dicts."""
    results: List[Dict[str, Any]] = []
    for std in STANDARDS:
        name = std[0]
        path = std[1]
        actual = _resolve_path(data, path)
        if len(std) == 3:
            expected = std[2]
            if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
                passed = actual >= expected
            else:
                passed = actual == expected
        else:
            # truthy / non-blank check
            passed = bool(actual)
        results.append({
            "check": name,
            "path": path,
            "expected": std[2] if len(std) == 3 else "(non-blank)",
            "actual": actual,
            "passed": passed,
        })
    return results


# ---------------------------------------------------------------------------
# Repo listing
# ---------------------------------------------------------------------------

def list_org_repos(org: str, limit: int = 800) -> List[Dict[str, Any]]:
    """Retrieve repositories for an organization, sorted by last push."""
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


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------

def process_single(org: str, r: Dict[str, Any]) -> Dict[str, Any]:
    """Run compliance checks for a single repository."""
    start_repo = time.monotonic()
    name = r["name"]
    owner = r["owner"]["login"]
    default_branch = r.get("default_branch")

    # The org listing endpoint doesn't include security_and_analysis;
    # fetch the full repo payload so we get it.
    full_repo = r
    if "security_and_analysis" not in r:
        try:
            full_repo = gh_api(f"/repos/{owner}/{name}")
        except Exception:
            pass

    # Collect data buckets
    data: Dict[str, Dict[str, Any]] = {
        "basic": _collect_basic(full_repo),
        "security_and_analysis": _collect_security_and_analysis(full_repo),
        "default_branch_protection": (
            _collect_branch_protection(owner, name, default_branch)
            if default_branch
            else {}
        ),
    }

    # Evaluate standards
    checks = _evaluate_standards(data)
    passed_count = sum(1 for c in checks if c["passed"])
    total_count = len(checks)

    # Team identification: prefer API teams, fall back to name prefix
    api_teams = _get_api_teams(owner, name)
    team_from_name = _extract_team_from_name(name)

    row: Dict[str, Any] = {
        "org": org,
        "repo": name,
        "full_name": full_repo.get("full_name"),
        "team": api_teams[0] if api_teams else team_from_name,
        "team_source": "api" if api_teams else ("name_prefix" if team_from_name else None),
        "api_teams": ", ".join(api_teams) if api_teams else None,
        "private": full_repo.get("private"),
        "archived": full_repo.get("archived"),
        "pushed_at": full_repo.get("pushed_at"),
        "default_branch": default_branch,
        "language": full_repo.get("language"),
        "compliance_passed": passed_count,
        "compliance_total": total_count,
        "compliance_pct": round(100 * passed_count / total_count, 1) if total_count else 0,
    }

    # Add individual check columns
    failed_checks: List[str] = []
    for c in checks:
        row[c["check"]] = c["passed"]
        if not c["passed"]:
            failed_checks.append(c["check"])
    row["failed_checks"] = ", ".join(failed_checks)

    elapsed = time.monotonic() - start_repo
    print(f"  [{owner}/{name}] {passed_count}/{total_count} checks passed ({elapsed:.1f}s)", file=sys.stderr)
    return row


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    global __start_time
    __start_time = time.monotonic()
    if len(sys.argv) < 2:
        print(
            "Usage: python repo_compliance.py <org> [--excel path] [--limit N] "
            "[--sort [-]column] [--repo-file file] [--audit-db path]"
        )
        sys.exit(2)

    org = sys.argv[1]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_db_path = os.path.join(script_dir, "repo_compliance.db")
    excel_path: Optional[str] = None
    limit: Optional[int] = None
    repo_list: Optional[List[str]] = None
    sort_key: Optional[str] = None
    sort_asc: bool = True
    audit_db_path: Optional[str] = None
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
            if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("--"):
                audit_db_path = sys.argv[i + 1]
                i += 2
            else:
                audit_db_path = default_db_path
                i += 1
        else:
            print(f"Unknown argument: {arg}")
            sys.exit(2)

    if audit_db_path:
        init_db(audit_db_path, table_name="compliance_rows")

    # Fetch repos
    print("Fetching repo list...", file=sys.stderr)
    fetch_start = time.monotonic()
    if repo_list is not None:
        repos: List[Dict[str, Any]] = []
        for full in repo_list:
            owner, rname = full.split("/", 1)
            try:
                repos.append(gh_api(f"/repos/{owner}/{rname}"))
            except Exception:
                pass
    else:
        if limit is None:
            effective_limit = 800 if (excel_path or audit_db_path) else 10
        else:
            effective_limit = limit
        repos = list_org_repos(org, limit=effective_limit)
    fetch_elapsed = time.monotonic() - fetch_start
    print(f"Fetched {len(repos)} repos in {fetch_elapsed:.1f}s", file=sys.stderr)

    # Process repos
    total_repos = len(repos)
    rows: List[Dict[str, Any]] = []
    process_start = time.monotonic()
    for idx, r in enumerate(repos, 1):
        try:
            rows.append(process_single(org, r))
        except Exception as exc:
            print(f"error processing repo {r.get('full_name')}: {exc}", file=sys.stderr)
        if idx % 10 == 0 or idx == total_repos:
            batch_elapsed = time.monotonic() - process_start
            avg = batch_elapsed / idx
            eta = avg * (total_repos - idx)
            print(
                f"Progress: {idx}/{total_repos} repos "
                f"({batch_elapsed:.0f}s elapsed, ~{eta:.0f}s remaining)",
                file=sys.stderr,
            )

    df = pd.DataFrame(rows)

    # Sort
    if sort_key is None:
        sort_key = "compliance_pct"
        sort_asc = True
    if sort_key in df.columns:
        df = df.sort_values(by=sort_key, ascending=sort_asc, na_position="last")
    else:
        print(f"Warning: sort key '{sort_key}' not a column", file=sys.stderr)

    # Write to DB
    if audit_db_path:
        conn = sqlite3.connect(audit_db_path)
        cursor = conn.cursor()
        for record in df.to_dict(orient="records"):
            full = record.get("full_name")
            if full:
                cursor.execute(
                    "INSERT OR REPLACE INTO compliance_rows (full_name, audit_json) VALUES (?, ?)",
                    (full, json.dumps(record)),
                )
        conn.commit()
        conn.close()

    print(f"Processed {len(rows)} repositories", file=sys.stderr)
    elapsed = time.monotonic() - __start_time
    print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)

    # Summary
    check_names = [s[0] for s in STANDARDS]
    summary_rows = []
    for cn in check_names:
        if cn in df.columns:
            summary_rows.append({"check": cn, "passed": int(df[cn].sum()), "total": len(df)})
    summary = pd.DataFrame(summary_rows)

    if excel_path:
        try:
            with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="Compliance")
                summary.to_excel(writer, index=False, sheet_name="Summary")
            print(f"Wrote {excel_path}", file=sys.stderr)
        except ImportError:
            print(
                "Excel export requires openpyxl. Install with: pip install openpyxl",
                file=sys.stderr,
            )
            sys.exit(1)

    if not excel_path and repo_list is None and audit_db_path is None:
        print(json.dumps(df.to_dict(orient="records"), indent=2))


if __name__ == "__main__":
    main()
