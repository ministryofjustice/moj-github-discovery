#!/usr/bin/env python3

import argparse
import csv
import datetime as dt
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import requests

from utils import (
    gh_api,
    count_alerts,
    branch_protection,
    check_codeowners_exists,
    fork_and_template_info,
    init_db,
    save_to_db,
    _get_session,
    _extract_link_rel,
)

def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def parse_dt(value: Optional[str]) -> Optional[dt.datetime]:
    if not value:
         return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))

def age_days(start: Optional[dt.datetime], end: Optional[dt.datetime] = None) -> Optional[int]:
    if not start:
        return None
    end = end or now_utc()
    return max((end - start).days, 0)

def safe_get(obj:  Any, *keys: Any, default: Any = "") -> Any:
    cur = obj
    for key in keys:
        if isinstance(cur, dict):
            cur = cur.get(key)
        elif isinstance(cur, list) and isinstance(key, int) and 0 <= key < len(cur):
            cur = cur[key]
        else:
            return default
        if cur is None:
            return default
    return cur

def remediation_date(alert: Dict[str, Any]) -> Optional[dt.datetime]:
    for field in ("fixed_at", "resolved_at", "dismissed_at"):
        parsed = parse_dt(alert.get(field))
        if parsed:
            return parsed
    return None

def extract_logins(users: Any) -> str:
    if not isinstance(users, list):
        return ""
    logins = [u.get("login") for u in users if isinstance(u, dict) and u.get("login")]
    return ",".join(sorted(set(logins)))

def derive_remediator(alert: Dict[str, Any], assignees: str = "") -> str:
    for path in [
        ("dismissed_by", "login"),
        ("resolved_by", "login"),
        ("fixed_by", "login"),
        ("push_protection_bypassed_by", "login"),
    ]:
        value = safe_get(alert, *path, default="")
        if value:
            return value
    return assignees or ""

def severity_weight(severity: str) -> int:
    weights = {
        "critical":10,
        "high": 5,
        "medium": 3,
        "moderate": 3,
        "low": 1,
        "warning": 1,
        "note": 0,
        "error": 5,
    }
    return weights.get((severity or "").lower(), 1 if severity else 0)

def status_group(state: str) -> str:
    return "open" if (state or "").lower() == "open" else "closed"

def csv_write(path: str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
            with open(path, "w", encoding="utf-8") as f:
                pass
            print(f"No rows to write for {path}")
            return

    fieldnames: List[str] = []
    seen = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                fieldnames.append(key)
                seen.add(key)

    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

def parse_repo_full_name(value: str) -> Tuple[str, str]:
    parts = value.strip().split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Expected owner/repo format, got: {value}")
    return parts[0], parts[1]

def load_targets_from_repo_file(path: str) -> List[str]:
    repos: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            repos.append(line)
    return repos

def list_target_repos(args: argparse.Namespace) -> List[Dict[str, Any]]:
    if args.repos:
        repo_names = args.repos
    elif args.repo_file:
        repo_names = load_targets_from_repo_file(args.repo_file)
    else:
        try:
            repos = gh_api(
                f"/orgs/{args.org}/repos",
                paginate=True,
                params=["type=all", "sort=updated", "direction=desc"],
            )
        except requests.exceptions.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else "unknown"
            raise SystemExit(
                f"Unable to list repos for org '{args.org}' (HTTP {code}). "
                f"Use --repos owner/repo ... or --repo-file repos.txt with repos you can access."
            )
        
        if not isinstance(repos, list):
            raise SystemExit("Repo listing did not return a list.")
        repo_infos = repos
        if not args.include_archived:
            repo_infos = repos
        return repo_infos[: args.limit]

    repo_infos: List[Dict[str, Any]] = []
    for full_name in repo_names[: args.limit]:
        owner, repo = parse_repo_full_name(full_name)
        try:
            repo_info = gh_api(f"/repos/{owner}/{repo}")
            if isinstance(repo_info, dict):
                repo_infos.append(repo_info)
        except Exception as exc:
            print(f"Skipping {full_name}: {exc}", file=sys.stderr)

    if not args.include_archived:
        repo_infos = [r for r in repo_infos if not r.get("archived")]
    return repo_infos

def normalize_code_scanning(alert: Dict[str, Any], repo_full: str, sla_days: int) -> Dict[str, Any]:
    created = parse_dt(alert.get("created_at"))
    remediated = remediation_date(alert)
    state = alert.get("state", "")
    assignees = extract_logins(alert.get("assignees") or [])
    severity = (
        safe_get(alert, "rule", "security_severity_level", default="")
        or safe_get(alert, "rule", "severity", default="")
    )

    return {
        "id": alert.get("number") or alert.get("id"),
        "type": "code_scanning",
        "repo": repo_full,
        "owner": repo_full.split("/", 1)[0],
        "repo_name": repo_full.split("/", 1)[1],
        "state": state,
        "status_group": status_group(state),
        "severity": severity,
        "title": safe_get(alert, "rule", "name", default="") or safe_get(alert, "rule", "id", default=""),
        "package": "",
        "ecosystem": "",
        "manifest": "",
        "location": safe_get(alert, "most_recent_instance", "location", "path", default=""),
        "created_at": created.isoformat() if created else "",
        "updated_at": alert.get("updated_at", ""),
        "remediated_at": remediated.isoformat() if remediated else "",
        "age_days": age_days(created, remediated or now_utc()), 
        "ttr_days": age_days(created, remediated) if remediated else None, 
        "sla_days": sla_days,
        "overdue": status_group(state) == "open" and (age_days(created) or 0) > sla_days,
        "stale": status_group(state) == "open" and (age_days(created) or 0) >= 180,
        "remediator": derive_remediator(alert, assignees),
        "assignees": assignees,
        "resolution": alert.get("dismissed_reason") or ("fixed" if alert.get("fixed_at") else ""),
        "html_url": alert.get("html_url", ""),
        "api_url": alert.get("url", ""),   
    }

def normalize_dependabot(alert: Dict[str, Any], repo_full: str, sla_days: int) -> Dict[str, Any]:
    created = parse_dt(alert.get("created_at"))
    remediated = remediation_date(alert)
    state = alert.get("state", "")
    assignees = extract_logins(alert.get("assignees") or []) 

    package_name = (
        safe_get(alert, "dependency", "package", "name", default="")
        or safe_get(alert, "security_vulnerability", "package", "name", default="")
    )
    ecosystem = (
        safe_get(alert, "dependency", "package", "ecosystem", default="")
        or safe_get(alert, "security_vulnerability", "package", "ecosystem", default="")
    )

    severity = (
        safe_get(alert, "security_advisory", "severity", default="") 
        or safe_get(alert, "security_vulnerability", "severity", default="")
    )

    return {
        "id": alert.get("number") or alert.get("id"),
        "type": "dependabot",
        "repo": repo_full,
        "owner": repo_full.split("/", 1)[0],
        "repo_name": repo_full.split("/", 1)[1],
        "state": state,
        "status_group": status_group(state),
        "severity": severity,
        "title": safe_get(alert, "security_advisory", "summary",  default="") or package_name,
        "package": package_name,
        "ecosystem": ecosystem,
        "manifest": safe_get(alert, "dependency", "manifest_path",  default=""),
        "location": "",
        "created_at": created.isoformat() if created else "",
        "updated_at": alert.get("updated_at", ""),
        "remediated_at": remediated.isoformat() if remediated else "",
        "age_days": age_days(created, remediated or now_utc()), 
        "ttr_days": age_days(created, remediated) if remediated else None, 
        "sla_days": sla_days,
        "overdue": status_group(state) == "open" and (age_days(created) or 0) > sla_days,
        "stale": status_group(state) == "open" and (age_days(created) or 0) >= 180,
        "remediator": derive_remediator(alert, assignees),
        "assignees": assignees,
        "resolution": alert.get("dismissed_reason") or ("fixed" if alert.get("fixed_at") else ""),
        "html_url": alert.get("html_url", ""),
        "api_url": alert.get("url", ""),   
    }

def normalize_secret_scanning(alert: Dict[str, Any], repo_full: str, sla_days: int) -> Dict[str, Any]:
    created = parse_dt(alert.get("created_at"))
    remediated = remediation_date(alert)
    state = alert.get("state", "")
    assignees = extract_logins(alert.get("assignees") or []) 
    severity = alert.get("severity") or ("high" if alert.get("is_publicly_leaked") else "")

    return {
        "id": alert.get("number") or alert.get("id"),
        "type": "secret_scanning",
        "repo": repo_full,
        "owner": repo_full.split("/", 1)[0],
        "repo_name": repo_full.split("/", 1)[1],
        "state": state,
        "status_group": status_group(state),
        "severity": severity,
        "title": alert.get("secret_type", ""),
        "package": "",
        "ecosystem": "",
        "manifest": "",
        "location": safe_get(alert, "locations", 0, "details", "path", default=""),
        "created_at": created.isoformat() if created else "",
        "updated_at": alert.get("updated_at", ""),
        "remediated_at": remediated.isoformat() if remediated else "",
        "age_days": age_days(created, remediated or now_utc()), 
        "ttr_days": age_days(created, remediated) if remediated else None, 
        "sla_days": sla_days,
        "overdue": status_group(state) == "open" and (age_days(created) or 0) > sla_days,
        "stale": status_group(state) == "open" and (age_days(created) or 0) >= 180,
        "remediator": derive_remediator(alert, assignees),
        "assignees": assignees,
        "resolution": alert.get("resolution", ""),
        "html_url": alert.get("html_url", ""),
        "api_url": alert.get("url", ""),   
    }

def fetch_code_scanning_alerts(owner: str, repo: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for state in ("open", "closed", "dismissed", "fixed"):
        try:
            data = gh_api(
                f"/repos/{owner}/{repo}/code-scanning/alerts",
                paginate=True,
                params=[f"state={state}", "sort=created", "direction=desc"],
            )
            if isinstance(data, list):
                rows.extend(d for d in data if isinstance(d, dict) and "number" in d)
        except requests.exceptions.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else None
            if code in (403, 404):
                return []
            raise
        except Exception:
            return rows

def fetch_secret_scanning_alerts(owner: str, repo: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for state in ("open", "resolved"):
        try:
            data = gh_api(
                f"/repos/{owner}/{repo}/secret-scanning/alerts",
                paginate=True,
                params=[f"state={state}", "sort=created", "direction=desc"],
            )
            if isinstance(data, list):
                rows.extend(data)
        except requests.exceptions.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else None
            if code in (403, 404):
                return []
            raise
    return rows


def fetch_dependabot_alerts(owner: str, repo: str) -> List[Dict[str, Any]]:
    try:
        session = _get_session()
        rows: List[Dict[str, Any]] = []
        seen = set()

        for state in ("open", "fixed", "dismissed", "auto_dismissed"):
            url = f"https://api.github.com/repos/{owner}/{repo}/dependabot/alerts?state={state}&per_page=100"

            while url:
                try:
                    resp = session.get(url)
                    resp.raise_for_status()
                    data = resp.json()
                    if not isinstance(data, list):
                        break             
                    for item in data:
                        ident = item.get("number") or item.get("id")
                        if ident not in seen:
                            seen.add(ident)
                            rows.append(item)
                    url = _extract_link_rel(resp.headers.get("Link", ""), "next")
                except Exception:
                    url = None
        return rows
    except Exception:
        return []

def build_repo_summary(
    repo_info: Dict[str, Any],
    alert_count_info: Dict[str, Any],
    detail_rows: List[Dict[str, Any]],
    stale_days: int,
) -> Dict[str, Any]:
    owner = safe_get(repo_info, " owner", "login", default="") or (repo_info.get("owner") or {}).get("login", "")
    repo = (
        repo_info.get("name", "") 
        or repo_info.get("repo_name", "") 
        or repo_info.get("repo", "")
    )
    full_name = repo_info.get("full_name", "") or (f"{owner}/{repo}" if owner and repo else "")
    default_branch = repo_info.get("default_branch", "") or "main"

    if (not owner or not repo) and "/" in full_name:
        owner, repo = full_name.split("/", 1)

    protection = {} 
    if owner and repo and default_branch:
        try:
            protection = branch_protection(owner, repo, default_branch)
        except Exception:
            protection = {}

    codeowners = {"present": False, "path": None}
    if owner and repo and default_branch:
        try: 
            codeowners = check_codeowners_exists(owner, repo, default_branch) 
        except Exception:
            codeowners = {"present": False, "path": None}

    try:
        fork_template = fork_and_template_info(repo_info)
    except Exception:
        fork_template = {
            "is_fork": False,
            "fork_source": None,
            "is_generated_from_template": False,
            "template_source": None,
        }

    open_rows = [r for r in detail_rows if r.get("status_group") == "open"]
    closed_rows = [r for r in detail_rows if r.get("status_group") == "closed"]
    overdue_rows = [ r for r in open_rows if r.get("overdue")]
    stale_rows = [r for r in open_rows if(r.get("age_days") or 0) >= stale_days]
    risk_score = sum(severity_weight(r.get("severity", "")) for r in open_rows)

    protection_settings = protection.get("protection_settings") or []
    if not isinstance(protection_settings, list):
            protection_settings = [str(protection_settings)]

    return {
            "repo": full_name,
            "owner": owner,
            "repo_name": repo,
            "visibility": "private" if repo_info.get("private") else "public",
            "archived": repo_info.get("archived", False),
            "default_branch": default_branch,
            "default_branch_protected": protection.get("default_branch_protected"),
            "protect_settings": "|".join(protection.get("protection_settings") or []),
            "codeowners_present": codeowners.get("present"),
            "codeowners_path": codeowners.get("path"),
            "is_fork": fork_template.get("is_fork"),
            "fork_source": fork_template.get("fork_source"),
            "is_generated_from_template": fork_template.get("is_generated_from_template"),
            "template_source": fork_template.get("template_source"),
            "code_scanning_access": alert_count_info.get("code_scanning_access"),
            "code_scanning_alerts": alert_count_info.get("code_scanning_alerts"),
            "dependabot_access": alert_count_info.get("dependabot_access"),
            "dependabot_alerts": alert_count_info.get("dependabot_alerts"),
            "secret_scanning_access": alert_count_info.get("secret_scanning_access"),
            "secret_scanning_alerts": alert_count_info.get("secret_scanning_alerts"),
            "open_alert_rows": len(open_rows),
            "closed_alert_rows": len(closed_rows),
            "overdue_open_alerts": len(overdue_rows),
            "stale_open_alerts": len(stale_rows),
            "risk_score": risk_score,
    }

def build_owner_summary(rows: List[Dict[str, Any]], stale_days: int) -> List[Dict[str, Any]]:
    summary: Dict[str, Dict[str, Any]] = defaultdict (
        lambda: {
            "owner": "", 
            "open_alerts": 0, 
            "closed_alerts": 0, 
            "overdue_open_alerts": 0,
            "stale_open_alerts": 0,
            "remediated_alerts": 0,
            "ttr_values": [],
        }
    )

    for row in rows:
        actor = row.get("remediator") or row.get("assignees") or "unassigned"
        entry = summary[actor]
        entry["owner"] = actor

        if row.get("status_group") == "open":
            entry["open_alerts"] += 1
            if row.get("overdue"):
                entry["overdue_open_alerts"] += 1
            if (row.get("age_days") or 0) >= stale_days:
                entry["stale_open_alerts"] += 1
        else:
            entry["closed_alerts"] += 1
            entry["remediated_alerts"] += 1
            if row.get("ttr_days") is not None:
                entry["ttr_values"].append(row["ttr_days"])

    result: List[Dict[str, Any]] = []
    for actor, item in summary.items():
        ttr_values = item.pop("ttr_values")
        item["avg_ttr_days"] = round(sum(ttr_values) / len(ttr_values), 2) if ttr_values else None
        result.append(item)

    return sorted(result, key=lambda x: (-x["open_alerts"], x["owner"]))
    
    
 
def main() -> None:
    parser = argparse.ArgumentParser(description="MOJ GitHub alert metric discover")
    parser.add_argument("--org", default=os.getenv("GITHUB_ORG", "ministryofjustice"))
    parser.add_argument("--repos", nargs="*", help="Specific repos to scan, e.g owner/repo owner/repo")
    parser.add_argument("--repo-file", help="Text file containing owner/repo entries, one per line")
    parser.add_argument("--limit", type=int, default=400)
    parser.add_argument("--include-archived", action="store_true")
    parser.add_argument("--out-prefix", default="github_alerts")
    parser.add_argument("--code-scanning-sla", type=int, default=14)
    parser.add_argument("--dependabot-sla", type=int, default=30)
    parser.add_argument("--secret-scanning-sla", type=int, default=7)
    parser.add_argument("--stale-days", type=int, default=180)
    parser.add_argument("--db", help="optional SQLite DB path to persist per-repo alert summaries")
    args = parser.parse_args()

    repo_infos = list_target_repos(args)
    if not repo_infos:
        raise SystemExit("No repositories found to scan.")

    if args.db:
        init_db(args.db, table_name="alert_metrics")

    all_rows: List[Dict[str, Any]] = []
    repo_summaries: List[Dict[str, Any]] = []

    total = len(repo_infos)
    for idx, repo_info in enumerate(repo_infos, start=1):
        owner = safe_get(repo_info, "owner", "login", default="")
        repo = repo_info.get("name", "")
        full_name = repo_info.get("full_name", f"{owner}/{repo}")

        print(f"[{idx}/{total}] Scanning {full_name}...", file=sys.stderr)

        # Quick repo-level counts / access map from shared utils
        try:
            counts = count_alerts(owner, repo)
        except Exception as exc:
            print(f"count_alerts fail for {full_name}: {exc}", file=sys.stderr)
            counts = {
                "code_scanning_access": False,
                "code_scanning_alerts": 0,
                "dependabot_access": False,
                "dependabot_alerts": 0,
                "secret_scanning_access": False,
                "secret_scanning_alerts": 0,
            }

        detail_rows: List[Dict[str, Any]] = []

        try:
            code_alerts = fetch_code_scanning_alerts(owner, repo)
            detail_rows.extend(
                normalize_code_scanning(alert, full_name, args.code_scanning_sla)
                for alert in code_alerts
            )
        except Exception as exc:
            print(f"Code scanning detail skipped for {full_name}: {exc}", file=sys.stderr)
        
        try:
            dependabot_alerts = fetch_dependabot_alerts(owner, repo)
            detail_rows.extend(
                normalize_dependabot(alert, full_name, args.code_scanni_sla)
                for alert in dependabot_alerts
            )
        except Exception as exc:
            print(f"Dependabot detail skipped for {full_name}: {exc}", file=sys.stderr)

        try:
            secret_alerts = fetch_secret_scanning_alerts(owner, repo)
            detail_rows.extend(
                normalize_secret_scanning(alert, full_name, args.code_scanning_sla)
                for alert in secret_alerts
            )
        except Exception as exc:
            print(f"Secret scanning detail skipped for {full_name}: {exc}", file=sys.stderr)

        all_rows.extend(detail_rows)
        
        try:
            repo_summary = build_repo_summary(repo_info, counts, detail_rows, args.stale_days)
        except Exception as exc:
            print(f"Repo summary skipped for {full_name}: {exc}", file=sys.stderr)
            repo_summary = {
                "repo": full_name,
                "owner": owner,
                "repo_name": repo,
                "open_alert_rows":len([r for r in detail_rows if r.get("status_group") == "open"]),
                "closed_alert_rows": len([r for r in detail_rows if r.get("status_group") == "closed"]),
                "risk_score":0,
            }
        repo_summaries.append(repo_summary)

    owner_summary = build_owner_summary(all_rows, args.stale_days)

    raw_csv = f"{args.out_prefix}_raw.csv"
    repo_csv = f"{args.out_prefix}_repo_summary.csv"
    owner_csv = f"{args.out_prefix}_owner_summary.csv"

    if not all_rows:
        print("No alert rows collected, writing empty CSV")
    csv_write(raw_csv, all_rows)

    csv_write(repo_csv, repo_summaries)
    csv_write(owner_csv, owner_summary)

    print(f"Done. Wrote {len(all_rows)} alert rows")
    print(f"Wrote {raw_csv}")
    print(f"Wrote {repo_csv}")
    print(f"Wrote {owner_csv}")
    if args.db:
        print(f"Wrote/updated SQLite data in {args.db}")

if __name__ == "__main__":
    main()
