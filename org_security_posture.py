"""Organisation-level security posture and operational process audit.

Covers six dimensions that complement the per-repo audits in list_repos.py:

1. Organisation-level settings & permissions
   - Members with 2FA disabled
   - Outside collaborators
   - Teams and their repo access
   - Audit log (recent admin events)

2. GitHub Advanced Security (GHAS)
   - Org-wide code-scanning alerts
   - Org-wide secret-scanning alerts

3. Dependency & supply chain
   - Per-repo SBOM availability
   - Dependabot security-updates enablement

4. Actions & CI/CD operational posture
   - Self-hosted runners
   - Allowed-actions policy
   - Org-level action secrets (names only)
   - Default workflow permissions

5. Webhooks & integrations
   - Org webhooks
   - Installed GitHub Apps

6. Policy-as-code / rulesets
   - Org-level repository rulesets

Usage:
    python org_security_posture.py <org> [--excel path] [--json]
"""

import atexit
import json
import os
import pickle
import sys
import time
from typing import Any, Dict, List, Optional

import requests
from utils import _get_github_token

# Build our own session — completely independent of utils._SESSION
# so we never accidentally go through _request_with_backoff.
_POSTURE_SESSION: Optional[requests.Session] = None


def _get_posture_session() -> requests.Session:
    """Return a dedicated session for this script (no retry adapter)."""
    global _POSTURE_SESSION
    if _POSTURE_SESSION is None:
        token = _get_github_token()
        sess = requests.Session()
        sess.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        })
        _POSTURE_SESSION = sess
    return _POSTURE_SESSION

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── elapsed-time reporting ───────────────────────────────────────────
__start_time: Optional[float] = None


def _report_elapsed() -> None:
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)


atexit.register(_report_elapsed)

API_BASE = "https://api.github.com"
REQUEST_TIMEOUT = 15  # seconds per HTTP request


def _cache_path(org: str) -> str:
    """Return the pickle cache file path for a given org."""
    return os.path.join(SCRIPT_DIR, f".posture_cache_{org}.pkl")


def _load_cache(org: str) -> Dict[str, Any]:
    path = _cache_path(org)
    if os.path.exists(path):
        try:
            with open(path, "rb") as f:
                cache = pickle.load(f)
            age_min = (time.time() - cache.get("_ts", 0)) / 60
            print(f"  Loaded cache ({age_min:.0f} min old): {path}", file=sys.stderr)
            return cache
        except Exception as exc:
            print(f"  Cache load failed: {exc}", file=sys.stderr)
    return {}


def _save_cache(org: str, cache: Dict[str, Any]) -> None:
    cache["_ts"] = time.time()
    path = _cache_path(org)
    with open(path, "wb") as f:
        pickle.dump(cache, f)
    print(f"  Saved cache: {path}", file=sys.stderr)


def _org_api(path: str) -> tuple:
    """Single-shot GitHub API call. No silent retries.

    Returns (json_data, error_kind) where error_kind is None on success,
    or one of '403', '404', 'other'.
    """
    url = API_BASE + (path if path.startswith("/") else "/" + path)
    label = path.split("?")[0]  # strip query params for log readability
    print(f"      GET {label}", file=sys.stderr, flush=True)
    sess = _get_posture_session()
    try:
        resp = sess.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        if resp.status_code == 204:
            return True, None  # success with no body (e.g. vulnerability-alerts)
        return resp.json(), None
    except requests.exceptions.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else 0
        kind = {403: "403", 404: "404"}.get(code, "other")
        print(f"      ← HTTP {code} ({kind})", file=sys.stderr, flush=True)
        return None, kind
    except requests.exceptions.Timeout:
        print(f"      ← TIMEOUT after {REQUEST_TIMEOUT}s", file=sys.stderr, flush=True)
        return None, "other"
    except Exception as exc:
        print(f"      ← ERROR: {exc}", file=sys.stderr, flush=True)
        return None, "other"


# =====================================================================
# 1. Organisation-level settings & permissions
# =====================================================================

def _count_org_members(org: str, max_pages: int = 30) -> Dict[str, Any]:
    """Count total members and public members (works without admin scope)."""
    total = 0
    for page in range(1, max_pages + 1):
        data, err = _org_api(f"/orgs/{org}/members?per_page=100&page={page}")
        if err:
            return {"access": err, "total_members": None, "public_members": None}
        if not isinstance(data, list) or not data:
            break
        total += len(data)
        if len(data) < 100:
            break
    # Public members
    pub_count = 0
    for page in range(1, max_pages + 1):
        data, err = _org_api(f"/orgs/{org}/public_members?per_page=100&page={page}")
        if err:
            break
        if not isinstance(data, list) or not data:
            break
        pub_count += len(data)
        if len(data) < 100:
            break
    return {"access": "ok", "total_members": total, "public_members": pub_count}


def members_without_2fa(org: str) -> Dict[str, Any]:
    """Return members that do not have two-factor authentication enabled."""
    members: List[Dict[str, Any]] = []
    for page in range(1, 6):
        data, err = _org_api(f"/orgs/{org}/members?filter=2fa_disabled&per_page=100&page={page}")
        if err:
            print(f"    access error: {err} (needs admin:org scope)", file=sys.stderr)
            return {"access": err, "members": []}
        if not isinstance(data, list) or not data:
            break
        members.extend(data)
        print(f"    page {page}: {len(data)} members", file=sys.stderr, flush=True)
        if len(data) < 100:
            break
    return {"access": "ok", "members": [{"login": m.get("login"), "id": m.get("id")} for m in members]}


def outside_collaborators(org: str, max_pages: int = 5) -> Dict[str, Any]:
    """Return outside collaborators for the org (capped to avoid runaway pagination)."""
    collabs: List[Dict[str, Any]] = []
    for page in range(1, max_pages + 1):
        data, err = _org_api(f"/orgs/{org}/outside_collaborators?per_page=100&page={page}")
        if err:
            print(f"    access error: {err} (needs Members read scope)", file=sys.stderr)
            return {"access": err, "collaborators": []}
        if not isinstance(data, list) or not data:
            break
        collabs.extend(data)
        print(f"    page {page}: {len(data)} collaborators", file=sys.stderr, flush=True)
        if len(data) < 100:
            break
    return {"access": "ok", "collaborators": [{"login": c.get("login"), "id": c.get("id")} for c in collabs]}


def teams_and_repos(org: str, max_pages: int = 10) -> List[Dict[str, Any]]:
    """Return teams with metadata (uses counts from list endpoint, no per-team repo fetch)."""
    teams: List[Dict[str, Any]] = []
    for page in range(1, max_pages + 1):
        data, err = _org_api(f"/orgs/{org}/teams?per_page=100&page={page}")
        if err:
            print(f"    access error: {err}", file=sys.stderr)
            break
        if not isinstance(data, list) or not data:
            break
        teams.extend(data)
        print(f"    page {page}: {len(data)} teams (total so far: {len(teams)})", file=sys.stderr, flush=True)
        if len(data) < 100:
            break

    return [
        {
            "name": t.get("name"),
            "slug": t.get("slug"),
            "description": t.get("description"),
            "privacy": t.get("privacy"),
            "notification_setting": t.get("notification_setting"),
            "permission": t.get("permission"),
            "parent": t.get("parent", {}).get("name") if t.get("parent") else None,
        }
        for t in teams
    ]


def audit_log_recent(org: str, limit: int = 100) -> Dict[str, Any]:
    """Fetch recent audit log entries (requires org-admin token)."""
    data, err = _org_api(f"/orgs/{org}/audit-log?per_page={min(limit, 100)}&include=all")
    if err:
        print(f"    access error: {err} (requires org admin)", file=sys.stderr)
        return {"access": err, "entries": []}
    if isinstance(data, list):
        return {"access": "ok", "entries": data[:limit]}
    return {"access": "ok", "entries": []}


# =====================================================================
# 2. GitHub Advanced Security (GHAS) — org-wide alerts
# =====================================================================

def org_code_scanning_alerts(org: str, max_pages: int = 10) -> Dict[str, Any]:
    """Fetch org-wide code scanning alert summary (capped pagination)."""
    data, err = _org_api(f"/orgs/{org}/code-scanning/alerts?state=open&per_page=100")
    if err:
        return {"access": err, "open_count": None, "alerts": []}
    if isinstance(data, list):
        alerts = list(data)
        print(f"    page 1: {len(data)} alerts", file=sys.stderr, flush=True)
        page = 2
        while len(data) == 100 and page <= max_pages:
            data, err = _org_api(f"/orgs/{org}/code-scanning/alerts?state=open&per_page=100&page={page}")
            if err or not isinstance(data, list) or not data:
                break
            alerts.extend(data)
            print(f"    page {page}: {len(data)} alerts (total: {len(alerts)})", file=sys.stderr, flush=True)
            page += 1
        truncated = page > max_pages and len(data) == 100
        summary = [
            {
                "rule_id": a.get("rule", {}).get("id"),
                "severity": a.get("rule", {}).get("severity"),
                "repo": a.get("repository", {}).get("full_name"),
                "state": a.get("state"),
            }
            for a in alerts
        ]
        return {"access": "ok", "open_count": len(alerts), "alerts": summary,
                "truncated": truncated}
    return {"access": "ok", "open_count": 0, "alerts": []}


def org_secret_scanning_alerts(org: str, max_pages: int = 10) -> Dict[str, Any]:
    """Fetch org-wide secret scanning alert summary (capped pagination)."""
    data, err = _org_api(f"/orgs/{org}/secret-scanning/alerts?state=open&per_page=100")
    if err:
        return {"access": err, "open_count": None, "alerts": []}
    if isinstance(data, list):
        alerts = list(data)
        print(f"    page 1: {len(data)} alerts", file=sys.stderr, flush=True)
        page = 2
        while len(data) == 100 and page <= max_pages:
            data, err = _org_api(f"/orgs/{org}/secret-scanning/alerts?state=open&per_page=100&page={page}")
            if err or not isinstance(data, list) or not data:
                break
            alerts.extend(data)
            print(f"    page {page}: {len(data)} alerts (total: {len(alerts)})", file=sys.stderr, flush=True)
            page += 1
        truncated = page > max_pages and len(data) == 100
        summary = [
            {
                "secret_type": a.get("secret_type_display_name") or a.get("secret_type"),
                "repo": a.get("repository", {}).get("full_name"),
                "state": a.get("state"),
                "created_at": a.get("created_at"),
            }
            for a in alerts
        ]
        return {"access": "ok", "open_count": len(alerts), "alerts": summary,
                "truncated": truncated}
    return {"access": "ok", "open_count": 0, "alerts": []}


# =====================================================================
# 3. Dependency & supply chain
# =====================================================================

def dependency_supply_chain(org: str, repo_limit: int = 100) -> Dict[str, Any]:
    """Check SBOM availability and branch protection on the most recently
    pushed repos.  Uses only endpoints that work with a member token:
      - /repos/.../dependency-graph/sbom  (needs contents:read)
      - /repos/.../branches/{branch}      (needs read access)
    """
    cap = min(repo_limit, 100)  # never fetch more than 1 page
    repos, err = _org_api(f"/orgs/{org}/repos?per_page={cap}&page=1&sort=pushed&direction=desc")
    if err or not isinstance(repos, list):
        print(f"    error listing repos: {err}", file=sys.stderr)
        return {"repos_checked": 0, "sbom_available": 0, "default_branch_protected": 0, "details": []}

    details: List[Dict[str, Any]] = []
    for i, repo in enumerate(repos):
        owner = repo.get("owner", {}).get("login", "")
        name = repo.get("name", "")
        full_name = f"{owner}/{name}"
        default_branch = repo.get("default_branch", "main")
        visibility = repo.get("visibility", "")
        archived = repo.get("archived", False)
        license_id = (repo.get("license") or {}).get("spdx_id", "none")
        topics = repo.get("topics", [])

        # SBOM check (works with member token)
        _, sbom_err = _org_api(f"/repos/{owner}/{name}/dependency-graph/sbom")
        sbom_ok = sbom_err is None

        # Branch protection via branch endpoint (works with read access)
        # NOTE: /branches/{branch}/protection requires admin — but
        #       /branches/{branch} returns a `protected` boolean for any reader.
        bp_data, bp_err = _org_api(f"/repos/{owner}/{name}/branches/{default_branch}")
        bp_protected = False
        if bp_err is None and isinstance(bp_data, dict):
            bp_protected = bp_data.get("protected", False)

        details.append({
            "repo": full_name,
            "visibility": visibility,
            "archived": archived,
            "default_branch": default_branch,
            "license": license_id,
            "topics": ", ".join(topics) if topics else "",
            "sbom_available": sbom_ok,
            "default_branch_protected": bp_protected,
        })
        if (i + 1) % 10 == 0:
            print(f"    checked {i + 1}/{len(repos)} repos", file=sys.stderr, flush=True)

    return {
        "repos_checked": len(details),
        "sbom_available": sum(1 for d in details if d["sbom_available"]),
        "default_branch_protected": sum(1 for d in details if d["default_branch_protected"]),
        "details": details,
    }


# =====================================================================
# 4. Actions & CI/CD operational posture
# =====================================================================

def actions_posture(org: str) -> Dict[str, Any]:
    """Gather Actions configuration: runners, permissions, secrets."""
    result: Dict[str, Any] = {}

    # Self-hosted runners
    runners_data, runners_err = _org_api(f"/orgs/{org}/actions/runners")
    if runners_err:
        result["runners"] = {"access": runners_err, "total_count": None, "runners": []}
    elif isinstance(runners_data, dict):
        result["runners"] = {
            "access": "ok",
            "total_count": runners_data.get("total_count", 0),
            "runners": [
                {
                    "name": r.get("name"),
                    "os": r.get("os"),
                    "status": r.get("status"),
                    "busy": r.get("busy"),
                    "labels": [lb.get("name") for lb in r.get("labels", [])],
                }
                for r in runners_data.get("runners", [])
            ],
        }
    else:
        result["runners"] = {"access": "ok", "total_count": 0, "runners": []}

    # Allowed actions policy
    perms_data, perms_err = _org_api(f"/orgs/{org}/actions/permissions")
    if perms_err:
        result["actions_permissions"] = {"access": perms_err}
    elif isinstance(perms_data, dict):
        result["actions_permissions"] = {
            "access": "ok",
            "enabled_repositories": perms_data.get("enabled_repositories"),
            "allowed_actions": perms_data.get("allowed_actions"),
            "sha_pinning_required": perms_data.get("sha_pinning_required"),
        }
    else:
        result["actions_permissions"] = {"access": "ok"}

    # Org-level secrets (names only)
    secrets_data, secrets_err = _org_api(f"/orgs/{org}/actions/secrets")
    if secrets_err:
        result["secrets"] = {"access": secrets_err, "total_count": None, "names": []}
    elif isinstance(secrets_data, dict):
        result["secrets"] = {
            "access": "ok",
            "total_count": secrets_data.get("total_count", 0),
            "names": [s.get("name") for s in secrets_data.get("secrets", [])],
        }
    else:
        result["secrets"] = {"access": "ok", "total_count": 0, "names": []}

    # Default workflow permissions
    wf_perms_data, wf_perms_err = _org_api(f"/orgs/{org}/actions/permissions/workflow")
    if wf_perms_err:
        result["default_workflow_permissions"] = {"access": wf_perms_err}
    elif isinstance(wf_perms_data, dict):
        result["default_workflow_permissions"] = {
            "access": "ok",
            "default_workflow_permissions": wf_perms_data.get("default_workflow_permissions"),
            "can_approve_pull_request_reviews": wf_perms_data.get("can_approve_pull_request_reviews"),
        }
    else:
        result["default_workflow_permissions"] = {"access": "ok"}

    return result


# =====================================================================
# 5. Webhooks & integrations
# =====================================================================

def webhooks_and_integrations(org: str) -> Dict[str, Any]:
    """List org webhooks and installed GitHub Apps."""
    result: Dict[str, Any] = {}

    # Org webhooks
    hooks_data, hooks_err = _org_api(f"/orgs/{org}/hooks")
    if hooks_err:
        result["webhooks"] = {"access": hooks_err, "count": None, "hooks": []}
    elif isinstance(hooks_data, list):
        result["webhooks"] = {
            "access": "ok",
            "count": len(hooks_data),
            "hooks": [
                {
                    "id": h.get("id"),
                    "name": h.get("name"),
                    "active": h.get("active"),
                    "events": h.get("events"),
                    "config_url": h.get("config", {}).get("url"),
                }
                for h in hooks_data
            ],
        }
    else:
        result["webhooks"] = {"access": "ok", "count": 0, "hooks": []}

    # Installed GitHub Apps
    installs_data, installs_err = _org_api(f"/orgs/{org}/installations")
    if installs_err:
        result["github_apps"] = {"access": installs_err, "total_count": None, "apps": []}
    elif isinstance(installs_data, dict):
        result["github_apps"] = {
            "access": "ok",
            "total_count": installs_data.get("total_count", 0),
            "apps": [
                {
                    "app_slug": inst.get("app_slug"),
                    "app_id": inst.get("app_id"),
                    "target_type": inst.get("target_type"),
                    "permissions": inst.get("permissions"),
                    "events": inst.get("events"),
                    "repository_selection": inst.get("repository_selection"),
                }
                for inst in installs_data.get("installations", [])
            ],
        }
    else:
        result["github_apps"] = {"access": "ok", "total_count": 0, "apps": []}

    return result


# =====================================================================
# 6. Policy-as-code / rulesets
# =====================================================================

def org_rulesets(org: str) -> Dict[str, Any]:
    """Fetch org-level repository rulesets."""
    data, err = _org_api(f"/orgs/{org}/rulesets")
    if err:
        return {"access": err, "count": None, "rulesets": []}
    if isinstance(data, list):
        return {
            "access": "ok",
            "count": len(data),
            "rulesets": [
                {
                    "id": rs.get("id"),
                    "name": rs.get("name"),
                    "target": rs.get("target"),
                    "enforcement": rs.get("enforcement"),
                    "source_type": rs.get("source_type"),
                }
                for rs in data
            ],
        }
    return {"access": "ok", "count": 0, "rulesets": []}


# =====================================================================
# Aggregation & output
# =====================================================================

def run_full_audit(org: str, repo_sample_limit: int = 100, use_cache: bool = True) -> Dict[str, Any]:
    """Execute all six audit dimensions and return a combined report.

    Completed sections are cached to disk so a killed/resumed run picks up
    where it left off.  Pass ``use_cache=False`` to force a fresh run.
    """
    cache = _load_cache(org) if use_cache else {}
    report: Dict[str, Any] = {"org": org, "audited_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # Org overview (always fetch, cheap single call)
    print("\n── org_overview ──", file=sys.stderr, flush=True)
    org_data, org_err = _org_api(f"/orgs/{org}")
    if org_err is None and isinstance(org_data, dict):
        def _get(key: str, admin_only: bool = False):
            """Get a field, returning 'admin_only' marker if key missing and admin_only=True."""
            if key in org_data:
                return org_data[key]
            return "requires_admin_token" if admin_only else None

        report["org_overview"] = {
            "name": _get("name"),
            "description": _get("description"),
            "blog": _get("blog"),
            "public_repos": _get("public_repos"),
            "total_private_repos": _get("total_private_repos"),
            "owned_private_repos": _get("owned_private_repos"),
            "followers": _get("followers"),
            "created_at": _get("created_at"),
            "updated_at": _get("updated_at"),
            # Security-critical org settings (admin-only fields marked)
            "two_factor_requirement_enabled": _get("two_factor_requirement_enabled", admin_only=True),
            "default_repository_permission": _get("default_repository_permission", admin_only=True),
            "default_repository_branch": _get("default_repository_branch"),
            "members_can_create_repositories": _get("members_can_create_repositories"),
            "members_can_create_public_repositories": _get("members_can_create_public_repositories"),
            "members_can_create_private_repositories": _get("members_can_create_private_repositories"),
            "members_can_create_internal_repositories": _get("members_can_create_internal_repositories"),
            "members_can_fork_private_repositories": _get("members_can_fork_private_repositories"),
            "members_can_delete_repositories": _get("members_can_delete_repositories"),
            "members_can_change_repo_visibility": _get("members_can_change_repo_visibility"),
            "members_can_invite_outside_collaborators": _get("members_can_invite_outside_collaborators"),
            "members_can_create_pages": _get("members_can_create_pages"),
            "members_can_create_public_pages": _get("members_can_create_public_pages"),
            "members_can_create_private_pages": _get("members_can_create_private_pages"),
            "members_can_delete_issues": _get("members_can_delete_issues"),
            "members_can_create_teams": _get("members_can_create_teams"),
            "members_can_view_dependency_insights": _get("members_can_view_dependency_insights"),
            "web_commit_signoff_required": _get("web_commit_signoff_required"),
            "deploy_keys_enabled_for_repositories": _get("deploy_keys_enabled_for_repositories"),
            # GHAS / security features for new repos (admin-only)
            "advanced_security_enabled_for_new_repositories": _get("advanced_security_enabled_for_new_repositories", admin_only=True),
            "dependency_graph_enabled_for_new_repositories": _get("dependency_graph_enabled_for_new_repositories", admin_only=True),
            "dependabot_alerts_enabled_for_new_repositories": _get("dependabot_alerts_enabled_for_new_repositories", admin_only=True),
            "dependabot_security_updates_enabled_for_new_repositories": _get("dependabot_security_updates_enabled_for_new_repositories", admin_only=True),
            "secret_scanning_enabled_for_new_repositories": _get("secret_scanning_enabled_for_new_repositories", admin_only=True),
            "secret_scanning_push_protection_enabled_for_new_repositories": _get("secret_scanning_push_protection_enabled_for_new_repositories", admin_only=True),
            "secret_scanning_push_protection_custom_link_enabled": _get("secret_scanning_push_protection_custom_link_enabled", admin_only=True),
            "secret_scanning_push_protection_custom_link": _get("secret_scanning_push_protection_custom_link", admin_only=True),
            "plan": _get("plan"),
        }
    else:
        report["org_overview"] = {"access": org_err or "error"}

    sections = {
        "1_org_settings": [
            ("total_members", lambda: _count_org_members(org)),
            ("members_without_2fa", lambda: members_without_2fa(org)),
            ("outside_collaborators", lambda: outside_collaborators(org)),
            ("teams", lambda: teams_and_repos(org)),
            ("audit_log_recent", lambda: audit_log_recent(org)),
        ],
        "2_ghas_alerts": [
            ("code_scanning", lambda: org_code_scanning_alerts(org)),
            ("secret_scanning", lambda: org_secret_scanning_alerts(org)),
        ],
        "3_dependency_supply_chain": [
            ("summary", lambda: dependency_supply_chain(org, repo_sample_limit)),
        ],
        "4_actions_posture": [
            ("details", lambda: actions_posture(org)),
        ],
        "5_webhooks_integrations": [
            ("details", lambda: webhooks_and_integrations(org)),
        ],
        "6_rulesets": [
            ("details", lambda: org_rulesets(org)),
        ],
    }

    for section_key, tasks in sections.items():
        # Use cached section if available
        if section_key in cache:
            print(f"\n── {section_key} ── (cached)", file=sys.stderr)
            report[section_key] = cache[section_key]
            continue

        print(f"\n── {section_key} ──", file=sys.stderr)
        section_data: Dict[str, Any] = {}
        for task_name, fn in tasks:
            t0 = time.monotonic()
            print(f"  → {task_name} ...", file=sys.stderr, flush=True)
            try:
                section_data[task_name] = fn()
            except Exception as exc:
                print(f"    ERROR: {exc}", file=sys.stderr)
                section_data[task_name] = {"error": str(exc)}
            print(f"    done ({time.monotonic() - t0:.1f}s)", file=sys.stderr, flush=True)
        report[section_key] = section_data

        # Save after each section so progress survives a kill
        cache[section_key] = section_data
        _save_cache(org, cache)

    return report


def _val_or_no_access(data: Dict[str, Any], key: str) -> Any:
    """Return value if accessible, otherwise 'no_access (needs admin token)'."""
    access = data.get("access")
    if access and access != "ok":
        return f"no_access ({access})"
    val = data.get(key)
    return val if val is not None else 0


def _build_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    """Build a high-level summary dict from the full report."""
    overview = report.get("org_overview", {})
    org_settings = report.get("1_org_settings", {})
    ghas = report.get("2_ghas_alerts", {})
    deps = report.get("3_dependency_supply_chain", {}).get("summary", {})
    actions = report.get("4_actions_posture", {}).get("details", {})
    webhooks = report.get("5_webhooks_integrations", {}).get("details", {})
    rulesets = report.get("6_rulesets", {}).get("details", {})

    summary: Dict[str, Any] = {}

    # Org overview
    if overview.get("access") is None:  # no access key = successful fetch
        summary["org_name"] = overview.get("name", "")
        summary["public_repos"] = overview.get("public_repos")
        summary["total_private_repos"] = overview.get("total_private_repos", "no_access")
        summary["2fa_requirement_enabled"] = overview.get("two_factor_requirement_enabled")
        summary["default_repo_permission"] = overview.get("default_repository_permission")
        summary["default_branch"] = overview.get("default_repository_branch")
        summary["members_can_create_public_repos"] = overview.get("members_can_create_public_repositories")
        summary["members_can_create_private_repos"] = overview.get("members_can_create_private_repositories")
        summary["members_can_fork_private_repos"] = overview.get("members_can_fork_private_repositories")
        summary["members_can_delete_repos"] = overview.get("members_can_delete_repositories")
        summary["members_can_change_visibility"] = overview.get("members_can_change_repo_visibility")
        summary["members_can_invite_outside_collabs"] = overview.get("members_can_invite_outside_collaborators")
        summary["web_commit_signoff_required"] = overview.get("web_commit_signoff_required")
        summary["deploy_keys_enabled_for_repos"] = overview.get("deploy_keys_enabled_for_repositories")
        summary["advanced_security_new_repos"] = overview.get("advanced_security_enabled_for_new_repositories")
        summary["dependency_graph_new_repos"] = overview.get("dependency_graph_enabled_for_new_repositories")
        summary["dependabot_alerts_new_repos"] = overview.get("dependabot_alerts_enabled_for_new_repositories")
        summary["dependabot_security_updates_new_repos"] = overview.get("dependabot_security_updates_enabled_for_new_repositories")
        summary["secret_scanning_new_repos"] = overview.get("secret_scanning_enabled_for_new_repositories")
        summary["secret_scanning_push_protection_new_repos"] = overview.get("secret_scanning_push_protection_enabled_for_new_repositories")

    # Org settings
    total_members = org_settings.get("total_members", {})
    summary["total_members"] = _val_or_no_access(total_members, "total_members") if isinstance(total_members, dict) else "no_access"
    summary["public_members"] = total_members.get("public_members") if isinstance(total_members, dict) and total_members.get("access") == "ok" else "no_access"

    mfa_data = org_settings.get("members_without_2fa", {})
    if isinstance(mfa_data, dict):
        summary["members_without_2fa"] = _val_or_no_access(mfa_data, "members") if mfa_data.get("access") != "ok" else len(mfa_data.get("members", []))
    else:
        summary["members_without_2fa"] = "no_access"

    collabs_data = org_settings.get("outside_collaborators", {})
    if isinstance(collabs_data, dict):
        summary["outside_collaborators"] = _val_or_no_access(collabs_data, "collaborators") if collabs_data.get("access") != "ok" else len(collabs_data.get("collaborators", []))
    else:
        summary["outside_collaborators"] = "no_access"

    teams = org_settings.get("teams", [])
    summary["teams_count"] = len(teams) if isinstance(teams, list) else "no_access"

    audit_data = org_settings.get("audit_log_recent", {})
    if isinstance(audit_data, dict):
        summary["audit_log_entries_fetched"] = _val_or_no_access(audit_data, "entries") if audit_data.get("access") != "ok" else len(audit_data.get("entries", []))
    else:
        summary["audit_log_entries_fetched"] = "no_access"

    # GHAS
    summary["code_scanning_open_alerts"] = _val_or_no_access(ghas.get("code_scanning", {}), "open_count")
    summary["secret_scanning_open_alerts"] = _val_or_no_access(ghas.get("secret_scanning", {}), "open_count")

    # Supply chain + repo-level security
    summary["repos_checked_for_supply_chain"] = deps.get("repos_checked", 0)
    summary["repos_with_sbom"] = deps.get("sbom_available", 0)
    summary["repos_with_branch_protection"] = deps.get("default_branch_protected", 0)

    # Actions
    summary["self_hosted_runners"] = _val_or_no_access(actions.get("runners", {}), "total_count")
    summary["allowed_actions_policy"] = _val_or_no_access(actions.get("actions_permissions", {}), "allowed_actions")
    summary["sha_pinning_required"] = _val_or_no_access(actions.get("actions_permissions", {}), "sha_pinning_required")
    summary["org_secrets_count"] = _val_or_no_access(actions.get("secrets", {}), "total_count")
    summary["default_workflow_permissions"] = _val_or_no_access(
        actions.get("default_workflow_permissions", {}), "default_workflow_permissions"
    )

    # Webhooks
    summary["org_webhooks_count"] = _val_or_no_access(webhooks.get("webhooks", {}), "count")
    summary["installed_github_apps"] = _val_or_no_access(webhooks.get("github_apps", {}), "total_count")

    # Rulesets
    summary["org_rulesets_count"] = _val_or_no_access(rulesets, "count")

    return summary


def write_excel(report: Dict[str, Any], path: str) -> None:
    """Write the audit report to a multi-sheet Excel workbook."""
    import pandas as pd

    summary = _build_summary(report)
    summary_df = pd.DataFrame(list(summary.items()), columns=["metric", "value"])

    # Org overview
    overview = report.get("org_overview", {})
    if overview and overview.get("access") is None:
        overview_df = pd.DataFrame(list(overview.items()), columns=["setting", "value"])
    else:
        overview_df = pd.DataFrame()

    org_settings = report.get("1_org_settings", {})

    # Members without 2FA (now returns dict with 'members' key)
    mfa_raw = org_settings.get("members_without_2fa", {})
    mfa_list = mfa_raw.get("members", []) if isinstance(mfa_raw, dict) else []
    mfa_df = pd.DataFrame(mfa_list) if mfa_list else pd.DataFrame()

    # Outside collaborators (now returns dict with 'collaborators' key)
    collabs_raw = org_settings.get("outside_collaborators", {})
    collabs_list = collabs_raw.get("collaborators", []) if isinstance(collabs_raw, dict) else []
    collabs_df = pd.DataFrame(collabs_list) if collabs_list else pd.DataFrame()

    # Teams
    teams_raw = org_settings.get("teams", [])
    teams_flat = [
        {"name": t.get("name"), "slug": t.get("slug"), "description": t.get("description"),
         "privacy": t.get("privacy"), "notification_setting": t.get("notification_setting"),
         "permission": t.get("permission"), "parent": t.get("parent")}
        for t in teams_raw
    ]
    teams_df = pd.DataFrame(teams_flat) if teams_flat else pd.DataFrame()

    # GHAS alerts
    ghas = report.get("2_ghas_alerts", {})
    code_alerts = ghas.get("code_scanning", {}).get("alerts", [])
    code_df = pd.DataFrame(code_alerts) if code_alerts else pd.DataFrame()
    secret_alerts = ghas.get("secret_scanning", {}).get("alerts", [])
    secret_df = pd.DataFrame(secret_alerts) if secret_alerts else pd.DataFrame()

    # Supply chain
    deps = report.get("3_dependency_supply_chain", {}).get("summary", {})
    deps_details = deps.get("details", [])
    deps_df = pd.DataFrame(deps_details) if deps_details else pd.DataFrame()

    # Actions
    actions = report.get("4_actions_posture", {}).get("details", {})
    runners = actions.get("runners", {}).get("runners", [])
    runners_df = pd.DataFrame(runners) if runners else pd.DataFrame()

    secrets_names = actions.get("secrets", {}).get("names", [])
    secrets_df = pd.DataFrame({"secret_name": secrets_names}) if secrets_names else pd.DataFrame()

    # Webhooks
    wh = report.get("5_webhooks_integrations", {}).get("details", {})
    hooks = wh.get("webhooks", {}).get("hooks", [])
    hooks_df = pd.DataFrame(hooks) if hooks else pd.DataFrame()

    apps = wh.get("github_apps", {}).get("apps", [])
    apps_df = pd.DataFrame(apps) if apps else pd.DataFrame()

    # Rulesets
    rulesets = report.get("6_rulesets", {}).get("details", {}).get("rulesets", [])
    rulesets_df = pd.DataFrame(rulesets) if rulesets else pd.DataFrame()

    try:
        with pd.ExcelWriter(path, engine="openpyxl") as writer:
            summary_df.to_excel(writer, index=False, sheet_name="Summary")
            if not overview_df.empty:
                overview_df.to_excel(writer, index=False, sheet_name="Org Settings")
            if not mfa_df.empty:
                mfa_df.to_excel(writer, index=False, sheet_name="2FA Disabled")
            if not collabs_df.empty:
                collabs_df.to_excel(writer, index=False, sheet_name="Outside Collaborators")
            if not teams_df.empty:
                teams_df.to_excel(writer, index=False, sheet_name="Teams")
            if not code_df.empty:
                code_df.to_excel(writer, index=False, sheet_name="Code Scanning Alerts")
            if not secret_df.empty:
                secret_df.to_excel(writer, index=False, sheet_name="Secret Scanning Alerts")
            if not deps_df.empty:
                deps_df.to_excel(writer, index=False, sheet_name="Supply Chain")
            if not runners_df.empty:
                runners_df.to_excel(writer, index=False, sheet_name="Runners")
            if not secrets_df.empty:
                secrets_df.to_excel(writer, index=False, sheet_name="Org Secrets")
            if not hooks_df.empty:
                hooks_df.to_excel(writer, index=False, sheet_name="Webhooks")
            if not apps_df.empty:
                apps_df.to_excel(writer, index=False, sheet_name="GitHub Apps")
            if not rulesets_df.empty:
                rulesets_df.to_excel(writer, index=False, sheet_name="Rulesets")
        print(f"Wrote {path}", file=sys.stderr)
    except ImportError:
        print("Excel export requires openpyxl and pandas.\n"
              "Install with: pip install openpyxl pandas", file=sys.stderr)
        sys.exit(1)


# =====================================================================
# CLI
# =====================================================================

def main() -> None:
    global __start_time
    __start_time = time.monotonic()

    if len(sys.argv) < 2:
        print("Usage: python org_security_posture.py <org> [--excel path] [--json] [--repo-limit N] [--no-cache]")
        sys.exit(2)

    org = sys.argv[1]
    excel_path: Optional[str] = None
    output_json = False
    repo_limit = 100
    use_cache = True

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--excel" and i + 1 < len(sys.argv):
            excel_path = sys.argv[i + 1]
            i += 2
        elif arg == "--json":
            output_json = True
            i += 1
        elif arg == "--repo-limit" and i + 1 < len(sys.argv):
            repo_limit = int(sys.argv[i + 1])
            i += 2
        elif arg == "--no-cache":
            use_cache = False
            i += 1
        else:
            print(f"Unknown argument: {arg}", file=sys.stderr)
            i += 1

    print(f"Running org security posture audit for: {org}", file=sys.stderr)
    report = run_full_audit(org, repo_sample_limit=repo_limit, use_cache=use_cache)

    summary = _build_summary(report)
    print("\n═══ SECURITY POSTURE SUMMARY ═══", file=sys.stderr)
    for k, v in summary.items():
        print(f"  {k}: {v}", file=sys.stderr)

    if excel_path:
        write_excel(report, excel_path)

    if output_json or (not excel_path):
        print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
