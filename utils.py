"""Common utilities for GitHub repository auditing."""

import json
import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

import requests


def _get_github_token() -> str:
    """Get GitHub token from environment or gh CLI config."""
    # First try GITHUB_TOKEN env var
    token = os.getenv("GITHUB_TOKEN")
    if token:
        return token
    
    # Try to read from gh CLI config
    try:
        gh_config_path = os.path.expanduser("~/.config/gh/hosts.yml")
        if os.path.exists(gh_config_path):
            import yaml
            with open(gh_config_path) as f:
                config = yaml.safe_load(f)
                if config and "github.com" in config:
                    oauth_token = config["github.com"].get("oauth_token")
                    if oauth_token:
                        return oauth_token
    except Exception:
        pass
    
    raise RuntimeError(
        "No GitHub token found. Set GITHUB_TOKEN env var or configure gh CLI."
    )


def gh_api(path: str, method: str = "GET", paginate: bool = False, params: Optional[List[str]] = None) -> Any:
    """Call GitHub API via requests and parse JSON."""
    token = _get_github_token()
    base_url = "https://api.github.com"
    
    # Ensure path starts with /
    if not path.startswith("/"):
        path = "/" + path
    
    url = base_url + path
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    
    # Handle pagination
    if paginate:
        all_results = []
        page = 1
        per_page = 100
        
        while True:
            # Add pagination params to URL
            separator = "&" if "?" in url else "?"
            paginated_url = f"{url}{separator}per_page={per_page}&page={page}"
            
            response = requests.request(method, paginated_url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            if isinstance(data, list):
                if not data:
                    break
                all_results.extend(data)
            else:
                all_results.append(data)
                break
            
            page += 1
        
        return all_results
    else:
        response = requests.request(method, url, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        return data if data else None


def try_get(path: str) -> Tuple[Optional[Any], Optional[str]]:
    """Return (json, error_kind). error_kind in {'404','403','other'} or None."""
    try:
        return gh_api(path), None
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return None, "404"
        if e.response.status_code == 403:
            return None, "403"
        return None, "other"
    except Exception:
        return None, "other"


def count_alerts(owner: str, repo: str) -> Dict[str, Any]:
    """Count security alerts.

    The previous implementation fetched only the first page of results
    (`per_page=100`) which meant repos with more than 100 alerts returned
    an incorrect count.  In addition we now filter to *open* alerts since
    closed/fixed alerts are less interesting for most audits.

    The function calls the three relevant endpoints and uses the
    ``paginate`` flag of ``gh_api`` to transparently follow GitHub's
    pagination links until all items have been collected.  We also capture
    HTTP errors so that callers can distinguish a lack of permissions
    against other failures.
    """
    result: Dict[str, Any] = {}

    def fetch(name: str, endpoint: str):
        """Helper that populates access/alerts keys for a given endpoint."""
        try:
            # include state=open to count only active alerts
            items = gh_api(f"/repos/{owner}/{repo}/{endpoint}?state=open", paginate=True)
            count = len(items) if isinstance(items, list) else 0
            result[f"{name}_access"] = "ok"
            result[f"{name}_alerts"] = count
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code
            if status == 403:
                result[f"{name}_access"] = "forbidden"
                result[f"{name}_alerts"] = None
            elif status == 404:
                # endpoint missing (e.g. Dependabot disabled)
                result[f"{name}_access"] = "not_found"
                result[f"{name}_alerts"] = 0
            else:
                result[f"{name}_access"] = str(status)
                result[f"{name}_alerts"] = None
        except Exception:
            result[f"{name}_access"] = "error"
            result[f"{name}_alerts"] = None

    # dependabot alerts
    fetch("dependabot", "dependabot/alerts")
    # code scanning alerts
    fetch("code_scanning", "code-scanning/alerts")
    # secret scanning alerts
    fetch("secret_scanning", "secret-scanning/alerts")

    return result


def branch_protection(owner: str, repo: str, default_branch: str) -> Dict[str, Any]:
    """Check if the default branch is protected.

    The previous implementation used the ``/protection`` sub-endpoint, which
    requires admin privileges and therefore returned "forbidden" for most
    read-only tokens.  The public ``/branches/{branch}`` endpoint includes a
    ``protected`` boolean and works with any authenticated (or even unauthenticated)
    request, so it gives a more accurate answer for auditing purposes.
    """
    data, err = try_get(f"/repos/{owner}/{repo}/branches/{default_branch}")
    if err == "404":
        # branch not found; treat as unprotected
        return {"default_branch_protected": False}
    if err == "403":
        # unlikely on this endpoint, but handle gracefully
        return {"default_branch_protected": None, "branch_protection_access": "forbidden"}
    if err is None:
        # data should be a dict with `protected` and optional `protection`.
        protected = False
        details: Optional[Dict[str, Any]] = None
        if isinstance(data, dict):
            protected = bool(data.get("protected"))
            details = data.get("protection")

        result: Dict[str, Any] = {"default_branch_protected": protected}
        if details:
            # build a concise list of protections that are actually enabled
            flags: List[str] = []
            # required status checks
            rsc = details.get("required_status_checks") or {}
            if rsc.get("enforcement_level") not in (None, "off"):
                flags.append("required_status_checks")
            # pull request review rules
            if details.get("required_pull_request_reviews"):
                flags.append("required_pull_request_reviews")
            # admin enforcement
            if details.get("enforce_admins", {}).get("enabled"):
                flags.append("enforce_admins")
            # push restrictions (users/teams/apps)
            restr = details.get("restrictions") or {}
            if restr.get("users") or restr.get("teams") or restr.get("apps"):
                flags.append("restrictions")
            # linear history, force pushes, deletions
            if details.get("required_linear_history", {}).get("enabled"):
                flags.append("required_linear_history")
            if details.get("allow_force_pushes", {}).get("enabled"):
                flags.append("allow_force_pushes")
            if details.get("allow_deletions", {}).get("enabled"):
                flags.append("allow_deletions")

            result["protection_settings"] = flags
        return result
    return {"default_branch_protected": None, "branch_protection_access": err}


def init_db(db_path: str, table_name: str = "audits") -> None:
    """Initialize SQLite database with a table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            full_name TEXT PRIMARY KEY,
            audit_json TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_to_db(db_path: str, full_name: str, data: Dict[str, Any], table_name: str = "audits") -> None:
    """Upsert data into SQLite database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        f"INSERT OR REPLACE INTO {table_name} (full_name, audit_json) VALUES (?, ?)",
        (full_name, json.dumps(data))
    )
    conn.commit()
    conn.close()
