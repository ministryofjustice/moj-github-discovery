"""Common utilities for GitHub repository auditing."""

import json
import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# module‑level globals used to cache the GitHub token and HTTP session
_TOKEN: Optional[str] = None
_SESSION: Optional[requests.Session] = None


def _get_github_token() -> str:
    """Return a GitHub token, caching the result.

    Tokens are first looked up in the environment variable
    ``GITHUB_TOKEN`` (or ``GH_TOKEN``); if absent we fall back to the
    GitHub CLI configuration file.  The value is cached in a module-level
    variable so repeated calls are cheap.
    """
    global _TOKEN
    if _TOKEN:
        return _TOKEN

    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        _TOKEN = token
        return token

    # gh CLI config fallback
    try:
        gh_config_path = os.path.expanduser("~/.config/gh/hosts.yml")
        if os.path.exists(gh_config_path):
            import yaml

            with open(gh_config_path) as f:
                config = yaml.safe_load(f)
                if config and "github.com" in config:
                    oauth_token = config["github.com"].get("oauth_token")
                    if oauth_token:
                        _TOKEN = oauth_token
                        return oauth_token
    except Exception:
        pass

    raise RuntimeError(
        "No GitHub token found. Set GITHUB_TOKEN or GH_TOKEN env var or configure gh CLI."
    )


def _get_session() -> requests.Session:
    """Return a cached ``requests.Session`` configured with auth headers.

    Creating a session once and reusing it avoids repeated TCP handshakes and
    speeds up multiple API calls in a row.
    """
    global _SESSION
    if _SESSION is None:
        token = _get_github_token()
        sess = requests.Session()
        sess.headers.update(
            {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            }
        )
        _SESSION = sess
    return _SESSION


def gh_api(path: str, method: str = "GET", paginate: bool = False, params: Optional[List[str]] = None) -> Any:
    """Invoke the GitHub API and return parsed JSON.

    ``path`` should be the request path (e.g. ``/repos/owner/name``).
    If ``paginate`` is True, the function will follow ``per_page``/``page``
    links until all items are retrieved and return a concatenated list.
    """
    sess = _get_session()
    base_url = "https://api.github.com"

    if not path.startswith("/"):
        path = "/" + path
    url = base_url + path

    # append extra query params if provided
    if params:
        sep = "&" if "?" in url else "?"
        url = url + sep + "&".join(params)

    if paginate:
        results: List[Any] = []
        page = 1
        per_page = 100
        while True:
            sep = "&" if "?" in url else "?"
            paged = f"{url}{sep}per_page={per_page}&page={page}"
            resp = sess.request(method, paged)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                if not data:
                    break
                results.extend(data)
            else:
                results.append(data)
                break
            page += 1
        return results
    else:
        resp = sess.request(method, url)
        resp.raise_for_status()
        data = resp.json()
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


def fork_and_template_info(repo_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract fork source and template source information from repo data.
    
    Args:
        repo_data: Repository metadata dict (from repo_info() or similar)
    
    Returns:
        Dict with keys: is_fork, fork_source, is_generated_from_template, template_source
    """
    info: Dict[str, Any] = {
        "is_fork": False,
        "fork_source": None,
        "is_generated_from_template": False,
        "template_source": None,
    }
    
    # Check if this is a fork
    if repo_data.get("fork") and repo_data.get("parent"):
        info["is_fork"] = True
        parent = repo_data.get("parent", {})
        info["fork_source"] = parent.get("full_name")
    
    # Check if generated from a template
    if repo_data.get("template_repository"):
        info["is_generated_from_template"] = True
        template = repo_data.get("template_repository", {})
        info["template_source"] = template.get("full_name")
    
    return info



def _count_alerts_efficient(owner: str, repo: str, endpoint: str) -> Tuple[int, Optional[str]]:
    """Count alerts efficiently using Link header pagination without fetching all results.
    
    Returns (count, error_kind) where error_kind is None on success, or one of
    {'403', '404', 'other'} on error. Makes only 1 API call instead of many.
    """
    sess = _get_session()
    base_url = "https://api.github.com"
    url = f"{base_url}/repos/{owner}/{repo}/{endpoint}?state=open&per_page=1"
    
    try:
        resp = sess.get(url)
        resp.raise_for_status()
        
        # Check Link header for pagination info
        link_header = resp.headers.get('link', '')
        if 'rel="last"' in link_header:
            # Extract page number from last link: <url?page=N>; rel="last"
            for link_part in link_header.split(','):
                if 'rel="last"' in link_part:
                    try:
                        page_num = int(link_part.split('page=')[-1].split('>')[0])
                        return page_num, None
                    except (ValueError, IndexError):
                        pass
        
        # No "last" link means only 1 page or fewer results
        data = resp.json()
        count = len(data) if isinstance(data, list) else 0
        return count, None
        
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code
        if status == 403:
            return None, "403"
        elif status == 404:
            return 0, "404"
        else:
            return None, str(status)
    except Exception:
        return None, "other"


def _count_alerts_dependabot(owner: str, repo: str) -> Tuple[int, Optional[str]]:
    """Count Dependabot alerts using cursor-based pagination.
    
    Dependabot uses cursor-based pagination (rel="next") instead of page-based.
    Fetch with per_page=100 and follow cursor links to get accurate count.
    
    Returns (count, error_kind) where error_kind is None on success, or one of
    {'403', '404', 'other'} on error.
    """
    sess = _get_session()
    base_url = "https://api.github.com"
    url = f"{base_url}/repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100"
    
    try:
        count = 0
        while url:
            resp = sess.get(url)
            resp.raise_for_status()
            
            data = resp.json()
            if isinstance(data, list):
                count += len(data)
            
            # Check for next page in Link header
            url = None
            link_header = resp.headers.get('link', '')
            if 'rel="next"' in link_header:
                for link_part in link_header.split(','):
                    if 'rel="next"' in link_part:
                        try:
                            url = link_part.split('<')[1].split('>')[0]
                        except (IndexError, ValueError):
                            pass
                        break
        
        return count, None
        
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code
        if status == 403:
            return None, "403"
        elif status == 404:
            return 0, "404"
        else:
            return None, str(status)
    except Exception:
        return None, "other"



def count_alerts(owner: str, repo: str) -> Dict[str, Any]:
    """Count security alerts using appropriate pagination methods.

    - Dependabot: Uses cursor-based pagination (per_page=100, follows rel="next")
    - Code Scanning & Secret Scanning: Use efficient page-based pagination (1 API call)
    
    All three endpoints are queried in parallel.
    Results are stored in ``<name>_access``/``<name>_alerts`` keys.
    Errors are classified to distinguish forbidden vs not found.
    """
    result: Dict[str, Any] = {}

    def _fetch_dependabot() -> None:
        count, err = _count_alerts_dependabot(owner, repo)
        if err is None:
            result["dependabot_access"] = "ok"
            result["dependabot_alerts"] = count
        elif err == "403":
            result["dependabot_access"] = "forbidden"
            result["dependabot_alerts"] = None
        elif err == "404":
            result["dependabot_access"] = "not_found"
            result["dependabot_alerts"] = 0
        else:
            result["dependabot_access"] = err
            result["dependabot_alerts"] = None

    def _fetch_efficient(name: str, endpoint: str) -> None:
        count, err = _count_alerts_efficient(owner, repo, endpoint)
        if err is None:
            result[f"{name}_access"] = "ok"
            result[f"{name}_alerts"] = count
        elif err == "403":
            result[f"{name}_access"] = "forbidden"
            result[f"{name}_alerts"] = None
        elif err == "404":
            result[f"{name}_access"] = "not_found"
            result[f"{name}_alerts"] = 0
        else:
            result[f"{name}_access"] = err
            result[f"{name}_alerts"] = None

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        futures.append(executor.submit(_fetch_dependabot))
        futures.append(executor.submit(_fetch_efficient, "code_scanning", "code-scanning/alerts"))
        futures.append(executor.submit(_fetch_efficient, "secret_scanning", "secret-scanning/alerts"))
        for fut in as_completed(futures):
            pass

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
