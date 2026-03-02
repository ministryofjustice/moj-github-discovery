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


def count_alerts(owner: str, repo: str) -> Dict[str, Any]:
    """Count security alerts.

    Three endpoints are queried in parallel; each fetches *open* alerts with
    pagination.  Results are stored in ``<name>_access``/``<name>_alerts``
    keys.  Errors are classified to distinguish forbidden vs not found.
    """
    result: Dict[str, Any] = {}

    def _fetch(name: str, endpoint: str) -> None:
        try:
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
                result[f"{name}_access"] = "not_found"
                result[f"{name}_alerts"] = 0
            else:
                result[f"{name}_access"] = str(status)
                result[f"{name}_alerts"] = None
        except Exception:
            result[f"{name}_access"] = "error"
            result[f"{name}_alerts"] = None

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        futures.append(executor.submit(_fetch, "dependabot", "dependabot/alerts"))
        futures.append(executor.submit(_fetch, "code_scanning", "code-scanning/alerts"))
        futures.append(executor.submit(_fetch, "secret_scanning", "secret-scanning/alerts"))
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


def get_full_branch_protection(owner: str, repo: str, branch: str) -> Dict[str, Any]:
    """Call the protected-branch `/protection` endpoint and return all fields.

    This endpoint requires elevated permissions for some fields and may
    return HTTP 403 for read-only tokens. The function returns a dict with
    the raw protection data when successful, or a structured error value.
    """
    try:
        data = gh_api(f"/repos/{owner}/{repo}/branches/{branch}/protection")
        # return raw payload under a consistent key
        return {"ok": True, "protection": data}
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if getattr(e, 'response', None) is not None else None
        if status == 403:
            return {"ok": False, "error": "forbidden", "status": 403}
        if status == 404:
            return {"ok": False, "error": "not_found", "status": 404}
        return {"ok": False, "error": "http_error", "status": status}
    except Exception as e:
        return {"ok": False, "error": "error", "reason": str(e)}


def list_workflows(owner: str, repo: str) -> List[Dict[str, Any]]:
    """Return the list of GitHub Actions workflows for a repository.

    Uses the public Actions API and returns an empty list on error or when
    workflows cannot be accessed.
    """
    out, err = try_get(f"/repos/{owner}/{repo}/actions/workflows")
    if err or not isinstance(out, dict):
        return []
    return out.get("workflows", [])


def analyze_workflows(owner: str, repo: str) -> Dict[str, Any]:
    """Fetch and perform a lightweight analysis of workflow files.

    This function attempts to list files under `.github/workflows` and then
    fetches each YAML file to detect common test or lint keywords.  It
    returns a dictionary containing boolean indicators and per-workflow
    findings.  Any access errors are surfaced in a `note` field.
    """
    test_keywords = [
        "test", "pytest", "jest", "mocha", "unittest", "rspec", "cargo test",
        "vitest", "tap", "ava", "jasmine", "nightwatch", "cypress",
    ]
    lint_keywords = [
        "lint", "eslint", "pylint", "flake8", "black", "prettier", "clippy",
        "rustfmt", "golangci-lint", "shellcheck", "shfmt", "hadolint", "yamllint",
    ]

    workflow_files, err = try_get(f"/repos/{owner}/{repo}/contents/.github/workflows")
    if err or not isinstance(workflow_files, list):
        return {
            "has_tests": False,
            "has_linting": False,
            "workflows_analyzed": 0,
            "findings": {},
            "note": "could not access .github/workflows directory",
        }

    session = _get_session()

    findings: Dict[str, List[str]] = {}
    has_tests = False
    has_linting = False
    workflows_analyzed = 0

    def fetch_and_scan(file_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(file_info, dict):
            return None
        name = file_info.get("name", "")
        download_url = file_info.get("download_url")
        if not download_url or not (name.endswith(".yml") or name.endswith(".yaml")):
            return None
        try:
            resp = session.get(download_url, timeout=10)
            resp.raise_for_status()
            content = resp.text
        except Exception:
            return None
        detected: List[str] = []
        lower = content.lower()
        for keyword in test_keywords:
            if keyword.lower() in lower:
                detected.append(f"test:{keyword}")
                return {"name": name, "detected": detected, "has_tests": True}
        for keyword in lint_keywords:
            if keyword.lower() in lower:
                detected.append(f"lint:{keyword}")
                return {"name": name, "detected": detected, "has_linting": True}
        return None

    from concurrent.futures import ThreadPoolExecutor, as_completed

    futures = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        for fi in workflow_files:
            futures.append(executor.submit(fetch_and_scan, fi))
        for fut in as_completed(futures):
            res = fut.result()
            if not res:
                continue
            workflows_analyzed += 1
            name = res["name"]
            findings[name] = res.get("detected", [])
            if res.get("has_tests"):
                has_tests = True
            if res.get("has_linting"):
                has_linting = True

    return {
        "has_tests": has_tests,
        "has_linting": has_linting,
        "workflows_analyzed": workflows_analyzed,
        "findings": findings,
    }


def get_code_security_configuration(owner: str, repo: str) -> Dict[str, Any]:
    """Attempt to fetch repository code/security configuration.

    Tries a few likely endpoints and returns the first successful response
    or an error note. This is intentionally tolerant because API surface
    varies between GitHub versions and enterprise installs.
    """
    candidates = [
        f"/repos/{owner}/{repo}/code-scanning/configuration",
        f"/repos/{owner}/{repo}/security-analysis",
        f"/repos/{owner}/{repo}/security-and-analysis",
    ]
    last_err = None
    for ep in candidates:
        out, err = try_get(ep)
        if err is None:
            return {"endpoint": ep, "data": out}
        last_err = err
    return {"error": True, "reason": last_err}


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
