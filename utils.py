"""Common utilities for GitHub repository auditing."""

import json
import os
import sqlite3
import time
from urllib.parse import parse_qs, urlparse
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# module‑level globals used to cache the GitHub token and HTTP session
_TOKEN: Optional[str] = None
_SESSION: Optional[requests.Session] = None


def _read_github_app_private_key() -> Optional[str]:
    """Return GitHub App private key from environment variable content."""
    key_value = os.getenv("GH_APP_PRIVATE_KEY") or os.getenv("GITHUB_APP_PRIVATE_KEY")
    if key_value:
        return key_value.replace("\\n", "\n")
    return None


def _resolve_github_app_installation_id(
    sess: requests.Session, headers: Dict[str, str]
) -> str:
    """Resolve GitHub App installation ID from env or org name."""
    installation_id = os.getenv("GH_APP_INSTALLATION_ID") or os.getenv(
        "GITHUB_APP_INSTALLATION_ID"
    )
    if installation_id:
        return installation_id

    org_login = (
        os.getenv("GH_ORG")
        or os.getenv("GITHUB_ORG")
        or os.getenv("GITHUB_OWNER")
    )
    if not org_login:
        raise RuntimeError(
            "GitHub App auth requires GH_APP_INSTALLATION_ID (or GITHUB_APP_INSTALLATION_ID), "
            "or GH_ORG/GITHUB_ORG to auto-resolve the installation."
        )

    installation_accounts: List[str] = []
    for page in range(1, 11):
        resp = sess.get(
            f"https://api.github.com/app/installations?per_page=100&page={page}",
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        installations = resp.json()
        if not isinstance(installations, list) or not installations:
            break

        for installation in installations:
            account = (installation.get("account") or {}).get("login")
            if isinstance(account, str):
                installation_accounts.append(account)
                if account.lower() == org_login.lower():
                    return str(installation.get("id"))

        if len(installations) < 100:
            break

    accounts = ", ".join(sorted(set(installation_accounts)))
    raise RuntimeError(
        f"No GitHub App installation found for org '{org_login}'. "
        f"Visible installations: {accounts or 'none'}."
    )


def _get_github_app_installation_token() -> Optional[str]:
    """Return a GitHub App installation token when app env vars are configured."""
    app_id = os.getenv("GH_APP_ID") or os.getenv("GITHUB_APP_ID")
    if not app_id:
        return None

    private_key = _read_github_app_private_key()
    if not private_key:
        raise RuntimeError(
            "GitHub App auth requested via GH_APP_ID/GITHUB_APP_ID but no private key was provided. "
            "Set GH_APP_PRIVATE_KEY (or GITHUB_APP_PRIVATE_KEY)."
        )

    try:
        import jwt
    except ImportError as exc:
        raise RuntimeError(
            "GitHub App authentication requires PyJWT and cryptography. "
            "Install them with: pip install PyJWT cryptography"
        ) from exc

    now = int(time.time())
    app_jwt = jwt.encode(
        {
            "iat": now - 60,
            "exp": now + 540,
            "iss": str(app_id),
        },
        private_key,
        algorithm="RS256",
    )

    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    sess = requests.Session()
    installation_id = _resolve_github_app_installation_id(sess, headers)
    token_resp = sess.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers=headers,
        timeout=30,
    )
    token_resp.raise_for_status()
    token_data = token_resp.json()
    token = token_data.get("token")
    if not token:
        raise RuntimeError(
            "GitHub App access token response did not include a token value."
        )
    return token


def _rate_limit_retry_delay(resp: requests.Response, attempt: int) -> int:
    """Return backoff delay in seconds for a 403 response.

    Prefer GitHub-provided headers when available and fall back to bounded
    exponential backoff for secondary/abuse limits.
    """
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            return max(1, int(float(retry_after)))
        except ValueError:
            pass

    remaining = resp.headers.get("X-RateLimit-Remaining")
    reset_at = resp.headers.get("X-RateLimit-Reset")
    if remaining == "0" and reset_at:
        try:
            reset_epoch = int(reset_at)
            return max(1, min(900, reset_epoch - int(time.time()) + 1))
        except ValueError:
            pass

    return min(300, 15 * (2 ** (attempt - 1)))


def _request_with_backoff(
    sess: requests.Session,
    method: str,
    url: str,
    max_attempts: int = 5,
) -> requests.Response:
    """Send an API request and retry when GitHub returns rate-limit 403s."""
    for attempt in range(1, max_attempts + 1):
        resp = sess.request(method, url)
        try:
            resp.raise_for_status()
            return resp
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            if status != 403 or attempt >= max_attempts:
                raise
            time.sleep(_rate_limit_retry_delay(resp, attempt))

    # Defensive fallback; loop should have returned or raised.
    raise RuntimeError("Unexpected request retry flow")


def _get_github_token() -> str:
    """Return a GitHub token, caching the result.

    Resolution order:

    1. ``GITHUB_TOKEN`` or ``GH_TOKEN`` from environment variables.
    2. GitHub App installation token (when GitHub App env vars are set).
    3. GitHub CLI token from ``~/.config/gh/hosts.yml``.

    The resolved value is cached in a module-level variable so repeated
    calls are cheap.
    """
    global _TOKEN
    if _TOKEN:
        return _TOKEN

    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        _TOKEN = token
        return token

    app_token = _get_github_app_installation_token()
    if app_token:
        _TOKEN = app_token
        return app_token

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
        "No GitHub token found. Set GITHUB_TOKEN/GH_TOKEN, or configure GH_APP_ID with a "
        "GitHub App private key, or configure gh CLI."
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


def gh_api(
    path: str,
    method: str = "GET",
    paginate: bool = False,
    params: Optional[List[str]] = None,
) -> Any:
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
            resp = _request_with_backoff(sess, method, paged)
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
        resp = _request_with_backoff(sess, method, url)
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

    # Check if this is a fork based on the boolean flag.
    is_fork = bool(repo_data.get("fork"))
    info["is_fork"] = is_fork
    if is_fork:
        parent = repo_data.get("parent") or {}
        info["fork_source"] = parent.get("full_name") or parent.get("name")

    # Check if generated from a template
    if repo_data.get("template_repository"):
        info["is_generated_from_template"] = True
        template = repo_data.get("template_repository", {})
        info["template_source"] = template.get("full_name")

    return info


def _extract_link_rel(link_header: str, rel_name: str) -> Optional[str]:
    """Return URL for a given relation name from a GitHub Link header."""
    if not link_header:
        return None
    for link_part in link_header.split(","):
        part = link_part.strip()
        if f'rel="{rel_name}"' not in part:
            continue
        if "<" in part and ">" in part:
            try:
                return part.split("<", 1)[1].split(">", 1)[0]
            except (IndexError, ValueError):
                return None
    return None


def _count_alerts_by_iteration(
    sess: requests.Session, initial_url: str, per_page: int = 100
) -> int:
    """Count alerts by iterating pages when last-page parsing is unavailable."""
    sep = "&" if "?" in initial_url else "?"
    base_url = f"{initial_url}{sep}per_page={per_page}"
    page = 1
    total = 0
    while True:
        resp = sess.get(f"{base_url}&page={page}")
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list) or not data:
            break
        total += len(data)
        if len(data) < per_page:
            break
        page += 1
    return total


def _count_alerts_efficient(
    owner: str, repo: str, endpoint: str
) -> Tuple[Optional[int], Optional[str]]:
    """Count alerts efficiently using Link header pagination without fetching all results.

    Returns (count, error_kind) where error_kind is None on success, or one of
    {'403', '404', 'other'} on error. Makes one API call in the common case.
    """
    sess = _get_session()
    base_url = "https://api.github.com"
    list_url = f"{base_url}/repos/{owner}/{repo}/{endpoint}?state=open"
    url = f"{list_url}&per_page=1"

    try:
        resp = sess.get(url)
        resp.raise_for_status()

        # Check Link header for pagination info.
        link_header = resp.headers.get("link", "")
        last_url = _extract_link_rel(link_header, "last")
        if last_url:
            try:
                page_values = parse_qs(urlparse(last_url).query).get("page")
                if page_values:
                    return int(page_values[0]), None
            except (ValueError, TypeError):
                # Fall back to iterative counting for correctness.
                return _count_alerts_by_iteration(sess, list_url), None

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
            return None, "other"
    except Exception:
        return None, "other"


def _count_alerts_dependabot(
    owner: str, repo: str
) -> Tuple[Optional[int], Optional[str]]:
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

            # Check for next page in Link header.
            url = _extract_link_rel(resp.headers.get("link", ""), "next")

        return count, None

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code
        if status == 403:
            return None, "403"
        elif status == 404:
            return 0, "404"
        else:
            return None, "other"
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
        futures.append(
            executor.submit(_fetch_efficient, "code_scanning", "code-scanning/alerts")
        )
        futures.append(
            executor.submit(
                _fetch_efficient, "secret_scanning", "secret-scanning/alerts"
            )
        )
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
        return {
            "default_branch_protected": None,
            "branch_protection_access": "forbidden",
        }
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


def check_codeowners_exists(owner: str, repo: str, default_branch: str) -> dict:
    CODEOWNERS_PATHS = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]
    sess = _get_session()
    base_url = "https://api.github.com"
    tree_url = f"{base_url}/repos/{owner}/{repo}/git/trees/{default_branch}"

    resp = sess.get(f"{tree_url}?recursive=1")
    resp.raise_for_status()
    tree_paths = {item["path"] for item in resp.json().get("tree", [])}

    for path in CODEOWNERS_PATHS:
        if path in tree_paths:
            return {"present": True, "path": path}
    return {"present": False, "path": None}


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


def save_to_db(
    db_path: str, full_name: str, data: Dict[str, Any], table_name: str = "audits"
) -> None:
    """Upsert data into SQLite database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        f"INSERT OR REPLACE INTO {table_name} (full_name, audit_json) VALUES (?, ?)",
        (full_name, json.dumps(data)),
    )
    conn.commit()
    conn.close()
