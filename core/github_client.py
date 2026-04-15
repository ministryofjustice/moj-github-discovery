"""HTTP transport layer — session management, retry, and rate-limit handling.

All network I/O for the toolkit flows through this module.  Nothing in
``github_api.py``, ``collector.py``, or elsewhere imports ``requests``
directly — they use the ``BaseHttpClient`` abstraction instead.

Extending
---------
Subclass ``BaseHttpClient`` to swap the transport layer.  The most common
reason is testing: pass a ``MockHttpClient`` (with canned fixture responses)
to ``RepoCollector`` so no real API calls are made in unit tests.

See ``CONTRIBUTING.md § 7`` for a walkthrough.

Migration notes
---------------
Consolidates ``utils._get_github_token``, ``utils._get_session``,
``utils._request_with_backoff``, ``utils._rate_limit_retry_delay``,
``utils._extract_link_rel``, and the duplicate
``org_security_posture._get_posture_session`` into one place.
"""

from __future__ import annotations

import os
import sys
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urljoin

import requests

# ── Abstract base ─────────────────────────────────────────────────────


class BaseHttpClient(ABC):
    """Transport contract used by all endpoint classes.

    Subclass this to change how HTTP requests are made — e.g. to inject
    recorded fixtures in tests or to swap in an OAuth2 client.

    Example::

        class MockHttpClient(BaseHttpClient):
            def __init__(self, fixtures: dict) -> None:
                self.fixtures = fixtures

            def get(self, path: str) -> Any:
                return self.fixtures.get(path, {})

            def get_paginated(self, path: str, per_page: int = 100) -> list[Any]:
                return self.fixtures.get(path, [])
    """

    BASE_URL: str = "https://api.github.com"

    @abstractmethod
    def get(self, path: str) -> Any:
        """GET a GitHub API path and return parsed JSON.

        Args:
            path: API path relative to ``BASE_URL``, e.g. ``/repos/org/repo``.
                  Absolute URLs (starting with ``https://``) are used as-is.

        Returns:
            Parsed JSON — a ``dict`` for single-resource endpoints, a ``list``
            for collection endpoints.

        Raises:
            requests.HTTPError: on non-2xx responses after exhausting retries.
        """

    @abstractmethod
    def get_paginated(self, path: str, per_page: int = 100) -> list[Any]:
        """GET all pages for a paginated endpoint and return a flat list.

        Follows ``Link: rel="next"`` headers until the last page.

        Args:
            path:     API path (may already include query params).
            per_page: Page size to request (GitHub max is 100 for most endpoints).

        Returns:
            Concatenated items from all pages.
        """


# ── Concrete implementation ───────────────────────────────────────────


class GitHubHttpClient(BaseHttpClient):
    """Authenticated GitHub API client with automatic retry on rate limits.

    On a 403 response the client checks GitHub's ``Retry-After`` and
    ``X-RateLimit-Reset`` headers and sleeps the appropriate duration before
    retrying, up to ``max_attempts`` times.  Exponential backoff is used when
    no header hint is available.

    Token resolution order:
    1. ``token`` constructor argument
    2. ``GITHUB_TOKEN`` environment variable
    3. ``GH_TOKEN`` environment variable
    4. GitHub App Environment Variables (``GH/GITHUB_APP_ID``, ``GH/GITHUB_APP_PRIVATE_KEY``)
    5. ``~/.config/gh/hosts.yml`` (GitHub CLI config)
    """

    def __init__(
        self,
        auth_method: Literal["pat", "app", "cli"] | None = None,
        token: str | None = None,
        max_attempts: int = 5,
    ) -> None:
        self._token = token or self._resolve_token(auth_method)
        self._max_attempts = max_attempts
        self._session: requests.Session | None = None

    # ── Token resolution ──────────────────────────────────────────────

    @staticmethod
    def _resolve_token(auth_method) -> str:
        """Return a GitHub token and cache the result.

        Resolution order:
        1. GITHUB_TOKEN or GH_TOKEN environment variables
        2. GitHub App Installation Token (requires GitHub App env vars documented in docs/setup.md)
        3. GitHub CLI token from gh CLI config (~/.config/gh/hosts.yml).

        Raises:
            RuntimeError: if no token can be found anywhere.
        """

        # Check if auth_method specified and call particular method, fall back to default behaviour otherwise
        if auth_method is not None:
            print(
                f"Auth Method Selected: {auth_method} - Attempting Authentication",
                file=sys.stderr,
            )
            if auth_method == "pat":
                token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
                if not token:
                    raise RuntimeError(
                        f"Auth method {auth_method} selected - but no GITHUB_TOKEN or GH_TOKEN env var found"
                    )
                print("PAT Authentication Successful", file=sys.stderr)
                return token
            if auth_method == "app":
                token = GitHubHttpClient._resolve_github_app_installation_token()
                if not token:
                    raise RuntimeError(
                        f"Auth method {auth_method} selected - but GitHub App auth could not be resolved"
                    )
                print("GitHub App Authentication Successful", file=sys.stderr)
                return token
            if auth_method == "cli":
                token = GitHubHttpClient._resolve_github_cli_token()
                if not token:
                    raise RuntimeError(
                        f"Auth method {auth_method} selected - but no GITHUB_CLI token found"
                    )
                print("GitHub CLI Authentication Successful", file=sys.stderr)
                return token

        print(
            "No Auth Method Arg Provided - Reverting to Default Behaviour",
            file=sys.stderr,
        )
        # 1. GitHub PAT Environment Variable
        print("Checking for GitHub PAT Authentication", file=sys.stderr)
        token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        if token:
            print("PAT Authentication Successful", file=sys.stderr)
            return token

        # 2. GitHub App Environment Variables
        print(
            "PAT Authentication Unsuccessful - Attempting GitHub App Authentication",
            file=sys.stderr,
        )
        gh_app_token = GitHubHttpClient._resolve_github_app_installation_token()
        if gh_app_token:
            print("GitHub App Authentication Successful", file=sys.stderr)
            return gh_app_token

        print(
            "GitHub App Authentication Unsuccessful - Attempting GitHub CLI Authentication",
            file=sys.stderr,
        )

        # 3. GitHub CLI Config
        gh_cli_token = GitHubHttpClient._resolve_github_cli_token()
        if gh_cli_token:
            print("GitHub CLI Authentication Successful", file=sys.stderr)
            return gh_cli_token

        raise RuntimeError(
            "No GitHub token found. "
            "Set GITHUB_TOKEN or GH_TOKEN, or run `gh auth login`."
        )

    @staticmethod
    def _resolve_github_app_installation_id(
        sess: requests.Session, headers: Dict[str, str]
    ) -> str:
        """Resolve GitHub App Installation ID via Env or Org Name"""

        # Env Var Validation (GH/GITHUB_APP_INSTALLATION_ID
        app_installation_id = os.getenv("GH_APP_INSTALLATION_ID") or os.getenv(
            "GITHUB_APP_INSTALLATION_ID"
        )
        if app_installation_id:
            return app_installation_id

        # If Env Vars not Provided - Fallback to Auto-Discovery via Org Login
        org_login = (
            os.getenv("GITHUB_ORG") or os.getenv("GH_ORG") or os.getenv("GITHUB_OWNER")
        )

        if not org_login:
            raise RuntimeError(
                "GitHub App auth requires GH_APP_INSTALLATION_ID (or GITHUB_APP_INSTALLATION_ID), "
                "or GH_ORG/GITHUB_ORG/GITHUB_OWNER to auto-resolve the installation."
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
                        installation_id_value = installation.get("id")
                        if installation_id_value is None or not isinstance(
                            installation_id_value, (int, str)
                        ):
                            raise RuntimeError(
                                "GitHub App installation list response did not include a valid "
                                f"'id' for installation with account '{account}'."
                            )
                        return str(installation_id_value)

            if len(installations) < 100:
                break

        accounts = ", ".join(sorted(set(installation_accounts)))
        raise RuntimeError(
            f"No GitHub App installation found for org '{org_login}'. "
            f"Visible installations: {accounts or 'none'}."
        )

    @staticmethod
    def _resolve_github_app_installation_token() -> str:

        # Env Var Validation: GH_APP_ID / GITHUB_APP_ID
        github_app_id = os.getenv("GITHUB_APP_ID") or os.getenv("GH_APP_ID")
        if not github_app_id:
            return None

        # Env Var Validation: GH_/GITHUB_APP_PRIVATE_KEY
        github_app_private_key = GitHubHttpClient._read_github_app_private_key()
        if not github_app_private_key:
            raise RuntimeError(
                "GitHub App Auth Requested via GH_APP_ID / GITHUB_APP_ID, but no private key provided ",
                "Set GH_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY",
            )

        # Verify JWT Set Up for GH App Authentication
        try:
            import jwt
        except ImportError as exc:
            raise RuntimeError(
                "GitHub App Authentication Requires PyJWT and Cryptography. "
                "Ensure they are added via: uv add pyjwt cryptography"
            ) from exc

        now = int(time.time())

        # Generate temporary JSON Web Token (JWT) to request App Token
        app_jwt = jwt.encode(
            {"iat": now - 60, "exp": now + 540, "iss": str(github_app_id)},
            github_app_private_key,
            algorithm="RS256",
        )

        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        with requests.Session() as app_sess:
            app_installation_id = GitHubHttpClient._resolve_github_app_installation_id(
                app_sess, headers
            )

            token_resp = app_sess.post(
                f"https://api.github.com/app/installations/{app_installation_id}/access_tokens",
                headers=headers,
                timeout=30,
            )
            token_resp.raise_for_status()

            token_data = token_resp.json()

            token = token_data.get("token")

            if not token:
                raise RuntimeError(
                    "GitHub App Access Token Response did not include a token value"
                )

            return token

    def _read_github_app_private_key() -> Optional[str]:
        """Return GitHub App private key from environment variable content."""
        key_value = os.getenv("GITHUB_APP_PRIVATE_KEY") or os.getenv(
            "GH_APP_PRIVATE_KEY"
        )
        if key_value:
            return key_value.replace("\\n", "\n")
        return None

    @staticmethod
    def _resolve_github_cli_token() -> str:
        """Attempt to resolve a GitHub CLI token from the gh CLI config or via `gh auth token` command."""

        # First Attempt - Use gh auth token
        try:
            import subprocess

            result = subprocess.run(
                ["gh", "auth", "token"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True,
            )
            token = result.stdout.strip()
            if token:
                return token
        except Exception:
            pass

        # Second Attempt - Read from gh CLI config file
        config_path = os.path.expanduser("~/.config/gh/hosts.yml")

        if not os.path.exists(config_path):
            return None
        try:
            import yaml  # pyyaml is already a dependency

            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            return config.get("github.com", {}).get("oauth_token") or config.get(
                "github.com", {}
            ).get("token")
        except Exception:
            return None

    # ── Session ───────────────────────────────────────────────────────

    def _get_session(self) -> requests.Session:
        if self._session is None:
            sess = requests.Session()
            sess.headers.update(
                {
                    "Authorization": f"token {self._token}",
                    "Accept": "application/vnd.github.v3+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
            )
            self._session = sess
        return self._session

    # ── Backoff helpers ───────────────────────────────────────────────

    @staticmethod
    def _rate_limit_delay(resp: requests.Response, attempt: int) -> int:
        """Return the number of seconds to sleep before the next retry."""
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
                return max(1, min(900, int(reset_at) - int(time.time()) + 1))
            except ValueError:
                pass

        # Bounded exponential backoff
        return min(300, 15 * (2 ** (attempt - 1)))

    @staticmethod
    def _format_wait(seconds: int) -> str:
        """Render a short human-readable duration string."""
        minutes, secs = divmod(max(0, int(seconds)), 60)
        if minutes:
            return f"{minutes}m {secs:02d}s"
        return f"{secs}s"

    @staticmethod
    def _rate_limit_reason(resp: requests.Response) -> str:
        """Summarise why the request is being delayed."""
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            return f"retry-after={retry_after}s"

        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining == "0":
            return "primary quota exhausted"

        return "403 rate limit"

    @staticmethod
    def _sleep_with_progress(delay_seconds: int, prefix: str) -> None:
        """Sleep while printing a live countdown on stderr."""
        remaining = max(1, int(delay_seconds))
        while remaining > 0:
            print(
                f"\r{prefix}: waiting {GitHubHttpClient._format_wait(remaining)}",
                end="",
                file=sys.stderr,
                flush=True,
            )
            # Keep updates frequent without spamming too much on long waits.
            sleep_for = 1 if remaining <= 60 else min(5, remaining)
            time.sleep(sleep_for)
            remaining -= sleep_for

        print("\r" + " " * 100, end="\r", file=sys.stderr, flush=True)
        print(f"{prefix}: retrying now", file=sys.stderr, flush=True)

    def _request(self, method: str, url: str) -> requests.Response:
        """Send a request and retry on rate-limit 403s."""
        sess = self._get_session()
        for attempt in range(1, self._max_attempts + 1):
            resp = sess.request(method, url)
            try:
                resp.raise_for_status()
                return resp
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status != 403 or attempt >= self._max_attempts:
                    raise
                delay = self._rate_limit_delay(resp, attempt)
                reason = self._rate_limit_reason(resp)
                self._sleep_with_progress(
                    delay,
                    prefix=f"[rate-limit] {reason} (attempt {attempt}/{self._max_attempts})",
                )

        raise RuntimeError("Unexpected retry exhaustion")  # defensive

    # ── Link-header pagination ────────────────────────────────────────

    @staticmethod
    def _next_page_url(link_header: str | None) -> str | None:
        """Extract the ``next`` URL from a GitHub ``Link`` response header.

        Returns ``None`` when there is no next page.
        """
        if not link_header:
            return None
        for part in link_header.split(","):
            url_part, *rels = part.strip().split(";")
            for rel in rels:
                if rel.strip() == 'rel="next"':
                    return url_part.strip().strip("<>")
        return None

    # ── Public interface ──────────────────────────────────────────────

    def get(self, path: str) -> Any:
        url = path if path.startswith("http") else urljoin(self.BASE_URL, path)
        return self._request("GET", url).json()

    def get_paginated(self, path: str, per_page: int = 100) -> list[Any]:
        sep = "&" if "?" in path else "?"
        url: str | None = (
            path if path.startswith("http") else urljoin(self.BASE_URL, path)
        )
        url = f"{url}{sep}per_page={per_page}"

        items: list[Any] = []
        while url:
            resp = self._request("GET", url)
            data = resp.json()
            if isinstance(data, list):
                items.extend(data)
            elif isinstance(data, dict):
                # Search API wraps results: {"total_count": N, "items": [...]}
                items.extend(data.get("items", []))
            url = self._next_page_url(resp.headers.get("Link"))
        return items
