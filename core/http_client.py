"""HTTP transport layer — session management, retry, and rate-limit handling.

All network I/O for the toolkit flows through this module.  Nothing in
``github_api.py``, ``collector.py``, or elsewhere imports ``requests``
directly — they use the ``BaseHttpClient`` abstraction instead.

Extending
---------
Subclass ``BaseHttpClient`` to swap the transport layer.  The most common
reason is testing: pass a ``MockHttpClient`` (with canned fixture responses)
to ``OrgCollector`` so no real API calls are made in unit tests.

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
import time
from abc import ABC, abstractmethod
from typing import Any
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
    4. ``~/.config/gh/hosts.yml`` (GitHub CLI config)
    """

    def __init__(
        self,
        token: str | None = None,
        max_attempts: int = 5,
    ) -> None:
        self._token = token or self._resolve_token()
        self._max_attempts = max_attempts
        self._session: requests.Session | None = None

    # ── Token resolution ──────────────────────────────────────────────

    @staticmethod
    def _resolve_token() -> str:
        """Return a GitHub token from the environment or the gh CLI config.

        Raises:
            RuntimeError: if no token can be found anywhere.
        """
        token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        if token:
            return token

        config_path = os.path.expanduser("~/.config/gh/hosts.yml")
        if os.path.exists(config_path):
            try:
                import yaml  # pyyaml is already a dependency

                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
                gh_token = config.get("github.com", {}).get(
                    "oauth_token"
                ) or config.get("github.com", {}).get("token")
                if gh_token:
                    return gh_token
            except Exception:
                pass

        raise RuntimeError(
            "No GitHub token found. "
            "Set GITHUB_TOKEN or GH_TOKEN, or run `gh auth login`."
        )

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
                time.sleep(self._rate_limit_delay(resp, attempt))

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
