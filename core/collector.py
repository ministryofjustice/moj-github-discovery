"""Collector — orchestrates API fetching and immediate persistence.

For each repository the collector iterates through every registered
:class:`~core.github_api.BaseEndpoint`, calls ``fetch()``, and immediately
persists the result to the database via ``storage.upsert()``.  If the
process is interrupted (Ctrl-C, quota limit, network error) all data
collected so far has already been written — nothing is lost.

Collectors
----------
* :class:`RepoCollector` — runs repo-scoped endpoints against every repo.
* :class:`OrgEndpointCollector` — runs org-scoped endpoints once per org.
* :class:`RepoListCollector` — discovers repos via the list-org-repos API.

Resume support
--------------
Pass ``resume=True`` to skip endpoints whose key is already populated in
the database row for a given repo.  This makes it safe to re-run the
collector against the same database after an interruption.

Extending
---------
Subclass :class:`BaseCollector` to change the iteration strategy — for
example to run endpoint calls in parallel or to apply a custom filter.

See ``CONTRIBUTING.md`` for a walkthrough.

Migration notes
---------------
Replaces the ``process_single()`` / ``main()`` logic in ``list_repos.py``,
the legacy single-repo audit script, and ``archive_repos.py``.
"""

from __future__ import annotations

import inspect
import sys
import threading
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel

from core.github_api import (
    ORG_ENDPOINTS,
    REPO_ENDPOINTS,
    BaseEndpoint,
    BaseOrgEndpoint,
    list_org_repos,
)
from core.github_client import BaseHttpClient, GitHubHttpClient
from core.models import RepoData
from core.storage import BaseStorage


# ── Abstract base ─────────────────────────────────────────────────────


class BaseCollector(ABC):
    """
    Extend to change how repositories are iterated or collection is scheduled.
    Example (parallel variant)::

        class ParallelCollector(BaseCollector):
            def collect(self, org, repos=None, resume=False):
                ...  # use ThreadPoolExecutor over the repo list
    """

    @abstractmethod
    def collect(
        self,
        org: str,
        repos: list[str] | None = None,
        resume: bool = False,
    ) -> None:
        """
        Fetch and persist data for all repositories.

        Args:
            org:    GitHub organisation name.
            repos:  Optional explicit list of ``owner/repo`` strings.  If
                    omitted, the full org repository list is discovered via
                    the API.
            resume: When ``True``, skip endpoints whose key is already
                    populated in the database for a given repo.
        """


# ── Concrete implementation ───────────────────────────────────────────


class RepoCollector(BaseCollector):
    """Iterates an org's repos and calls every registered repo-scoped endpoint.

    After **each** endpoint call the result is immediately merged into the
    database row for that repo via ``storage.upsert()``.  An interruption
    at any point leaves all previously collected data intact.

    Usage::

        storage = SqliteRepoStorage("repo_data.db")
        collector = RepoCollector(storage)
        collector.collect("ministryofjustice")

        # Resume after interruption:
        collector.collect("ministryofjustice", resume=True)

        # Audit a specific subset:
        collector.collect("ministryofjustice", repos=["org/repo-a", "org/repo-b"])
    """

    def __init__(
        self,
        storage: BaseStorage,
        client: BaseHttpClient | None = None,
        endpoints: list[type[BaseEndpoint]] | None = None,
        max_workers: int = 4,
    ) -> None:
        """
        Args:
            storage:   Initialised storage backend.  The collector calls
                       ``storage.init()`` automatically.
            client:    HTTP client to use.  Defaults to
                       :class:`~core.github_client.GitHubHttpClient`.
            endpoints: List of endpoint classes to run.  Defaults to
                       :data:`~core.github_api.REPO_ENDPOINTS`.
            max_workers: Number of worker threads for repo collection.
                        Use ``1`` for sequential collection.
        """
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")

        self.storage = storage
        self.client = client or GitHubHttpClient()
        self.endpoints: list[type[BaseEndpoint]] = endpoints or REPO_ENDPOINTS
        self.max_workers = max_workers
        self._storage_lock = threading.Lock()

    # ── Public interface ──────────────────────────────────────────────

    def collect(
        self,
        org: str,
        repos: list[str] | None = None,
        resume: bool = False,
    ) -> None:
        self.storage.init()

        repo_list = repos if repos is not None else list_org_repos(org, self.client)
        total = len(repo_list)
        print(
            f"Collecting {total} repo(s) for '{org}' "
            f"({'resume mode' if resume else 'full run'}, workers={self.max_workers})",
            file=sys.stderr,
        )

        if self.max_workers == 1 or total <= 1:
            for idx, full_name in enumerate(repo_list, start=1):
                print(
                    f"[{idx}/{total}] {full_name}",
                    file=sys.stderr,
                )
                self._collect_full_name(full_name, resume=resume)
            return

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for idx, full_name in enumerate(repo_list, start=1):
                print(
                    f"[{idx}/{total}] queue {full_name}",
                    file=sys.stderr,
                )
                futures[executor.submit(self._collect_full_name, full_name, resume)] = (
                    full_name
                )

            for future in as_completed(futures):
                full_name = futures[future]
                try:
                    future.result()
                    print(f"  [done] {full_name}", file=sys.stderr)
                except Exception as exc:
                    print(f"  [error] {full_name}: {exc}", file=sys.stderr)

    # ── Internal helpers ──────────────────────────────────────────────

    def _build_fetch_kwargs(
        self,
        endpoint: BaseEndpoint,
        existing: RepoData,
    ) -> dict[str, object]:
        """Map endpoint fetch kwargs from fields already present in ``RepoData``.

        Any fetch parameter beyond ``owner`` and ``repo`` that matches a
        ``RepoData`` field name is passed through (e.g. ``repo_details``).
        """
        kwargs: dict[str, object] = {}
        params = list(inspect.signature(endpoint.fetch).parameters.values())
        for param in params[2:]:
            if hasattr(existing, param.name):
                kwargs[param.name] = getattr(existing, param.name)
        return kwargs

    def _collect_repo(
        self,
        owner: str,
        repo: str,
        full_name: str,
        resume: bool,
    ) -> None:
        """Run all endpoints for a single repository."""
        existing = self._storage_read(full_name) or RepoData()

        for endpoint_cls in self.endpoints:
            endpoint = endpoint_cls(self.client)
            key = endpoint.name

            if resume and getattr(existing, key, None) is not None:
                print(
                    f"  [resume] {key} already collected — skipping",
                    file=sys.stderr,
                )
                continue

            try:
                fetch_kwargs = self._build_fetch_kwargs(endpoint, existing)
                result_model = endpoint.fetch(owner, repo, **fetch_kwargs)
                self._storage_upsert(full_name, RepoData(**{key: result_model}))
                # Refresh local copy so the next endpoint sees the updated state
                # TODO: This is a bit clunky — ideally the storage layer would handle merging
                existing = self._storage_read(full_name) or existing
                print(f"  [ok] {key}", file=sys.stderr)
            except Exception as exc:
                print(f"  [error] {key}: {exc}", file=sys.stderr)
                # Continue to the next endpoint — never abort the whole repo

        # Stamp the collection timestamp
        self._storage_upsert(
            full_name,
            RepoData(collected_at=datetime.now(timezone.utc).isoformat()),
        )

    def _collect_full_name(self, full_name: str, resume: bool) -> None:
        """Parse and collect a single ``owner/repo`` identifier."""
        parts = full_name.split("/", 1)
        if len(parts) != 2:
            print(
                f"[skip] Invalid repo name: {full_name!r}",
                file=sys.stderr,
            )
            return
        owner, repo = parts
        self._collect_repo(owner, repo, full_name, resume=resume)

    def _storage_read(self, full_name: str) -> RepoData | None:
        """Thread-safe storage read."""
        with self._storage_lock:
            return self.storage.read(full_name)

    def _storage_upsert(self, full_name: str, update: RepoData) -> None:
        """Thread-safe storage upsert."""
        with self._storage_lock:
            self.storage.upsert(full_name, update)


# ── Org-scoped collector ──────────────────────────────────────────────


class OrgEndpointCollector:
    """Runs org-scoped endpoints once per org and returns the results.

    Unlike :class:`RepoCollector` this does **not** iterate repositories.
    Each registered :class:`~core.github_api.BaseOrgEndpoint` is called
    once with the organisation name and the result is returned as a dict.

    Usage::

        collector = OrgEndpointCollector()
        results = collector.collect("ministryofjustice")
        # results == {"org_members": OrgMembersData(...), ...}
    """

    def __init__(
        self,
        client: BaseHttpClient | None = None,
        endpoints: list[type[BaseOrgEndpoint]] | None = None,
    ) -> None:
        self.client = client or GitHubHttpClient()
        self.endpoints: list[type[BaseOrgEndpoint]] = endpoints or ORG_ENDPOINTS

    def collect(self, org: str) -> dict[str, BaseModel]:
        """Run all org-scoped endpoints and return their results.

        Args:
            org: GitHub organisation login name.

        Returns:
            Dict mapping endpoint name to its Pydantic model result.
        """
        results: dict[str, BaseModel] = {}
        for endpoint_cls in self.endpoints:
            endpoint = endpoint_cls(self.client)
            try:
                results[endpoint.name] = endpoint.fetch(org)
                print(f"  [ok] {endpoint.name}", file=sys.stderr)
            except Exception as exc:
                print(f"  [error] {endpoint.name}: {exc}", file=sys.stderr)
        return results


# ── Repo-list collector ───────────────────────────────────────────────


class RepoListCollector:
    """Discovers repos in an organisation via the GitHub list-repos API.

    Wraps :func:`~core.github_api.list_org_repos` with all the filtering
    and sorting controls exposed by the GitHub API.

    Usage::

        collector = RepoListCollector()
        repos = collector.collect("ministryofjustice")
        # repos == ["ministryofjustice/repo-a", ...]

        # Only public, sorted by name:
        repos = collector.collect(
            "ministryofjustice", type="public", sort="full_name",
        )
    """

    def __init__(self, client: BaseHttpClient | None = None) -> None:
        self.client = client or GitHubHttpClient()

    def collect(
        self,
        org: str,
        *,
        type: Literal["all", "public", "private", "forks", "sources", "member"] = "all",
        sort: Literal["created", "updated", "pushed", "full_name"] = "pushed",
        direction: Literal["asc", "desc"] | None = None,
    ) -> list[str]:
        """Return the list of ``owner/repo`` strings for the organisation.

        Args:
            org:       GitHub organisation login name.
            type:      Filter by repo type.
            sort:      Property to sort results by.
            direction: Sort order.  Defaults to ``"asc"`` when *sort* is
                       ``"full_name"``, otherwise ``"desc"``.
        """
        repos = list_org_repos(
            org,
            self.client,
            type=type,
            sort=sort,
            direction=direction,
        )
        print(
            f"Discovered {len(repos)} repo(s) for '{org}' (type={type}, sort={sort})",
            file=sys.stderr,
        )
        return repos
