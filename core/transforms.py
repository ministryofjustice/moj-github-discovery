"""Data transforms — pure functions that enrich repo data.

Transforms receive a :class:`~core.models.RepoData` Pydantic model and
return an updated copy.  They must be *pure*: no network calls, no disk I/O,
no side effects.  The compiler applies all registered transforms in order
before building the output DataFrame.

Extending
---------
1. Subclass ``BaseTransform`` — implement ``name`` and ``apply``.
2. Add your class to ``TRANSFORMS``.

See ``CONTRIBUTING.md § 2`` for a walkthrough with a full example.

Rule of thumb
-------------
Use ``data.model_copy(update={...})`` to return a modified copy rather than
mutating the model in place.  Pydantic models are designed for this pattern.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import re

from core.models import LargeBlobData, RepoData, RepoTreeProcessedData

# Size limits in bytes (50/100 MB converted to bytes for ease of processing)
SOFT_LIMIT = 50 * 1024 * 1024
SOFT_LIMIT = 50 * 1024 * 1024
HARD_LIMIT = 100 * 1024 * 1024


# ── Abstract base ─────────────────────────────────────────────────────


class BaseTransform(ABC):
    """Extend to add computed fields or risk flags to repo data.

    Transforms must be *pure*:

    * No network or disk I/O.
    * No global state mutations.
    * Return an updated copy via ``data.model_copy(update={...})``.

    The compiler instantiates each class in ``TRANSFORMS`` once and calls
    ``apply`` for every repo row.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier used in error messages and logging."""

    @abstractmethod
    def apply(self, data: RepoData) -> RepoData:
        """Apply the transform and return the updated data.

        Args:
            data: Current ``RepoData`` for one repository.

        Returns:
            A (possibly modified) ``RepoData`` instance.  Use
            ``data.model_copy(update={...})`` to avoid mutating the input.
        """


# ── Concrete transforms ───────────────────────────────────────────────


class TimestampTransform(BaseTransform):
    """Compute ``days_since_push`` and ``age_days`` from ISO-8601 timestamps.

    Adds:
    * ``days_since_push`` — calendar days since the last push.
    * ``age_days``        — calendar days since the repository was created.
    """

    @property
    def name(self) -> str:
        return "timestamp"

    def apply(self, data: RepoData) -> RepoData:
        if data.repo_details is None:
            return data

        now = datetime.now(timezone.utc)
        updates: dict = {}

        if data.repo_details.pushed_at:
            pushed = datetime.fromisoformat(
                data.repo_details.pushed_at.replace("Z", "+00:00")
            )
            updates["days_since_push"] = (now - pushed).days

        if data.repo_details.created_at:
            created = datetime.fromisoformat(
                data.repo_details.created_at.replace("Z", "+00:00")
            )
            updates["age_days"] = (now - created).days

        return data.model_copy(update=updates) if updates else data


class ReferenceClassifier(BaseTransform):
    """Classify cross-repo code-search references as active or archived.

    Populates ``references.active_references`` and
    ``references.archive_references`` based on the ``archived`` flag on each
    :class:`~core.models.ReferenceItem`.
    """

    @property
    def name(self) -> str:
        return "reference_classifier"

    def apply(self, data: RepoData) -> RepoData:
        if data.references is None:
            return data

        active = sorted({r.full_name for r in data.references.items if not r.archived})
        archived = sorted({r.full_name for r in data.references.items if r.archived})
        updated_refs = data.references.model_copy(
            update={
                "active_references": active,
                "archive_references": archived,
            }
        )
        return data.model_copy(update={"references": updated_refs})


class FlagTransform(BaseTransform):
    """Generate a list of human-readable risk flags based on repo characteristics.

    Flags produced:

    * ``archived``                  — repo is archived
    * ``archived_open_issues``      — archived but still has open issues
    * ``archived_has_stars``        — archived but still has stars
    * ``archived_has_forks``        — archived but still has forks
    * ``archived_with_open_alerts`` — archived but has open security alerts
    * ``fork``                      — repo is a fork
    * ``disabled``                  — repo is disabled
    * ``unprotected_default_branch``— default branch has no protection rules
    * ``no_codeowners``             — no CODEOWNERS file found
    * ``stale``                     — not pushed in over a year

    Depends on: ``TimestampTransform`` (must run first to populate
    ``days_since_push``).
    """

    @property
    def name(self) -> str:
        return "flags"

    def apply(self, data: RepoData) -> RepoData:
        flags: list[str] = []
        meta = data.repo_details

        if meta:
            if meta.archived:
                flags.append("archived")
                if meta.open_issues_count > 0:
                    flags.append("archived_open_issues")
                if meta.stargazers_count > 0:
                    flags.append("archived_has_stars")
                if meta.forks_count > 0:
                    flags.append("archived_has_forks")
                if data.alerts and (
                    data.alerts.dependabot_alerts > 0
                    or data.alerts.code_scanning_alerts > 0
                    or data.alerts.secret_scanning_alerts > 0
                ):
                    flags.append("archived_with_open_alerts")
            if meta.fork:
                flags.append("fork")
            if meta.disabled:
                flags.append("disabled")

        if (
            data.branch_protection is not None
            and not data.branch_protection.default_branch_protected
        ):
            flags.append("unprotected_default_branch")

        if data.codeowners is not None and not data.codeowners.present:
            flags.append("no_codeowners")

        if data.days_since_push is not None and data.days_since_push > 365:
            flags.append("stale")

        return data.model_copy(update={"flags": flags})


class RepoTreeTransform(BaseTransform):
    """Summarise the repository tree into large-file metrics.

    Populates ``repo_tree_transform`` with:

    * ``repo``               — repository full name
    * ``largest_blob_bytes`` — size of the largest blob in the tree
    * ``largest_blob_path``  — path of the largest blob in the tree
    * ``large_blobs``        — blobs at or above the soft limit
    * ``exceeds_soft_limit`` — whether the largest blob exceeds the soft limit
    * ``exceeds_hard_limit`` — whether the largest blob exceeds the hard limit
    """

    @property
    def name(self) -> str:
        return "repo_tree_transform"

    @staticmethod
    def find_largest_blob(tree: list[object]) -> tuple[int, str | None, str | None]:
        largest_size = 0
        largest_path: str | None = None
        largest_sha: str | None = None

        for item in tree:
            if getattr(item, "type", None) != "blob":
                continue
            size = getattr(item, "size", None)
            if not isinstance(size, int):
                continue

            if size > largest_size:
                largest_size = size
                largest_path = getattr(item, "path", None)
                largest_sha = getattr(item, "sha", None)

        return largest_size, largest_path, largest_sha

    @staticmethod
    def process_repo_tree_stats(
        repo_full_name: str,
        tree: list[object],
    ) -> RepoTreeProcessedData:
        large_blobs: list[LargeBlobData] = []

        for item in tree:
            if getattr(item, "type", None) != "blob":
                continue
            size = getattr(item, "size", None)
            path = getattr(item, "path", None)
            if not isinstance(size, int) or not isinstance(path, str):
                continue
            if size >= SOFT_LIMIT:
                large_blobs.append(
                    LargeBlobData(
                        sha=getattr(item, "sha", None),
                        size_bytes=size,
                        path=path,
                    )
                )

        largest_size, largest_path, _largest_sha = RepoTreeTransform.find_largest_blob(
            tree
        )

        return RepoTreeProcessedData(
            repo=repo_full_name,
            largest_blob_bytes=largest_size,
            largest_blob_path=largest_path,
            large_blobs=large_blobs,
            exceeds_soft_limit=largest_size > SOFT_LIMIT,
            exceeds_hard_limit=largest_size > HARD_LIMIT,
        )

    def apply(self, data: RepoData) -> RepoData:
        if data.repo_tree is None or data.repo_details is None:
            return data

        processed = self.process_repo_tree_stats(
            data.repo_details.full_name,
            data.repo_tree.tree,
        )

        return data.model_copy(update={"repo_tree_transform": processed})


# — Standalone parsing helpers ————————————————————————


def parse_workflow_permissions(content: str) -> dict[str, object]:
    """Parse workflow file content and extract permissions posture.

    Pure function — no network, no side effects.
    """
    has_permissions = False
    permissions_value = ""
    has_write = False
    finding = "no_permissions_block"

    in_permissions_block = False
    permissions_lines: list[str] = []

    for line in content.splitlines():
        stripped = line.strip()

        if line.startswith("permissions:") or line.startswith("permissions :"):
            has_permissions = True
            in_permissions_block = True
            parts = stripped.split(":", 1)
            if len(parts) > 1 and parts[1].strip():
                permissions_value = parts[1].strip()
                in_permissions_block = False
            continue

        if in_permissions_block:
            if stripped and not line[0].isspace():
                in_permissions_block = False
            elif stripped:
                permissions_lines.append(stripped)

    if permissions_lines:
        permissions_value = "; ".join(permissions_lines)

    if not has_permissions:
        finding = "no_permissions_block"
    elif "write-all" in permissions_value:
        finding = "write-all"
        has_write = True
    elif "write" in permissions_value:
        finding = "has_write_scope"
        has_write = True
    else:
        finding = "compliant"

    return {
        "has_explicit_permissions": has_permissions,
        "permissions_value": permissions_value,
        "has_write_permissions": has_write,
        "finding": finding,
    }


def parse_actions_from_content(
    content: str, repo_name: str, workflow_path: str
) -> list[dict[str, str]]:
    """Extract all ``uses:`` action references from workflow file content.

    Pure function — no network, no side effects.
    """
    actions: list[dict[str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("uses:") or line.startswith("- uses:"):
            match = re.search(r'uses:\s*["\']?([^"\'#\s]+)', line)
            if match:
                ref = match.group(1)
                if ref.startswith("./"):
                    continue
                action_name, version = (
                    ref.rsplit("@", 1) if "@" in ref else (ref, "none")
                )
                actions.append(
                    {
                        "repo": repo_name,
                        "workflow_path": workflow_path,
                        "action_name": action_name,
                        "version": version,
                        "owner": action_name.split("/")[0]
                        if "/" in action_name
                        else action_name,
                    }
                )
    return actions


# ── Transform registry ────────────────────────────────────────────────
# Order matters: TimestampTransform runs before FlagTransform so that
# ``days_since_push`` is available when the stale flag is evaluated.
# Add new transforms here — no other files need to change.

TRANSFORMS: list[type[BaseTransform]] = [
    TimestampTransform,
    ReferenceClassifier,
    FlagTransform,
]
