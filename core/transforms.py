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

from core.models import RepoData


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
        if data.repo_meta is None:
            return data

        now = datetime.now(timezone.utc)
        updates: dict = {}

        if data.repo_meta.pushed_at:
            pushed = datetime.fromisoformat(
                data.repo_meta.pushed_at.replace("Z", "+00:00")
            )
            updates["days_since_push"] = (now - pushed).days

        if data.repo_meta.created_at:
            created = datetime.fromisoformat(
                data.repo_meta.created_at.replace("Z", "+00:00")
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
        meta = data.repo_meta

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


# ── Transform registry ────────────────────────────────────────────────
# Order matters: TimestampTransform runs before FlagTransform so that
# ``days_since_push`` is available when the stale flag is evaluated.
# Add new transforms here — no other files need to change.

TRANSFORMS: list[type[BaseTransform]] = [
    TimestampTransform,
    ReferenceClassifier,
    FlagTransform,
]
