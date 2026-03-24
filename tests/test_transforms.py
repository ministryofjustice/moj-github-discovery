"""Tests for core/transforms.py — pure data transforms."""

from __future__ import annotations

import pytest

from core.models import (
    AlertData,
    BranchProtection,
    CodeownersData,
    ReferenceData,
    ReferenceItem,
    RepoData,
    RepoDetails,
)
from core.transforms import (
    TRANSFORMS,
    BaseTransform,
    FlagTransform,
    ReferenceClassifier,
    TimestampTransform,
)


# ── BaseTransform ─────────────────────────────────────────────────────


class TestBaseTransform:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            BaseTransform()


# ── Transform registry ────────────────────────────────────────────────


class TestTransformRegistry:
    def test_order(self):
        assert TRANSFORMS == [TimestampTransform, ReferenceClassifier, FlagTransform]

    def test_all_have_name_and_apply(self):
        for cls in TRANSFORMS:
            t = cls()
            assert isinstance(t.name, str)
            # apply should accept and return RepoData
            result = t.apply(RepoData())
            assert isinstance(result, RepoData)


# ── TimestampTransform ────────────────────────────────────────────────


class TestTimestampTransform:
    def test_no_repo_meta_returns_unchanged(self):
        t = TimestampTransform()
        data = RepoData()
        result = t.apply(data)
        assert result.days_since_push is None
        assert result.age_days is None

    def test_computes_days_since_push(self):
        t = TimestampTransform()
        data = RepoData(
            repo_meta=RepoDetails(
                full_name="o/r",
                name="r",
                pushed_at="2020-01-01T00:00:00Z",
            )
        )
        result = t.apply(data)
        assert result.days_since_push is not None
        assert result.days_since_push > 365  # well over a year ago

    def test_computes_age_days(self):
        t = TimestampTransform()
        data = RepoData(
            repo_meta=RepoDetails(
                full_name="o/r",
                name="r",
                created_at="2020-01-01T00:00:00Z",
            )
        )
        result = t.apply(data)
        assert result.age_days is not None
        assert result.age_days > 365

    def test_both_timestamps(self):
        t = TimestampTransform()
        data = RepoData(
            repo_meta=RepoDetails(
                full_name="o/r",
                name="r",
                pushed_at="2024-01-01T00:00:00Z",
                created_at="2020-01-01T00:00:00Z",
            )
        )
        result = t.apply(data)
        assert result.days_since_push is not None
        assert result.age_days is not None
        assert result.age_days > result.days_since_push

    def test_no_timestamps_returns_unchanged(self):
        t = TimestampTransform()
        data = RepoData(repo_meta=RepoDetails(full_name="o/r", name="r"))
        result = t.apply(data)
        assert result.days_since_push is None
        assert result.age_days is None

    def test_does_not_mutate_input(self):
        t = TimestampTransform()
        data = RepoData(
            repo_meta=RepoDetails(
                full_name="o/r",
                name="r",
                pushed_at="2020-01-01T00:00:00Z",
            )
        )
        t.apply(data)
        assert data.days_since_push is None  # original unchanged


# ── ReferenceClassifier ──────────────────────────────────────────────


class TestReferenceClassifier:
    def test_no_references_returns_unchanged(self):
        t = ReferenceClassifier()
        data = RepoData()
        result = t.apply(data)
        assert result.references is None

    def test_classifies_active_and_archived(self):
        t = ReferenceClassifier()
        data = RepoData(
            references=ReferenceData(
                items=[
                    ReferenceItem(full_name="o/active1", archived=False),
                    ReferenceItem(full_name="o/active2", archived=False),
                    ReferenceItem(full_name="o/old", archived=True),
                ]
            )
        )
        result = t.apply(data)
        assert sorted(result.references.active_references) == ["o/active1", "o/active2"]
        assert result.references.archive_references == ["o/old"]

    def test_deduplicates_references(self):
        t = ReferenceClassifier()
        data = RepoData(
            references=ReferenceData(
                items=[
                    ReferenceItem(full_name="o/a", archived=False),
                    ReferenceItem(full_name="o/a", archived=False),
                ]
            )
        )
        result = t.apply(data)
        assert result.references.active_references == ["o/a"]

    def test_empty_items(self):
        t = ReferenceClassifier()
        data = RepoData(references=ReferenceData(items=[]))
        result = t.apply(data)
        assert result.references.active_references == []
        assert result.references.archive_references == []


# ── FlagTransform ─────────────────────────────────────────────────────


class TestFlagTransform:
    def test_no_data_empty_flags(self):
        t = FlagTransform()
        data = RepoData()
        result = t.apply(data)
        assert result.flags == []

    def test_archived_flag(self):
        t = FlagTransform()
        data = RepoData(repo_meta=RepoDetails(full_name="o/r", name="r", archived=True))
        result = t.apply(data)
        assert "archived" in result.flags

    def test_archived_with_open_issues(self):
        t = FlagTransform()
        data = RepoData(
            repo_meta=RepoDetails(
                full_name="o/r",
                name="r",
                archived=True,
                open_issues_count=5,
            )
        )
        result = t.apply(data)
        assert "archived" in result.flags
        assert "archived_open_issues" in result.flags

    def test_archived_with_stars_and_forks(self):
        t = FlagTransform()
        data = RepoData(
            repo_meta=RepoDetails(
                full_name="o/r",
                name="r",
                archived=True,
                stargazers_count=10,
                forks_count=3,
            )
        )
        result = t.apply(data)
        assert "archived_has_stars" in result.flags
        assert "archived_has_forks" in result.flags

    def test_archived_with_open_alerts(self):
        t = FlagTransform()
        data = RepoData(
            repo_meta=RepoDetails(full_name="o/r", name="r", archived=True),
            alerts=AlertData(dependabot_alerts=2),
        )
        result = t.apply(data)
        assert "archived_with_open_alerts" in result.flags

    def test_fork_flag(self):
        t = FlagTransform()
        data = RepoData(repo_meta=RepoDetails(full_name="o/r", name="r", fork=True))
        result = t.apply(data)
        assert "fork" in result.flags

    def test_disabled_flag(self):
        t = FlagTransform()
        data = RepoData(repo_meta=RepoDetails(full_name="o/r", name="r", disabled=True))
        result = t.apply(data)
        assert "disabled" in result.flags

    def test_unprotected_default_branch_flag(self):
        t = FlagTransform()
        data = RepoData(
            branch_protection=BranchProtection(default_branch_protected=False)
        )
        result = t.apply(data)
        assert "unprotected_default_branch" in result.flags

    def test_protected_branch_no_flag(self):
        t = FlagTransform()
        data = RepoData(
            branch_protection=BranchProtection(default_branch_protected=True)
        )
        result = t.apply(data)
        assert "unprotected_default_branch" not in result.flags

    def test_no_codeowners_flag(self):
        t = FlagTransform()
        data = RepoData(codeowners=CodeownersData(present=False))
        result = t.apply(data)
        assert "no_codeowners" in result.flags

    def test_codeowners_present_no_flag(self):
        t = FlagTransform()
        data = RepoData(codeowners=CodeownersData(present=True, path="CODEOWNERS"))
        result = t.apply(data)
        assert "no_codeowners" not in result.flags

    def test_stale_flag(self):
        t = FlagTransform()
        data = RepoData(days_since_push=400)
        result = t.apply(data)
        assert "stale" in result.flags

    def test_not_stale(self):
        t = FlagTransform()
        data = RepoData(days_since_push=100)
        result = t.apply(data)
        assert "stale" not in result.flags

    def test_multiple_flags_combined(self):
        t = FlagTransform()
        data = RepoData(
            repo_meta=RepoDetails(full_name="o/r", name="r", fork=True),
            branch_protection=BranchProtection(default_branch_protected=False),
            codeowners=CodeownersData(present=False),
            days_since_push=500,
        )
        result = t.apply(data)
        assert "fork" in result.flags
        assert "unprotected_default_branch" in result.flags
        assert "no_codeowners" in result.flags
        assert "stale" in result.flags

    def test_does_not_mutate_input(self):
        t = FlagTransform()
        data = RepoData(repo_meta=RepoDetails(full_name="o/r", name="r", archived=True))
        original_flags = data.flags.copy()
        t.apply(data)
        assert data.flags == original_flags


# ── Full pipeline ─────────────────────────────────────────────────────


class TestTransformPipeline:
    def test_all_transforms_in_order(self):
        """Run all transforms in registry order on a rich RepoData."""
        data = RepoData(
            repo_meta=RepoDetails(
                full_name="o/r",
                name="r",
                pushed_at="2020-01-01T00:00:00Z",
                created_at="2019-01-01T00:00:00Z",
            ),
            branch_protection=BranchProtection(default_branch_protected=False),
            codeowners=CodeownersData(present=False),
            references=ReferenceData(
                items=[
                    ReferenceItem(full_name="o/a", archived=False),
                    ReferenceItem(full_name="o/b", archived=True),
                ]
            ),
        )

        for cls in TRANSFORMS:
            data = cls().apply(data)

        # TimestampTransform ran
        assert data.days_since_push is not None
        assert data.age_days is not None
        # ReferenceClassifier ran
        assert data.references.active_references == ["o/a"]
        assert data.references.archive_references == ["o/b"]
        # FlagTransform ran (depends on TimestampTransform for stale)
        assert "stale" in data.flags
        assert "unprotected_default_branch" in data.flags
        assert "no_codeowners" in data.flags
