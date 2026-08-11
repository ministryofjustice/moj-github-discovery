"""Tests for presenter helpers in core/presenters.py."""

from __future__ import annotations

import pandas as pd

from core.models import DefaultBranchCommitData, ForkTemplateData, RepoData, RepoDetails
from core.presenters import (
    build_dashboard_dataframe,
    build_repo_summary_table,
    repo_data_to_dashboard_row,
    repo_data_to_list_row,
)
from tests.conftest import MockStorage


class TestBuildRepoSummaryTable:
    def test_empty_dataframe(self):
        df = pd.DataFrame()
        summary = build_repo_summary_table(df)

        assert summary["metric"].tolist() == [
            "repos_total",
            "repos_public",
            "repos_private",
            "repos_internal",
            "repos_archived",
            "repos_unprotected_default_branch",
            "repos_using_classic_branch_protection",
            "repos_with_active_rulesets",
        ]
        assert summary["value"].tolist() == [0, 0, 0, 0, 0, 0, 0, 0]

    def test_counts_non_empty_dataframe(self):
        df = pd.DataFrame(
            [
                {
                    "visibility": "public",
                    "archived": False,
                    "default_branch_protected": True,
                    "branch_protection_enabled": True,
                    "has_active_rulesets": False,
                },
                {
                    "visibility": "private",
                    "archived": True,
                    "default_branch_protected": False,
                    "branch_protection_enabled": False,
                    "has_active_rulesets": False,
                },
            ]
        )

        summary = build_repo_summary_table(df)
        metrics = dict(zip(summary["metric"], summary["value"]))

        assert metrics["repos_total"] == 2
        assert metrics["repos_public"] == 1
        assert metrics["repos_private"] == 1
        assert metrics["repos_internal"] == 0
        assert metrics["repos_archived"] == 1
        assert metrics["repos_unprotected_default_branch"] == 1
        assert metrics["repos_using_classic_branch_protection"] == 1
        assert metrics["repos_with_active_rulesets"] == 0


class TestBuildDashboardDataframe:
    def test_maps_storage_rows(self):
        storage = MockStorage()
        storage.upsert(
            "org/repo",
            RepoData(repo_details=RepoDetails(full_name="org/repo", name="repo")),
        )

        df = build_dashboard_dataframe(storage)

        assert len(df) == 1
        assert df.iloc[0]["repo"] == "org/repo"


class TestPresenterFallbacks:
    def test_list_row_uses_na_for_non_fork_when_fork_template_missing(self):
        row = repo_data_to_list_row(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    fork=False,
                )
            ),
        )
        assert row["fork"] is False
        assert row["fork_source"] == "N/A"

    def test_list_row_falls_back_last_pushed_at_to_last_push_activity(self):
        row = repo_data_to_list_row(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    pushed_at="2026-08-01T10:00:00Z",
                ),
                default_branch_commit=DefaultBranchCommitData(last_pushed_at=None),
            ),
        )
        assert row["last_push_activity"] == "2026-08-01T10:00:00Z"
        assert row["last_pushed_at"] == "2026-08-01T10:00:00Z"

    def test_list_row_visibility_defaults_to_unknown(self):
        row = repo_data_to_list_row(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    visibility=None,
                )
            ),
        )
        assert row["visibility"] == "unknown"

    def test_list_row_uses_parent_repo_full_name_from_repo_details(self):
        row = repo_data_to_list_row(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    fork=True,
                    parent_repo_full_name="upstream/parent",
                ),
            ),
        )
        assert row["fork"] is True
        assert row["fork_source"] == "upstream/parent"

    def test_list_row_uses_unknown_for_missing_fork_source_when_is_fork_true(self):
        row = repo_data_to_list_row(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    fork=True,
                ),
                fork_template=ForkTemplateData(is_fork=True, fork_source=None),
            ),
        )
        assert row["fork"] is True
        assert row["fork_source"] == "UNKNOWN"

    def test_dashboard_row_last_pushed_at_falls_back_to_last_push_activity(self):
        row = repo_data_to_dashboard_row(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    pushed_at="2026-08-01T10:00:00Z",
                ),
                default_branch_commit=DefaultBranchCommitData(last_pushed_at=None),
            ),
        )
        assert row["last_push_activity"] == "2026-08-01T10:00:00Z"
        assert row["last_pushed_at"] == "2026-08-01T10:00:00Z"

    def test_list_row_empty_repo_uses_na_for_push_timestamps_and_flag(self):
        row = repo_data_to_list_row(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    pushed_at=None,
                ),
                default_branch_commit=DefaultBranchCommitData(last_pushed_at=None),
            ),
        )
        assert row["last_push_activity"] == "N/A"
        assert row["last_pushed_at"] == "N/A"
        assert "empty_repo_no_push_activity" in row["flags"]

    def test_branch_protection_not_enforced_flag_when_no_enforcement_rules(self):
        from core.models import BranchProtection

        row = repo_data_to_list_row(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(full_name="org/repo", name="repo"),
                branch_protection=BranchProtection(
                    branch_protection_enabled=True,
                    default_branch_protected=True,
                    enforce_admins_enabled=False,
                    required_approving_review_count=0,
                    required_signatures_enabled=False,
                    require_code_owner_reviews=False,
                ),
            ),
        )
        assert "branch_protection_not_enforced" in row["flags"]

    def test_branch_protection_not_enforced_absent_when_enforcement_active(self):
        from core.models import BranchProtection

        row = repo_data_to_list_row(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(full_name="org/repo", name="repo"),
                branch_protection=BranchProtection(
                    branch_protection_enabled=True,
                    default_branch_protected=True,
                    required_approving_review_count=1,
                ),
            ),
        )
        assert "branch_protection_not_enforced" not in row["flags"]

    def test_dashboard_row_empty_repo_uses_na_for_push_timestamps_and_flag(self):
        row = repo_data_to_dashboard_row(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    pushed_at=None,
                ),
                default_branch_commit=DefaultBranchCommitData(last_pushed_at=None),
            ),
        )
        assert row["last_push_activity"] == "N/A"
        assert row["last_pushed_at"] == "N/A"
        assert "empty_repo_no_push_activity" in row["flags"]
