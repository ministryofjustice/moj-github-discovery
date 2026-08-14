"""Tests for presenter helpers in core/presenters.py."""

from __future__ import annotations

import pandas as pd

from core.models import (
    DefaultBranchCommitData,
    ForkTemplateData,
    LatestWorkflowRunData,
    RepoActionsPermissionsData,
    RepoData,
    RepoDetails,
    WorkflowData,
)
from core.presenters import (
    build_dashboard_dataframe,
    build_org_actions_posture_rows,
    build_org_ruleset_rows,
    build_org_webhook_rows,
    build_repo_summary_table,
    repo_data_to_dashboard_row,
    repo_data_to_list_row,
    workflow_repo_data_to_detail_rows,
    workflow_repo_data_to_summary_row,
    write_workflow_summary,
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


class TestWorkflowPresenterRows:
    def test_workflow_repo_data_to_summary_row(self):
        data = RepoData(
            repo_details=RepoDetails(
                full_name="org/repo",
                name="repo",
                archived=False,
                default_branch="main",
                visibility="private",
            ),
            workflows=WorkflowData(
                count=2,
                workflows=[
                    {"name": "CI", "path": ".github/workflows/ci.yml"},
                    {"name": "Release", "path": ".github/workflows/release.yml"},
                ],
            ),
            repo_actions_permissions=RepoActionsPermissionsData(
                enabled=True,
                allowed_actions="selected",
            ),
            latest_workflow_run=LatestWorkflowRunData(
                created_at="2026-08-13T00:00:00Z",
            ),
        )

        row = workflow_repo_data_to_summary_row("org/repo", data)

        assert row["repo"] == "org/repo"
        assert row["owner"] == "org"
        assert row["repo_name"] == "repo"
        assert row["workflow_count"] == 2
        assert row["has_workflows"] is True
        assert row["posture"] == "active_with_workflows"
        assert row["latest_workflow_run"] == "2026-08-13T00:00:00Z"

    def test_workflow_repo_data_to_detail_rows(self):
        data = RepoData(
            workflows=WorkflowData(
                count=1,
                workflows=[
                    {
                        "name": "CI",
                        "path": ".github/workflows/ci.yml",
                        "state": "active",
                    }
                ],
            )
        )

        rows = workflow_repo_data_to_detail_rows("org/repo", data)

        assert rows == [
            {
                "repo": "org/repo",
                "owner": "org",
                "repo_name": "repo",
                "workflow_name": "CI",
                "path": ".github/workflows/ci.yml",
                "state": "active",
            }
        ]


def test_write_workflow_summary_writes_expected_report(tmp_path):
    report_path = tmp_path / "summary.txt"
    repo_rows = [
        {
            "repo": "org/repo",
            "archived": False,
            "has_workflows": True,
            "workflow_count": 2,
            "actions_enabled": True,
            "disable_candidate": False,
        }
    ]
    detail_rows = [
        {
            "repo": "org/repo",
            "path": ".github/workflows/ci.yml",
        },
        {
            "repo": "org/repo",
            "path": ".github/workflows/release.yml",
        },
    ]

    write_workflow_summary(str(report_path), repo_rows, detail_rows)

    text = report_path.read_text(encoding="utf-8")
    assert "GITHUB ACTIONS WORKFLOW POSTURE - DISCOVERY REPORT" in text
    assert "Total repositories scanned:" in text
    assert "Total workflow files found:" in text
