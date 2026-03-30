"""Tests for presenter helpers in core/presenters.py."""

from __future__ import annotations

import pandas as pd

from core.models import RepoData, RepoDetails
from core.presenters import build_dashboard_dataframe, build_repo_summary_table
from tests.conftest import MockStorage


class TestBuildRepoSummaryTable:
    def test_empty_dataframe(self):
        df = pd.DataFrame()
        summary = build_repo_summary_table(df)

        assert summary["metric"].tolist() == [
            "repos_total",
            "repos_public",
            "repos_private",
            "repos_archived",
            "repos_with_dependabot_alerts",
            "repos_with_secret_alerts",
            "repos_with_code_scanning_alerts",
            "repos_unprotected_default_branch",
        ]
        assert summary["value"].tolist() == [0, 0, 0, 0, 0, 0, 0, 0]

    def test_counts_non_empty_dataframe(self):
        df = pd.DataFrame(
            [
                {
                    "private": False,
                    "archived": False,
                    "dependabot_alerts": 1,
                    "secret_scanning_alerts": 0,
                    "code_scanning_alerts": 0,
                    "default_branch_protected": True,
                },
                {
                    "private": True,
                    "archived": True,
                    "dependabot_alerts": 0,
                    "secret_scanning_alerts": 2,
                    "code_scanning_alerts": 3,
                    "default_branch_protected": False,
                },
            ]
        )

        summary = build_repo_summary_table(df)
        metrics = dict(zip(summary["metric"], summary["value"]))

        assert metrics["repos_total"] == 2
        assert metrics["repos_public"] == 1
        assert metrics["repos_private"] == 1
        assert metrics["repos_archived"] == 1
        assert metrics["repos_with_dependabot_alerts"] == 1
        assert metrics["repos_with_secret_alerts"] == 1
        assert metrics["repos_with_code_scanning_alerts"] == 1
        assert metrics["repos_unprotected_default_branch"] == 1


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
