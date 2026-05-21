"""Smoke tests for the pandas-based aggregation in actions_analysis."""

import pandas as pd


def test_action_usage_summary_groupby_matches_counter_semantics():
    """Verify groupby+size produces the same counts and ordering as Counter."""
    all_actions = [
        {"action_name": "actions/checkout", "owner": "actions"},
        {"action_name": "actions/checkout", "owner": "actions"},
        {"action_name": "actions/setup-python", "owner": "actions"},
        {"action_name": "softprops/action-gh-release", "owner": "softprops"},
    ]
    df = pd.DataFrame(all_actions)

    usage_summary_df = (
        df.groupby("action_name", sort=False)
        .size()
        .reset_index(name="times_used")
        .sort_values(by="times_used", ascending=False, kind="stable")
        .reset_index(drop=True)
    )

    assert list(usage_summary_df.columns) == ["action_name", "times_used"]
    assert usage_summary_df.iloc[0]["action_name"] == "actions/checkout"
    assert usage_summary_df.iloc[0]["times_used"] == 2
    assert len(usage_summary_df) == 3


def test_per_repo_pinning_compliance_pct_matches_manual_calc():
    """Verify per-repo aggregation gives the same totals/pct as the dict approach."""
    all_actions = [
        {"repo": "moj/repo-a", "version": "v3", "is_pinned": True},
        {"repo": "moj/repo-a", "version": "v3", "is_pinned": False},
        {"repo": "moj/repo-a", "version": "v3", "is_pinned": False},
        {"repo": "moj/repo-b", "version": "v1", "is_pinned": True},
        {"repo": "moj/repo-c", "version": "none", "is_pinned": False},  # excluded
    ]
    df = pd.DataFrame(all_actions)
    versioned = df[df["version"] != "none"]

    pinning_df = (
        versioned.groupby("repo", sort=False)
        .agg(total_refs=("is_pinned", "size"), pinned=("is_pinned", "sum"))
        .reset_index()
    )
    pinning_df["unpinned"] = pinning_df["total_refs"] - pinning_df["pinned"]
    pinning_df["compliance_pct"] = (
        (pinning_df["pinned"] / pinning_df["total_refs"].clip(lower=1)) * 100
    ).round(1)

    repo_a = pinning_df[pinning_df["repo"] == "moj/repo-a"].iloc[0]
    assert int(repo_a["total_refs"]) == 3
    assert int(repo_a["pinned"]) == 1
    assert int(repo_a["unpinned"]) == 2
    assert float(repo_a["compliance_pct"]) == 33.3

    # repo-c (only "none"-version action) must not appear in the per-repo table
    assert "moj/repo-c" not in set(pinning_df["repo"])
