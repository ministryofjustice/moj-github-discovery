"""Tests for utils/repo_list_maintenance.py selection behavior."""

from __future__ import annotations

from utils.repo_list_maintenance import select_repos_to_add


class TestSelectReposToAdd:
    def test_uses_target_count_without_prefix(self):
        repos_to_add = select_repos_to_add(
            recent_org_repos=["org/a", "org/b", "org/c"],
            existing_set={"org/a"},
            target_count=2,
            existing_count=1,
            prefix=None,
        )

        assert repos_to_add == ["org/b"]

    def test_ignores_target_count_with_prefix(self):
        repos_to_add = select_repos_to_add(
            recent_org_repos=["org/abc-a", "org/abc-b", "org/abc-c"],
            existing_set={"org/abc-a"},
            target_count=2,
            existing_count=1,
            prefix="abc-",
        )

        assert repos_to_add == ["org/abc-b", "org/abc-c"]
