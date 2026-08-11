from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from core.config import AuditConfig
from core.repo_list import (
    iter_repo_batches,
    load_repo_list_file,
    load_repo_list_yaml,
    resolve_repo_selection,
)


def test_load_repo_list_yaml_with_repos_key(tmp_path):
    path = tmp_path / "repos.yaml"
    path.write_text(
        """
repos:
  - dummyorg/repo-1
  - dummyorg/repo-1
  - dummyorg/repo-2
""".strip()
    )

    result = load_repo_list_yaml(path)

    assert result == [
        "dummyorg/repo-1",
        "dummyorg/repo-2",
    ]


def test_load_repo_list_yaml_with_root_list(tmp_path):
    path = tmp_path / "repos.yaml"
    path.write_text(
        """
- dummyorg/repo-1
- dummyorg/repo-2
""".strip()
    )

    result = load_repo_list_yaml(path)

    assert result == [
        "dummyorg/repo-1",
        "dummyorg/repo-2",
    ]


def test_load_repo_list_yaml_invalid_entry(tmp_path):
    path = tmp_path / "repos.yaml"
    path.write_text(
        """
repos:
  - invalid
""".strip()
    )

    with pytest.raises(ValueError, match="Invalid repo entry"):
        load_repo_list_yaml(path)


def test_load_repo_list_file_text_compatibility(tmp_path):
    path = tmp_path / "repos.txt"
    path.write_text(
        """
# ignored comment
dummyorg/repo-1
dummyorg/repo-2
""".strip()
    )

    result = load_repo_list_file(path)

    assert result == [
        "dummyorg/repo-1",
        "dummyorg/repo-2",
    ]


@patch.dict(os.environ, {"GH_ORG": "dummyorg", "GH_TOKEN": "test-token"})
def test_resolve_repo_selection_repos_cli_wins(tmp_path):
    config = AuditConfig(
        default_repo_list=str(tmp_path / "repos.yaml"),
        repo_search_scope="file",
        repo_limit=None,
    )

    result = resolve_repo_selection(
        config,
        auth=None,
        repos=["dummyorg/repo-a", "dummyorg/repo-b"],
    )

    assert result == ["dummyorg/repo-a", "dummyorg/repo-b"]


@patch.dict(os.environ, {"GH_ORG": "dummyorg", "GH_TOKEN": "test-token"})
def test_resolve_repo_selection_repo_file_takes_precedence(tmp_path):
    config_file = tmp_path / "config_repos.yaml"
    config_file.write_text("repos:\n  - dummyorg/config-repo\n")
    override_file = tmp_path / "override_repos.yaml"
    override_file.write_text("repos:\n  - dummyorg/override-repo\n")

    config = AuditConfig(
        default_repo_list=str(config_file),
        repo_search_scope="org",
        repo_limit=None,
    )

    result = resolve_repo_selection(config, auth=None, repo_file=override_file)

    assert result == ["dummyorg/override-repo"]


@patch.dict(os.environ, {"GH_ORG": "dummyorg", "GH_TOKEN": "test-token"})
def test_resolve_repo_selection_rejects_repos_and_repo_file(tmp_path):
    config = AuditConfig(default_repo_list=str(tmp_path / "repos.yaml"))
    with pytest.raises(ValueError, match="mutually exclusive"):
        resolve_repo_selection(
            config,
            auth=None,
            repos=["dummyorg/repo-a"],
            repo_file=tmp_path / "repos.yaml",
        )


@patch.dict(os.environ, {"GH_ORG": "dummyorg", "GH_TOKEN": "test-token"})
def test_resolve_repo_selection_file_scope_requires_existing_default_file(tmp_path):
    config = AuditConfig(
        default_repo_list=str(tmp_path / "missing.yaml"),
        repo_search_scope="file",
    )
    with pytest.raises(FileNotFoundError, match="default_repo_list"):
        resolve_repo_selection(config, auth=None)


@patch.dict(os.environ, {"GH_ORG": "dummyorg", "GH_TOKEN": "test-token"})
def test_resolve_repo_selection_file_scope_applies_global_limit(tmp_path):
    default_file = tmp_path / "repos.yaml"
    default_file.write_text(
        "repos:\n  - dummyorg/repo-a\n  - dummyorg/repo-b\n  - dummyorg/repo-c\n"
    )
    config = AuditConfig(
        default_repo_list=str(default_file),
        repo_search_scope="file",
        repo_limit=2,
    )

    result = resolve_repo_selection(config, auth=None)

    assert result == ["dummyorg/repo-a", "dummyorg/repo-b"]


@patch.dict(os.environ, {"GH_ORG": "dummyorg", "GH_TOKEN": "test-token"})
def test_resolve_repo_selection_org_scope_uses_collector_and_limit(tmp_path):
    config = AuditConfig(
        github_organization="dummyorg",
        default_repo_list=str(tmp_path / "repos.yaml"),
        repo_search_scope="org",
        repo_limit=1,
    )
    with patch(
        "core.repo_list.RepoListCollector.collect", return_value=["a/b", "c/d"]
    ) as mock_collect:
        result = resolve_repo_selection(config, auth="pat")

    mock_collect.assert_called_once_with(
        "dummyorg",
        sort="pushed",
        direction="asc",
    )
    assert result == ["a/b"]


@patch.dict(os.environ, {"GH_ORG": "dummyorg", "GH_TOKEN": "test-token"})
def test_resolve_repo_selection_org_scope_without_limit_returns_all(tmp_path):
    config = AuditConfig(
        github_organization="dummyorg",
        default_repo_list=str(tmp_path / "repos.yaml"),
        repo_search_scope="org",
        repo_limit=None,
    )
    with patch(
        "core.repo_list.RepoListCollector.collect",
        return_value=["a/b", "c/d", "e/f"],
    ) as mock_collect:
        result = resolve_repo_selection(config, auth="pat")

    mock_collect.assert_called_once_with(
        "dummyorg",
        sort="pushed",
        direction="asc",
    )
    assert result == ["a/b", "c/d", "e/f"]


def test_iter_repo_batches_splits_into_expected_chunks():
    repos = [f"owner/repo-{i}" for i in range(1, 6)]
    batches = list(iter_repo_batches(repos, 2))
    assert batches == [
        ["owner/repo-1", "owner/repo-2"],
        ["owner/repo-3", "owner/repo-4"],
        ["owner/repo-5"],
    ]


def test_iter_repo_batches_rejects_non_positive_batch_size():
    with pytest.raises(ValueError, match="batch_size"):
        list(iter_repo_batches(["owner/repo-1"], 0))
