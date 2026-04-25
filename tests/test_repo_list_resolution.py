"""Unit tests for the repo list resolution order in github_workflow.stage_1."""

from unittest.mock import MagicMock, patch

import pytest

import github_workflow
from core.config import AuditConfig


def _make_args(**overrides):
    defaults = dict(
        repos=None,
        repo_file=None,
        limit=500,
        org="ministryofjustice",
    )
    defaults.update(overrides)
    return MagicMock(**defaults)


def test_explicit_repos_arg_wins(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = _make_args(repos=["ministryofjustice/foo", "ministryofjustice/bar"])
    config = AuditConfig()
    client = MagicMock()

    result = github_workflow.stage_1_resolve_repo_list(args, client, config)

    assert result == ["ministryofjustice/foo", "ministryofjustice/bar"]


def test_repo_file_arg_used_when_no_repos(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo_file = tmp_path / "custom.yaml"
    repo_file.write_text("repos:\n  - ministryofjustice/baz\n")

    args = _make_args(repo_file=str(repo_file))
    config = AuditConfig()
    client = MagicMock()

    with patch(
        "github_workflow.load_repo_list_file",
        return_value=["ministryofjustice/baz"],
    ) as mock_load:
        result = github_workflow.stage_1_resolve_repo_list(args, client, config)

    mock_load.assert_called_once_with(str(repo_file))
    assert result == ["ministryofjustice/baz"]


def test_config_repo_list_file_used_when_no_cli_args(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_repo_file = tmp_path / "from_config.yaml"
    config_repo_file.write_text("repos:\n  - ministryofjustice/qux\n")

    args = _make_args()
    config = AuditConfig(repo_list_file=str(config_repo_file))
    client = MagicMock()

    with patch(
        "github_workflow.load_repo_list_file",
        return_value=["ministryofjustice/qux"],
    ) as mock_load:
        result = github_workflow.stage_1_resolve_repo_list(args, client, config)

    mock_load.assert_called_once_with(str(config_repo_file))
    assert result == ["ministryofjustice/qux"]


def test_default_repo_list_yaml_in_cwd_used_when_no_cli_or_config(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    default_file = tmp_path / "repo_list.yaml"
    default_file.write_text("repos:\n  - ministryofjustice/default\n")

    args = _make_args()
    # repo_list_file in config points to a path that doesn't exist
    config = AuditConfig(repo_list_file="/nonexistent/path.yaml")
    client = MagicMock()

    with patch(
        "github_workflow.load_repo_list_file",
        return_value=["ministryofjustice/default"],
    ) as mock_load:
        result = github_workflow.stage_1_resolve_repo_list(args, client, config)

    mock_load.assert_called_once_with("repo_list.yaml")
    assert result == ["ministryofjustice/default"]


def test_falls_back_to_org_listing_when_nothing_else_available(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = _make_args()
    config = AuditConfig(repo_list_file="/nonexistent/path.yaml")
    client = MagicMock()

    with patch(
        "github_workflow.list_org_repos",
        return_value=["ministryofjustice/from_api"],
    ) as mock_list:
        result = github_workflow.stage_1_resolve_repo_list(args, client, config)

    mock_list.assert_called_once_with("ministryofjustice", client)
    assert result == ["ministryofjustice/from_api"]


def test_raises_when_org_listing_fails_and_no_other_source(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = _make_args()
    config = AuditConfig(repo_list_file="/nonexistent/path.yaml")
    client = MagicMock()

    with patch(
        "github_workflow.list_org_repos",
        side_effect=Exception("API down"),
    ):
        with pytest.raises(SystemExit, match="Unable to list repos"):
            github_workflow.stage_1_resolve_repo_list(args, client, config)
