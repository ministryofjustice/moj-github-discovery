from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.config import AuditConfig
from main import SCRIPTS, _parse_args, base_directory_setup, main


# Parse_Args Tests
def test_parse_args_defaults():
    args = _parse_args([])
    assert args.config_file is None
    assert args.scripts is None
    assert not args.all
    assert args.auth is None


def test_parse_args_single_script():
    args = _parse_args(["--scripts", "alert_metrics"])
    assert args.scripts == ["alert_metrics"]
    assert not args.all


def test_parse_args_all_flag():
    args = _parse_args(["--all"])
    assert args.all
    assert args.scripts is None


def test_parse_args_auth_choice():
    args = _parse_args(["--auth", "pat"])
    assert args.auth == "pat"


def test_parse_args_invalid_script():
    with pytest.raises(SystemExit):
        _parse_args(["--scripts", "nonexistent_script"])


def test_parse_args_config_file(tmp_path):
    custom_config = tmp_path / "custom_config.yaml"
    custom_config.write_text("dummy: config")
    args = _parse_args(["--config-file", str(custom_config)])
    assert args.config_file == custom_config


def test_parse_args_repos():
    args = _parse_args(
        ["--scripts", "github_workflow", "--repos", "owner/repo1", "owner/repo2"]
    )
    assert args.repos == ["owner/repo1", "owner/repo2"]


# Validation Tests


def test_no_scripts_or_all_exits(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")
    with pytest.raises(SystemExit) as exc_info:
        main(["--config-file", str(config_file)])
    assert exc_info.value.code != 0


def test_repos_arg_rejected_for_org_security_posture(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "--config-file",
                str(config_file),
                "--scripts",
                "org_security_posture",
                "--repos",
                "owner/repo1",
                "owner/repo2",
            ]
        )
    assert exc_info.value.code != 0


# Script Execution Tests
def _make_mock_scripts():
    return {name: MagicMock() for name in SCRIPTS}


def test_single_script_execution(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")
    mock_scripts = _make_mock_scripts()
    with patch.dict(SCRIPTS, mock_scripts):
        main(["--config-file", str(config_file), "--scripts", "alert_metrics"])
    mock_scripts["alert_metrics"].run.assert_called_once()


def test_all_scripts_execution(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")
    mock_scripts = _make_mock_scripts()
    with patch.dict(SCRIPTS, mock_scripts):
        main(["--config-file", str(config_file), "--all"])
    for script in mock_scripts.values():
        script.run.assert_called_once()


def test_multiple_scripts_execution(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")
    mock_scripts = _make_mock_scripts()
    with patch.dict(SCRIPTS, mock_scripts):
        main(
            [
                "--config-file",
                str(config_file),
                "--scripts",
                "alert_metrics",
                "github_workflow",
            ]
        )
    mock_scripts["alert_metrics"].run.assert_called_once()
    mock_scripts["github_workflow"].run.assert_called_once()


def test_repos_kwarg_passed_to_alert_metrics(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")

    mock_scripts = _make_mock_scripts()

    with (
        patch("main.SCRIPTS", mock_scripts),
        patch("main.load_audit_config"),
        patch("main.base_directory_setup", return_value=("outputs", "internal")),
    ):
        main(
            [
                "--config-file",
                str(config_file),
                "--scripts",
                "alert_metrics",
                "--repos",
                "owner/repo1",
                "owner/repo2",
            ]
        )
    call_kwargs = mock_scripts["alert_metrics"].run.call_args.kwargs
    assert call_kwargs.get("repos") == ["owner/repo1", "owner/repo2"]


def test_repos_kwarg_passed_to_github_workflow(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")

    mock_scripts = _make_mock_scripts()

    with (
        patch("main.SCRIPTS", mock_scripts),
        patch("main.load_audit_config"),
        patch("main.base_directory_setup", return_value=("outputs", "internal")),
    ):
        main(
            [
                "--config-file",
                str(config_file),
                "--scripts",
                "github_workflow",
                "--repos",
                "owner/repo1",
                "owner/repo2",
            ]
        )

    call_kwargs = mock_scripts["github_workflow"].run.call_args.kwargs
    assert call_kwargs.get("repos") == ["owner/repo1", "owner/repo2"]


def test_repos_kwarg_passed_to_list_repos(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")

    mock_scripts = _make_mock_scripts()

    with (
        patch("main.SCRIPTS", mock_scripts),
        patch("main.load_audit_config"),
        patch("main.base_directory_setup", return_value=("outputs", "internal")),
    ):
        main(
            [
                "--config-file",
                str(config_file),
                "--scripts",
                "list_repos",
                "--repos",
                "owner/repo1",
                "owner/repo2",
            ]
        )
    call_kwargs = mock_scripts["list_repos"].run.call_args.kwargs
    assert call_kwargs.get("repos") == ["owner/repo1", "owner/repo2"]


def test_repos_kwarg_passed_to_archive_repos(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")

    mock_scripts = _make_mock_scripts()

    with (
        patch("main.SCRIPTS", mock_scripts),
        patch("main.load_audit_config"),
        patch("main.base_directory_setup", return_value=("outputs", "internal")),
    ):
        main(
            [
                "--config-file",
                str(config_file),
                "--scripts",
                "archive_repos",
                "--repos",
                "owner/repo1",
                "owner/repo2",
            ]
        )
    call_kwargs = mock_scripts["archive_repos"].run.call_args.kwargs
    assert call_kwargs.get("repos") == ["owner/repo1", "owner/repo2"]


def test_repos_kwarg_passed_to_lfs_script(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")

    mock_scripts = _make_mock_scripts()

    with (
        patch("main.SCRIPTS", mock_scripts),
        patch("main.load_audit_config"),
        patch("main.base_directory_setup", return_value=("outputs", "internal")),
    ):
        main(
            [
                "--config-file",
                str(config_file),
                "--scripts",
                "lfs_script",
                "--repos",
                "owner/repo1",
                "owner/repo2",
            ]
        )
    call_kwargs = mock_scripts["lfs_script"].run.call_args.kwargs
    assert call_kwargs.get("repos") == ["owner/repo1", "owner/repo2"]


# Summary / Exit Code Tests


def test_failed_script_exits_nonzero(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")

    mock_scripts = _make_mock_scripts()
    mock_scripts["list_repos"].run.side_effect = Exception("failed")

    with (
        patch("main.SCRIPTS", mock_scripts),
        patch("main.load_audit_config"),
        patch("main.base_directory_setup", return_value=("outputs", "internal")),
        pytest.raises(SystemExit) as exc_info,
    ):
        main(["--config-file", str(config_file), "--scripts", "list_repos"])
    assert exc_info.value.code != 0


def test_successful_script_exits_zero(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("dummy: config")

    mock_scripts = _make_mock_scripts()

    with (
        patch("main.SCRIPTS", mock_scripts),
        patch("main.load_audit_config"),
        patch("main.base_directory_setup", return_value=("outputs", "internal")),
    ):
        try:
            main(["--config-file", str(config_file), "--scripts", "list_repos"])
            exit_code = 0
        except SystemExit as exc_info:
            exit_code = exc_info.value.code
    assert exit_code == 0


def test_base_directory_setup_returns_fixed_directories():
    """Verify base_directory_setup returns fixed output and internal dirs."""
    config = AuditConfig()

    outputs, internal = base_directory_setup(config)

    assert outputs == "outputs"
    assert internal == "internal"
    assert Path("outputs").exists()
    assert Path("internal").exists()
