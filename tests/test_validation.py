"""Unit tests for core.validation."""

import pytest

from core.validation import direct_invocation_guard


def test_direct_invocation_guard_exits_with_code_1():
    with pytest.raises(SystemExit) as exc_info:
        direct_invocation_guard("scripts/alert_metrics.py")
    assert exc_info.value.code == 1


def test_direct_invocation_guard_prints_message(capsys):
    with pytest.raises(SystemExit):
        direct_invocation_guard("scripts/alert_metrics.py")
    captured = capsys.readouterr()
    assert "Error: Scripts must be run via audit-cli or main.py." in captured.err
    assert "uv run audit-cli --scripts alert_metrics --auth app" in captured.err


def test_direct_invocation_guard_uses_script_stem(capsys):
    with pytest.raises(SystemExit):
        direct_invocation_guard("scripts/list_repos.py")
    captured = capsys.readouterr()
    assert "--scripts list_repos" in captured.err


def test_direct_invocation_guard_handles_full_path(capsys):
    with pytest.raises(SystemExit):
        direct_invocation_guard(
            "/home/runner/work/repo/scripts/org_security_posture.py"
        )
    captured = capsys.readouterr()
    assert "--scripts org_security_posture" in captured.err
