"""Unit tests for core.config."""

import pytest
import yaml

from core.config import (
    AuditConfig,
    load_audit_config,
)


def test_defaults_all_stages_enabled():
    config = AuditConfig()
    audit = config.workflow_audit
    assert audit.collect_baseline_data is True
    assert audit.collect_additional_data is True
    assert audit.gen_posture_reports is True
    assert audit.actions_analysis is True
    assert audit.permissions_analysis is True
    assert audit.credentials_analysis is True
    assert audit.trigger_risk_analysis is True
    assert config.repo_list_file == "repo_list.yaml"


def test_load_returns_defaults_when_default_path_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = load_audit_config()
    assert config == AuditConfig()


def test_load_raises_when_explicit_path_missing(tmp_path):
    missing = tmp_path / "does_not_exist.yaml"
    with pytest.raises(FileNotFoundError):
        load_audit_config(missing)


def test_load_respects_stage_toggles(tmp_path):
    config_file = tmp_path / "audit_config.yaml"
    config_file.write_text(
        yaml.safe_dump(
            {
                "repo_list_file": "custom_repos.yaml",
                "workflow_audit": {
                    "collect_baseline_data": True,
                    "collect_additional_data": True,
                    "gen_posture_reports": False,
                    "actions_analysis": False,
                    "permissions_analysis": False,
                    "credentials_analysis": True,
                    "trigger_risk_analysis": False,
                },
            }
        )
    )

    config = load_audit_config(config_file)

    assert config.repo_list_file == "custom_repos.yaml"
    assert config.workflow_audit.gen_posture_reports is False
    assert config.workflow_audit.actions_analysis is False
    assert config.workflow_audit.credentials_analysis is True
    assert config.workflow_audit.trigger_risk_analysis is False


def test_load_fills_missing_fields_with_defaults(tmp_path):
    config_file = tmp_path / "partial.yaml"
    config_file.write_text(
        yaml.safe_dump(
            {
                "workflow_audit": {
                    "credentials_analysis": False,
                }
            }
        )
    )

    config = load_audit_config(config_file)

    assert config.repo_list_file == "repo_list.yaml"
    assert config.workflow_audit.collect_baseline_data is True
    assert config.workflow_audit.credentials_analysis is False


def test_empty_yaml_returns_defaults(tmp_path):
    config_file = tmp_path / "empty.yaml"
    config_file.write_text("")
    config = load_audit_config(config_file)
    assert config == AuditConfig()
