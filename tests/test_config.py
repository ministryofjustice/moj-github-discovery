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


def test_script_output_subdir_python_fallback_defaults():
    config = AuditConfig()

    assert config.list_repos.output_subdir == "list_repos"
    assert config.archive_repos.output_subdir == "archive_repos"
    assert config.alert_metrics.output_subdir == "alert_metrics"
    assert config.org_security_posture.output_subdir == "org_security_posture"
    assert config.lfs_script.output_subdir == "lfs_analysis"
    assert config.workflow_audit.output_subdir == "github_workflow_posture"


def test_output_subdir_can_be_overridden_from_config_file(tmp_path):
    config_file = tmp_path / "audit_config.yaml"
    config_file.write_text(
        yaml.safe_dump(
            {
                "list_repos": {"output_subdir": "custom_list_output"},
                "alert_metrics": {"output_subdir": "alerts_custom"},
            }
        )
    )

    config = load_audit_config(config_file)

    assert config.list_repos.output_subdir == "custom_list_output"
    assert config.alert_metrics.output_subdir == "alerts_custom"


def test_script_output_subdir_from_yaml(tmp_path):
    config_file = tmp_path / "audit_config.yaml"
    config_file.write_text(
        yaml.safe_dump(
            {
                "archive_repos": {"output_subdir": "custom_archive_dir"},
            }
        )
    )

    config = load_audit_config(config_file)

    assert config.archive_repos.output_subdir == "custom_archive_dir"


def test_load_returns_defaults_when_default_path_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = load_audit_config()
    assert config == AuditConfig()


def test_load_raises_when_explicit_path_missing(tmp_path):
    missing = tmp_path / "does_not_exist.yaml"
    with pytest.raises(FileNotFoundError):
        load_audit_config(missing)


def test_load_returns_config_from_file(tmp_path):
    config_file = tmp_path / "audit_config.yaml"
    config_file.write_text("repo_list_file: custom_repos.yaml")
    config = load_audit_config(config_file)
    assert config.repo_list_file == "custom_repos.yaml"


def test_load_respects_archive_repos_config_overrides(tmp_path):
    config_file = tmp_path / "audit_config.yaml"
    config_file.write_text(
        yaml.safe_dump(
            {
                "repo_list_file": "custom_repos.yaml",
                "archive_repos": {
                    "output_filename": "custom_archive_output.xlsx",
                    "use_cache": False,
                    "namespace_crossref": {
                        "enabled": True,
                        "target_repo": "custom_namespace_repo",
                        "target_branch": "custom_namespace_branch",
                        "root_folder": "custom_namespace_root",
                    },
                },
            }
        )
    )

    config = load_audit_config(config_file)

    assert config.repo_list_file == "custom_repos.yaml"
    assert config.archive_repos.output_filename == "custom_archive_output.xlsx"
    assert config.archive_repos.use_cache is False
    assert config.archive_repos.namespace_crossref.enabled is True
    assert (
        config.archive_repos.namespace_crossref.target_repo == "custom_namespace_repo"
    )
    assert (
        config.archive_repos.namespace_crossref.target_branch
        == "custom_namespace_branch"
    )
    assert (
        config.archive_repos.namespace_crossref.root_folder == "custom_namespace_root"
    )


def test_load_respects_alert_metrics_config(tmp_path):
    config_file = tmp_path / "audit_config.yaml"
    config_file.write_text(
        yaml.safe_dump(
            {
                "alert_metrics": {
                    "output_filename": "custom_alerts.csv",
                    "max_alerts": 500,
                    "repo_limit": 50,
                }
            }
        )
    )

    config = load_audit_config(config_file)

    assert config.alert_metrics.output_filename == "custom_alerts.csv"
    assert config.alert_metrics.max_alerts == 500
    assert config.alert_metrics.repo_limit == 50


def test_load_respects_org_security_posture_config_overrides(tmp_path):
    config_file = tmp_path / "audit_config.yaml"
    config_file.write_text(
        yaml.safe_dump(
            {
                "repo_list_file": "custom_repos.yaml",
                "org_security_posture": {
                    "database_path": "custom_org_posture.db",
                    "output_filename": "custom_org_posture.xlsx",
                    "use_cache": False,
                },
            }
        )
    )

    config = load_audit_config(config_file)

    assert config.repo_list_file == "custom_repos.yaml"
    assert config.org_security_posture.database_path == "custom_org_posture.db"
    assert config.org_security_posture.output_filename == "custom_org_posture.xlsx"
    assert config.org_security_posture.use_cache is False


def test_load_respects_list_repos_config_overrides(tmp_path):
    config_file = tmp_path / "audit_config.yaml"
    config_file.write_text(
        yaml.safe_dump(
            {
                "repo_list_file": "custom_list_repos_repos.yaml",
                "list_repos": {
                    "output_filename": "custom_list_repos_output.xlsx",
                    "use_cache": False,
                    "standard_endpoints_only": False,
                    "sort_by_field": "created_at",
                    "sort_ascending": True,
                },
            }
        )
    )

    config = load_audit_config(config_file)

    assert config.repo_list_file == "custom_list_repos_repos.yaml"
    assert config.list_repos.output_filename == "custom_list_repos_output.xlsx"
    assert config.list_repos.use_cache is False
    assert config.list_repos.standard_endpoints_only is False
    assert config.list_repos.sort_by_field == "created_at"
    assert config.list_repos.sort_ascending is True


def test_load_respects_workflow_audit_config_overrides(tmp_path):
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
