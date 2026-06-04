"""Audit config loading for moj-github-discovery scripts.

The default config lives at ``config/audit_config.yaml`` relative to the
repository root. Callers may override it by passing an explicit path via
the ``--config-file`` CLI argument on any script that consumes this module.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator

DEFAULT_CONFIG_PATH = Path("config/audit_config.yaml")


class LfsScriptConfig(BaseModel):
    """Config for ``lfs_script.py`` script."""

    database_path: str = "internal/lfs_audit.db"  # SQLite cache file for LFS audit data
    soft_limit_mb: int = 50  # soft file size limit in megabytes
    hard_limit_mb: int = 100  # hard file size limit in megabytes
    output_filename: str = (
        "repos_exceeding_thresholds.xlsx"  # output file for repos exceeding limits
    )
    use_cache: bool = (
        True  # whether to use database cache to skip repos already collected
    )


class AlertMetricsConfig(BaseModel):
    """Config for ``alert_metrics.py`` script."""

    output_filename: str = "alert_metrics.csv"  # output file for alert data
    max_alerts: Optional[int] = None  # max number of alerts to collect (for testing)
    repo_limit: Optional[int] = None  # max number of repos to audit (for testing)

    @field_validator("repo_limit", "max_alerts", mode="after")
    @classmethod
    def must_be_positive(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value <= 0:
            raise ValueError(f"Value must be a positive integer, got {value}")
        return value


class NamespaceCrossrefConfig(BaseModel):
    """Config for cross-referencing repos with external namespace data."""

    enabled: bool = False  # whether to perform cross-referencing
    target_repo: str = ""
    target_branch: str = "main"
    root_folder: str = ""

    @model_validator(mode="after")
    def validate_crossref(self) -> "NamespaceCrossrefConfig":
        for field_name in ["target_repo", "target_branch", "root_folder"]:
            if self.enabled and not self.__dict__.get(field_name):
                raise ValueError(
                    f"Namespace crossref is enabled but '{field_name}' is not set"
                )
        return self


class ArchiveReposConfig(BaseModel):
    """Config for ``archive_repos.py`` script."""

    database_path: str = (
        "internal/repo_audit.db"  # SQLite cache file for repo audit data
    )
    output_filename: str = "archive_repos.csv"  # output file for archived repo data
    page_num: Optional[int] = (
        None  # page number to process (for pagination of large orgs)
    )
    repo_limit: Optional[int] = (
        None  # limit total number of repos to process (for testing) - set to None for no limit
    )
    sort_by_field: str = "days_since_push"
    sort_ascending: bool = False  # sort order - descending by default
    use_cache: bool = (
        True  # whether to use database cache to skip endpoints already collected
    )
    namespace_crossref: NamespaceCrossrefConfig = Field(
        default_factory=NamespaceCrossrefConfig
    )


class ListReposConfig(BaseModel):
    """Config for ``list_repos.py`` script."""

    database_path: str = (
        "internal/repo_audit.db"  # SQLite cache file for repo audit data
    )
    output_filename: str = "list_repos.xlsx"  # output file for repo summary data
    repo_limit: Optional[int] = 400
    use_cache: bool = (
        True  # whether to use database cache to skip endpoints already collected
    )
    standard_endpoints_only: bool = (
        True  # whether to limit to standard audit endpoints or collect all available
    )
    sort_by_field: str = "pushed_at"  # field to sort by
    sort_ascending: bool = False  # sort order - descending by default


class OrgSecurityPostureConfig(BaseModel):
    """Config for ``org_security_posture.py`` script."""

    database_path: str = (
        "internal/org_security_posture.db"  # SQLite cache file for org posture data
    )
    output_filename: str = (
        "org_security_posture.xlsx"  # output file for org posture summary data
    )
    use_cache: bool = (
        True  # whether to reuse cached posture data from the org posture database
    )


class WorkflowAuditConfig(BaseModel):
    """Per-stage toggles for ``github_workflow.py``."""

    collect_baseline_data: bool = True  # stage 2
    collect_additional_data: bool = True  # stage 3
    gen_posture_reports: bool = True  # stage 4/5
    actions_analysis: bool = True  # stage 6
    permissions_analysis: bool = True  # stage 7
    credentials_analysis: bool = True  # stage 8
    trigger_risk_analysis: bool = True  # stage 9


class AuditConfig(BaseModel):
    """Top-level audit config loaded from ``audit_config.yaml``."""

    github_organization: str = "ministryofjustice"
    repo_list_file: str = "repo_list.yaml"
    lfs_script: LfsScriptConfig = Field(default_factory=LfsScriptConfig)
    alert_metrics: AlertMetricsConfig = Field(default_factory=AlertMetricsConfig)
    archive_repos: ArchiveReposConfig = Field(default_factory=ArchiveReposConfig)
    list_repos: ListReposConfig = Field(default_factory=ListReposConfig)
    org_security_posture: OrgSecurityPostureConfig = Field(
        default_factory=OrgSecurityPostureConfig
    )
    workflow_audit: WorkflowAuditConfig = Field(default_factory=WorkflowAuditConfig)


def load_audit_config(config_path: Optional[Path] = None) -> AuditConfig:
    """
    Load an :class:`AuditConfig` from disk.

    Behaviour:

    * If ``config_path`` is ``None``, the function looks for the default
      file at ``config/audit_config.yaml``. If that file is missing, a
      fully-defaulted :class:`AuditConfig` is returned (all stages on).
    * If ``config_path`` is provided but the file does not exist, a
      :class:`FileNotFoundError` is raised — the caller asked for a
      specific file and we should not silently fall back.
    * Missing fields in the YAML fall back to model defaults, so a
      partial config only needs to list the toggles being changed.
    """
    if config_path is not None:
        # Explicit override via CLI - must exist if provided
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found at {config_path}")
        resolved_path = config_path
    else:
        # No CLI override - fall back to default config file, then defaults if not found
        resolved_path = DEFAULT_CONFIG_PATH
        if not resolved_path.exists():
            return AuditConfig()  # return defaults if no config file found

    with resolved_path.open() as fh:
        config_data = yaml.safe_load(fh) or {}  # handle empty file case gracefully

    return AuditConfig(**config_data)
