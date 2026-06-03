"""Audit config loading for moj-github-discovery scripts.

The default config lives at ``config/audit_config.yaml`` relative to the
repository root. Callers may override it by passing an explicit path via
the ``--config-file`` CLI argument on any script that consumes this module.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path("config/audit_config.yaml")


class ListReposConfig(BaseModel):
    """Config for ``list_repos.py`` script."""

    database_path: str = (
        "internal/repo_audit.db"  # SQLite cache file for repo audit data
    )
    output_filename: str = "list_repos.xlsx"  # output file for repo summary data
    repo_limit: Optional[int] = 400
    resume: bool = (
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
    resume: bool = (
        True  # whether to use database cache to skip endpoints already collected
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
