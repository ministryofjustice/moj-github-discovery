"""Audit config loading for moj-github-discovery scripts.

The default config lives at ``config/audit_config.yaml`` relative to the
repository root. Callers may override it by passing an explicit path via
the ``--config-file`` CLI argument on any script that consumes this module.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import sys
import yaml
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path("config/audit_config.yaml")


class ListReposConfig(BaseModel):
    """Config for ``list_repos.py`` script."""

    database_filename: str = "repo_audit.db"  # SQLite cache file for repo audit data
    output_filename: str = "list_repos.xlsx"  # output file for repo summary data
    repo_limit: Optional[int] = 400
    resume: bool = (
        True  # whether to use database cache to skip endpoints already collected
    )
    sort_by_field: str = "pushed_at"  # field to sort by
    sort_ascending: bool = False  # sort order - descending by default


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
    workflow_audit: WorkflowAuditConfig = Field(default_factory=WorkflowAuditConfig)


def load_audit_config(config_path: Optional[Path] = None) -> AuditConfig:
    """Load an :class:`AuditConfig` from disk.

    Behaviour:

    - If the file at ``config_path`` exists, it will be loaded and parsed as YAML.
    - If the file does not exist and ``config_path`` is the default path, a warning will be printed and a default config will be returned.
    - If the file does not exist and ``config_path`` is not the default path, a FileNotFoundError will be raised.
    """
    resolved_path = config_path or DEFAULT_CONFIG_PATH

    if not resolved_path.exists():
        print(
            f"Warning: Config file not found at {resolved_path}. "
            "Using default config values. To fix this, create a config file at the default location or specify a path with --config-file.",
            file=sys.stderr,
        )
        return AuditConfig()

    print(f"Reading config from {resolved_path}...", file=sys.stderr)
    with resolved_path.open("r", encoding="utf-8") as fh:
        config_data = yaml.safe_load(fh) or {}

    return AuditConfig(**config_data)
