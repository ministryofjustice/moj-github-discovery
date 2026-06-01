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

    repo_list_file: str = "repo_list.yaml"
    workflow_audit: WorkflowAuditConfig = Field(default_factory=WorkflowAuditConfig)


DEFAULT_CONFIG_PATH = Path("config/audit_config.yaml")


def load_audit_config(config_path: Optional[Path] = None) -> AuditConfig:
    """Load an :class:`AuditConfig` from disk.

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
    if config_path is None:
        print(
            f"No config file specified, looking for default at {DEFAULT_CONFIG_PATH}...",
            file=sys.stderr,
        )
        resolved = DEFAULT_CONFIG_PATH
        if not resolved.exists():
            print(f"Default config file not found: {resolved}", file=sys.stderr)
            return AuditConfig()
    else:
        print(f"Loading config from {config_path}...", file=sys.stderr)
        resolved = Path(config_path)
        if not resolved.exists():
            print(f"Config file not found: {resolved}", file=sys.stderr)
            raise FileNotFoundError(f"Config file not found: {resolved}")

    print(f"Reading config from {resolved}...", file=sys.stderr)
    with resolved.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    return AuditConfig(**data)
