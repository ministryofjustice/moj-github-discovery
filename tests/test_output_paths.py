"""Unit tests for core.output_paths."""

from pathlib import Path

from core.config import AuditConfig
from core.output_paths import OutputPathResolver


def test_resolver_uses_base_dirs_not_config_roots():
    config = AuditConfig()
    resolver = OutputPathResolver(
        config=config,
        base_output_dir="base_outputs",
        base_internal_dir="base_internal",
    )

    assert resolver.outputs_root == Path("base_outputs")
    assert resolver.internal_root == Path("base_internal")


def test_script_output_dir_creates_dir(tmp_path):
    resolver = OutputPathResolver(
        config=AuditConfig(),
        base_output_dir=str(tmp_path / "outputs"),
        base_internal_dir=str(tmp_path / "internal"),
    )

    output_dir = resolver.script_output_dir("github_alerts")

    assert output_dir.exists()
    assert output_dir == tmp_path / "outputs" / "github_alerts"


def test_script_output_file_path(tmp_path):
    resolver = OutputPathResolver(
        config=AuditConfig(),
        base_output_dir=str(tmp_path / "outputs"),
        base_internal_dir=str(tmp_path / "internal"),
    )

    output_file = resolver.script_output_file("list_repos", "list_repos.xlsx")

    assert output_file == tmp_path / "outputs" / "list_repos" / "list_repos.xlsx"


def test_database_path_relative_no_double_prefix(tmp_path):
    resolver = OutputPathResolver(
        config=AuditConfig(),
        base_output_dir=str(tmp_path / "outputs"),
        base_internal_dir=str(tmp_path / "internal"),
    )

    db_path = resolver.database_path("internal/audit.db")

    assert db_path == tmp_path / "internal" / "audit.db"


def test_database_path_absolute_passthrough():
    resolver = OutputPathResolver(
        config=AuditConfig(),
        base_output_dir="outputs",
        base_internal_dir="internal",
    )

    absolute = "/tmp/custom.db"
    db_path = resolver.database_path(absolute)

    assert db_path == Path(absolute)
