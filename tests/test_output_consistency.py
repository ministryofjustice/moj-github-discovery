"""Consistency tests for script output path configuration."""

from core.config import AuditConfig
from core.output_paths import OutputPathResolver


def test_each_script_resolves_output_path_from_its_subdir(tmp_path):
    config = AuditConfig()
    outputs_root = tmp_path / "outputs"
    internal_root = tmp_path / "internal"
    resolver = OutputPathResolver(
        config=config,
        base_output_dir=str(outputs_root),
        base_internal_dir=str(internal_root),
    )

    expected = {
        "list_repos": (
            config.list_repos.output_subdir,
            config.list_repos.output_filename,
        ),
        "archive_repos": (
            config.archive_repos.output_subdir,
            config.archive_repos.output_filename,
        ),
        "alert_metrics": (
            config.alert_metrics.output_subdir,
            config.alert_metrics.output_filename,
        ),
        "org_security_posture": (
            config.org_security_posture.output_subdir,
            config.org_security_posture.output_filename,
        ),
        "lfs_script": (
            config.lfs_script.output_subdir,
            config.lfs_script.output_filename,
        ),
    }

    for _, (subdir, filename) in expected.values():
        resolved = resolver.script_output_file(subdir, filename)
        assert resolved == outputs_root / subdir / filename

    workflow_dir = resolver.script_output_dir(config.workflow_audit.output_subdir)
    workflow_repo_summary = (
        workflow_dir / f"{config.workflow_audit.output_prefix}_repo_summary.csv"
    )
    assert workflow_repo_summary == (
        outputs_root
        / config.workflow_audit.output_subdir
        / f"{config.workflow_audit.output_prefix}_repo_summary.csv"
    )


def test_multiple_scripts_use_distinct_output_subdirs():
    config = AuditConfig()

    subdirs = {
        config.list_repos.output_subdir,
        config.archive_repos.output_subdir,
        config.alert_metrics.output_subdir,
        config.org_security_posture.output_subdir,
        config.lfs_script.output_subdir,
        config.workflow_audit.output_subdir,
    }

    assert len(subdirs) == 6
