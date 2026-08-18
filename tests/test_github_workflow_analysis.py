"""Unit tests for single-pass workflow content analysis in github_workflow."""

from core.config import AuditConfig
from scripts.github_workflow import analyse_workflow_file_contents


def _detail_row(repo: str, path: str) -> dict[str, str]:
    owner, repo_name = repo.split("/", 1)
    return {
        "repo": repo,
        "owner": owner,
        "repo_name": repo_name,
        "path": path,
        "workflow_name": "CI",
        "state": "active",
    }


def test_analyse_workflow_file_contents_emits_all_enabled_stage_rows():
    config = AuditConfig().workflow_audit

    rows = [_detail_row("ministryofjustice/example-repo", ".github/workflows/ci.yml")]
    contents = {
        "ministryofjustice/example-repo/.github/workflows/ci.yml": (
            "name: CI\n"
            "on:\n"
            "  push:\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  test:\n"
            "    permissions:\n"
            "      id-token: write\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
    }

    result = analyse_workflow_file_contents(rows, contents, config)

    assert len(result["actions"]) == 1
    assert result["actions"][0]["action_name"] == "actions/checkout"

    assert len(result["permissions"]) == 1
    assert result["permissions"][0]["repo"] == "ministryofjustice/example-repo"
    assert result["permissions"][0]["workflow_path"] == ".github/workflows/ci.yml"

    assert len(result["credentials"]) == 1
    assert result["credentials"][0]["posture"] in {
        "oidc",
        "mixed",
        "no_cloud_auth_detected",
        "long_lived_credentials",
    }

    assert len(result["triggers"]) == 1
    assert result["triggers"][0]["repo"] == "ministryofjustice/example-repo"


def test_analyse_workflow_file_contents_could_not_load_rows():
    config = AuditConfig().workflow_audit

    rows = [
        _detail_row("ministryofjustice/example-repo", ".github/workflows/missing.yml")
    ]
    contents = {
        "ministryofjustice/example-repo/.github/workflows/missing.yml": None,
    }

    result = analyse_workflow_file_contents(rows, contents, config)

    assert result["actions"] == []
    assert result["permissions"][0]["finding"] == "could_not_load"
    assert result["credentials"][0]["posture"] == "could_not_load"
    assert result["triggers"][0]["posture"] == "could_not_load"
