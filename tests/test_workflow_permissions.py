"""Tests for workflow permissions checking."""

from __future__ import annotations

from core.github_api import check_workflow_permissions
from core.models import WorkflowPermissionFinding


class FakeClient:
    """Mock HTTP client that returns predefined content."""

    def __init__(self, content: str | None = None):
        self._content = content

    def get(self, path: str) -> dict | None:
        if self._content is None:
            return None
        import base64

        encoded = base64.b64encode(self._content.encode()).decode()
        return {"encoding": "base64", "content": encoded}


class TestCheckWorkflowPermissions:
    def test_no_permissions_block(self) -> None:
        content = (
            "name: CI\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        )
        client = FakeClient(content)
        result = check_workflow_permissions(
            client, "org", "repo", ".github/workflows/ci.yml"
        )

        assert isinstance(result, WorkflowPermissionFinding)
        assert result.finding == "no_permissions_block"
        assert result.has_explicit_permissions is False
        assert result.has_write_permissions is False

    def test_write_all(self) -> None:
        content = "name: CI\npermissions: write-all\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        client = FakeClient(content)
        result = check_workflow_permissions(
            client, "org", "repo", ".github/workflows/ci.yml"
        )

        assert result.finding == "write-all"
        assert result.has_explicit_permissions is True
        assert result.has_write_permissions is True

    def test_has_write_scope(self) -> None:
        content = "name: CI\npermissions:\n  contents: read\n  packages: write\non:\n  push:\n"
        client = FakeClient(content)
        result = check_workflow_permissions(
            client, "org", "repo", ".github/workflows/ci.yml"
        )

        assert result.finding == "has_write_scope"
        assert result.has_explicit_permissions is True
        assert result.has_write_permissions is True
        assert "packages: write" in result.permissions_value

    def test_compliant_read_only(self) -> None:
        content = "name: CI\npermissions:\n  contents: read\non:\n  push:\n"
        client = FakeClient(content)
        result = check_workflow_permissions(
            client, "org", "repo", ".github/workflows/ci.yml"
        )

        assert result.finding == "compliant"
        assert result.has_explicit_permissions is True
        assert result.has_write_permissions is False

    def test_inline_read_all(self) -> None:
        content = "name: CI\npermissions: read-all\non:\n  push:\n"
        client = FakeClient(content)
        result = check_workflow_permissions(
            client, "org", "repo", ".github/workflows/ci.yml"
        )

        assert result.finding == "compliant"
        assert result.has_explicit_permissions is True

    def test_could_not_load(self) -> None:
        client = FakeClient(None)
        result = check_workflow_permissions(
            client, "org", "repo", ".github/workflows/ci.yml"
        )

        assert result.finding == "could_not_load"
        assert result.has_explicit_permissions is False

    def test_returns_correct_repo_and_path(self) -> None:
        content = "name: CI\non:\n  push:\n"
        client = FakeClient(content)
        result = check_workflow_permissions(
            client, "ministryofjustice", "my-repo", ".github/workflows/deploy.yml"
        )

        assert result.repo == "ministryofjustice/my-repo"
        assert result.workflow_path == ".github/workflows/deploy.yml"
