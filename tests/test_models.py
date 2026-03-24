"""Tests for core/models.py — Pydantic data models."""

from __future__ import annotations


import pytest
from pydantic import ValidationError

from core.models import (
    AlertData,
    BranchProtection,
    CodeownersData,
    CommunityProfile,
    DependencyGraphData,
    FieldDefinition,
    FieldsConfig,
    FieldType,
    ForkTemplateData,
    OrgActionsData,
    OrgMembersData,
    OrgRulesetsData,
    OrgWebhooksData,
    ReferenceData,
    ReferenceItem,
    RepoData,
    RepoDetails,
    WorkflowAnalysis,
    WorkflowData,
)


# ── FieldType Enum ────────────────────────────────────────────────────


class TestFieldType:
    def test_all_types_present(self):
        assert set(FieldType) == {
            FieldType.string,
            FieldType.integer,
            FieldType.boolean,
            FieldType.date,
            FieldType.json,
        }

    def test_string_values(self):
        assert FieldType.string.value == "string"
        assert FieldType.integer.value == "integer"


# ── FieldDefinition / FieldsConfig ───────────────────────────────────


class TestFieldDefinition:
    def test_minimal(self):
        fd = FieldDefinition(
            source="repo_meta.name", column="Name", type=FieldType.string
        )
        assert fd.source == "repo_meta.name"
        assert fd.default is None

    def test_with_default(self):
        fd = FieldDefinition(
            source="a.b", column="C", type=FieldType.integer, default=0
        )
        assert fd.default == 0


class TestFieldsConfig:
    def test_validates_list(self):
        cfg = FieldsConfig(
            fields=[
                FieldDefinition(source="a", column="A", type=FieldType.string),
            ]
        )
        assert len(cfg.fields) == 1

    def test_invalid_type_raises(self):
        with pytest.raises(ValidationError):
            FieldsConfig(
                fields=[
                    {"source": "a", "column": "A", "type": "invalid_type"},
                ]
            )


# ── RepoDetails ──────────────────────────────────────────────────────


class TestRepoDetails:
    def test_minimal_creation(self):
        rd = RepoDetails(full_name="org/repo", name="repo")
        assert rd.full_name == "org/repo"
        assert rd.default_branch == "main"
        assert rd.private is False

    def test_extra_fields_ignored(self):
        """extra='ignore' should silently drop unknown GitHub API fields."""
        rd = RepoDetails(
            full_name="org/repo",
            name="repo",
            unknown_field="should not break",
            another_new_thing=42,
        )
        assert rd.full_name == "org/repo"
        assert not hasattr(rd, "unknown_field")

    def test_all_defaults(self):
        rd = RepoDetails(full_name="org/repo", name="repo")
        assert rd.org is None
        assert rd.archived is False
        assert rd.disabled is False
        assert rd.fork is False
        assert rd.is_template is False
        assert rd.size == 0
        assert rd.open_issues_count == 0

    def test_serialization_roundtrip(self):
        rd = RepoDetails(
            full_name="org/repo",
            name="repo",
            private=True,
            language="Python",
        )
        json_str = rd.model_dump_json()
        restored = RepoDetails.model_validate_json(json_str)
        assert restored == rd


# ── AlertData ─────────────────────────────────────────────────────────


class TestAlertData:
    def test_defaults(self):
        a = AlertData()
        assert a.dependabot_alerts == 0
        assert a.dependabot_access == "ok"
        assert a.secret_scanning_alerts == 0

    def test_custom_values(self):
        a = AlertData(dependabot_alerts=5, code_scanning_access="403 Forbidden")
        assert a.dependabot_alerts == 5
        assert a.code_scanning_access == "403 Forbidden"


# ── BranchProtection ─────────────────────────────────────────────────


class TestBranchProtection:
    def test_defaults(self):
        bp = BranchProtection()
        assert bp.default_branch_protected is False
        assert bp.protection_settings == []
        assert bp.branch_protection_access is None

    def test_with_settings(self):
        bp = BranchProtection(
            default_branch_protected=True,
            protection_settings=["required_status_checks", "enforce_admins"],
        )
        assert len(bp.protection_settings) == 2


# ── CodeownersData ────────────────────────────────────────────────────


class TestCodeownersData:
    def test_not_present(self):
        c = CodeownersData()
        assert c.present is False
        assert c.path is None

    def test_present(self):
        c = CodeownersData(present=True, path=".github/CODEOWNERS")
        assert c.present is True
        assert c.path == ".github/CODEOWNERS"


# ── CommunityProfile ─────────────────────────────────────────────────


class TestCommunityProfile:
    def test_defaults(self):
        cp = CommunityProfile()
        assert cp.health_percentage == 0
        assert cp.files is None

    def test_extra_ignored(self):
        cp = CommunityProfile(health_percentage=80, unknown_field="ignored")
        assert cp.health_percentage == 80


# ── WorkflowData / WorkflowAnalysis ──────────────────────────────────


class TestWorkflowData:
    def test_defaults(self):
        wd = WorkflowData()
        assert wd.count == 0
        assert wd.workflows == []
        assert wd.analysis is None

    def test_with_analysis(self):
        wa = WorkflowAnalysis(has_tests=True, has_linting=False, workflows_analyzed=3)
        wd = WorkflowData(count=3, analysis=wa)
        assert wd.analysis.has_tests is True
        assert wd.analysis.workflows_analyzed == 3


# ── ForkTemplateData ──────────────────────────────────────────────────


class TestForkTemplateData:
    def test_defaults(self):
        ft = ForkTemplateData()
        assert ft.is_fork is False
        assert ft.fork_source is None

    def test_fork(self):
        ft = ForkTemplateData(is_fork=True, fork_source="upstream/repo")
        assert ft.fork_source == "upstream/repo"


# ── DependencyGraphData ──────────────────────────────────────────────


class TestDependencyGraphData:
    def test_defaults(self):
        dg = DependencyGraphData()
        assert dg.enabled is False


# ── ReferenceData / ReferenceItem ─────────────────────────────────────


class TestReferenceData:
    def test_defaults(self):
        rd = ReferenceData()
        assert rd.items == []
        assert rd.active_references == []

    def test_with_items(self):
        items = [
            ReferenceItem(full_name="org/a"),
            ReferenceItem(full_name="org/b", archived=True),
        ]
        rd = ReferenceData(items=items)
        assert len(rd.items) == 2
        assert rd.items[1].archived is True


# ── Org-level models ─────────────────────────────────────────────────


class TestOrgModels:
    def test_org_members_defaults(self):
        m = OrgMembersData()
        assert m.total_members == 0
        assert m.members_without_2fa == []

    def test_org_actions_defaults(self):
        a = OrgActionsData()
        assert a.self_hosted_runners == 0
        assert a.allowed_actions_policy is None

    def test_org_webhooks(self):
        w = OrgWebhooksData(webhooks_count=2, installed_apps=["dependabot", "renovate"])
        assert len(w.installed_apps) == 2

    def test_org_rulesets_defaults(self):
        r = OrgRulesetsData()
        assert r.count == 0
        assert r.rulesets == []


# ── RepoData (top-level aggregate) ───────────────────────────────────


class TestRepoData:
    def test_all_fields_optional(self):
        """An empty RepoData should be valid."""
        rd = RepoData()
        assert rd.repo_meta is None
        assert rd.alerts is None
        assert rd.collected_at is None
        assert rd.flags == []

    def test_partial_construction(self):
        rd = RepoData(alerts=AlertData(dependabot_alerts=5))
        assert rd.alerts.dependabot_alerts == 5
        assert rd.repo_meta is None

    def test_model_copy_merge(self):
        """model_copy + JSON round-trip should merge fields without discarding others.

        This mirrors how SqliteStorage.upsert works: model_copy merges at the
        field level, and the JSON round-trip re-validates nested dicts back
        into proper Pydantic model instances.
        """
        existing = RepoData(
            alerts=AlertData(dependabot_alerts=3),
            collected_at="2024-01-01",
        )
        update = RepoData(
            codeowners=CodeownersData(present=True),
        )
        merged_raw = existing.model_copy(
            update=update.model_dump(exclude_none=True),
        )
        # Round-trip through JSON (as SqliteStorage does)
        merged = RepoData.model_validate_json(merged_raw.model_dump_json())
        assert merged.alerts.dependabot_alerts == 3  # preserved
        assert merged.codeowners.present is True  # added
        assert merged.collected_at == "2024-01-01"  # preserved

    def test_json_roundtrip(self):
        rd = RepoData(
            repo_meta=RepoDetails(full_name="org/repo", name="repo"),
            alerts=AlertData(dependabot_alerts=1),
            flags=["stale"],
        )
        json_str = rd.model_dump_json()
        restored = RepoData.model_validate_json(json_str)
        assert restored.repo_meta.full_name == "org/repo"
        assert restored.alerts.dependabot_alerts == 1
        assert restored.flags == ["stale"]

    def test_model_dump_exclude_none(self):
        rd = RepoData(alerts=AlertData())
        dumped = rd.model_dump(exclude_none=True)
        assert "repo_meta" not in dumped
        assert "alerts" in dumped
