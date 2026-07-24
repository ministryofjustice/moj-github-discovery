"""Pydantic v2 data models for the audit toolkit.

All data flowing between modules is typed here.  Every GitHub API endpoint
returns one of these models from its ``fetch()`` method and ``RepoData`` is
the top-level aggregate stored per-row in SQLite.

Design principles
-----------------
* ``extra="ignore"`` on API response models so new GitHub fields never
  break deserialisation.
* All fields on ``RepoData`` are ``Optional`` so a partially-collected row
  (e.g. after a mid-run interruption) is always valid.
* ``model_dump_json`` / ``model_validate_json`` replace all manual
  ``json.dumps`` / ``json.loads`` calls throughout the codebase.

When adding a new endpoint
--------------------------
1. Add a Pydantic model for its response here.
2. Add the corresponding ``Optional[YourModel] = None`` field to ``RepoData``.
3. Create the endpoint class in ``core/github_api.py``.
See ``CONTRIBUTING.md`` for a full walkthrough.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ── Fields config models ──────────────────────────────────────────────


class FieldType(str, Enum):
    """Output column types supported by the compiler."""

    string = "string"
    integer = "integer"
    boolean = "boolean"
    date = "date"
    json = "json"


class FieldDefinition(BaseModel):
    """A single column entry in ``fields.yaml``."""

    source: str
    """Dot-path into the ``RepoData`` JSON, e.g. ``repo_details.language``."""

    column: str
    """Human-readable column header in the output file."""

    type: FieldType
    """How to coerce the value before writing."""

    default: Any | None = None
    """Fallback when the source path is missing or null."""


class FieldsConfig(BaseModel):
    """Root model for ``fields.yaml``."""

    fields: list[FieldDefinition]


# ── Repo-level API response models ───────────────────────────────────


class RepoDetails(BaseModel):
    """Core repository metadata from ``/repos/{owner}/{repo}``.

    ``extra="ignore"`` means unknown GitHub API fields are silently dropped,
    so the model never breaks when GitHub adds new response keys.
    """

    model_config = ConfigDict(extra="ignore")

    full_name: str
    name: str
    org: str | None = None
    private: bool = False
    archived: bool = False
    archived_at: str | None = None
    disabled: bool = False
    fork: bool = False
    is_template: bool = False
    description: str | None = None
    language: str | None = None
    default_branch: str = "main"
    size: int = 0
    pushed_at: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    open_issues_count: int = 0
    stargazers_count: int = 0
    watchers_count: int = 0
    forks_count: int = 0
    security_and_analysis: dict[str, Any] | None = None
    license: dict[str, Any] | None = None
    """Repository license information from the GitHub API (e.g., SPDX key, name)."""


class RepoArchivedAt(BaseModel):
    """Repository Archival Date metadata. Also used for calculating days since archival"""

    archived_at: str | None = None


class DefaultBranchCommitData(BaseModel):
    """Most recent commit date on the default branch only."""

    last_pushed_at: str | None = None


class AlertData(BaseModel):
    """Open security alert counts for a single repository."""

    dependabot_alerts: int = 0
    dependabot_access: str = "ok"
    code_scanning_alerts: int = 0
    code_scanning_access: str = "ok"
    secret_scanning_alerts: int = 0
    secret_scanning_access: str = "ok"


class BranchProtection(BaseModel):
    """Classic branch protection status and active settings."""

    default_branch_protected: bool = False
    branch_protection_enabled: bool = False
    protection_settings: list[str] = Field(default_factory=list)
    enforce_admins_enabled: bool = False
    dismiss_stale_reviews: bool = False
    require_code_owner_reviews: bool = False
    required_approving_review_count: int = 0
    required_signatures_enabled: bool = False
    branch_protection_access: str | None = None
    """Set to an error message when the API call failed (e.g. no admin access)."""


class RepoRulesetsData(BaseModel):
    """Repository-level rulesets targeting the default branch."""

    has_active_rulesets: bool = False
    enforce_admins: bool = False
    dismiss_stale_reviews: bool = False
    require_code_owner_reviews: bool = False
    required_approving_review_count: int = 0
    required_signatures: bool = False
    rulesets_access: str | None = None
    """Set to an error message when the API call failed."""


class CodeownersData(BaseModel):
    """Whether a CODEOWNERS file exists and where it lives."""

    present: bool = False
    path: str | None = None


class CommunityProfile(BaseModel):
    """Community health profile from ``/repos/{owner}/{repo}/community/profile``."""

    model_config = ConfigDict(extra="ignore")

    health_percentage: int = 0
    files: dict[str, Any] | None = None


class WorkflowAnalysis(BaseModel):
    """Signals extracted by inspecting workflow file names and paths."""

    has_tests: bool = False
    has_linting: bool = False
    workflows_analyzed: int = 0
    findings: dict[str, Any] = Field(default_factory=dict)


class WorkflowData(BaseModel):
    """GitHub Actions workflow count and analysis signals."""

    count: int = 0
    workflows: list[dict[str, Any]] = Field(default_factory=list)
    analysis: WorkflowAnalysis | None = None


class RepoActionsPermissionsData(BaseModel):
    """Repository-level GitHub Actions permissions settings."""

    model_config = ConfigDict(extra="ignore")

    enabled: bool | None = None
    allowed_actions: str | None = None


class LatestWorkflowRunData(BaseModel):
    """Timestamp of the most recent workflow run for a repository."""

    created_at: str | None = None


class WorkflowPermissionFinding(BaseModel):
    """Result of checking a single workflow file for permissions posture."""

    repo: str
    workflow_path: str
    has_explicit_permissions: bool = False
    permissions_value: str = ""
    has_write_permissions: bool = False
    finding: str = "no_permissions_block"


class CredentialPostureFinding(BaseModel):
    """Result of checking a single workflow file for OIDC vs long-lived credentials."""

    repo: str
    workflow_path: str
    has_id_token_write: bool = False
    oidc_actions: str = ""
    credential_secrets_found: str = ""
    posture: str = "no_cloud_auth_detected"


class ForkTemplateData(BaseModel):
    """Fork origin and template source details."""

    is_fork: bool = False
    fork_source: str | None = None
    is_generated_from_template: bool = False
    template_source: str | None = None


class DependencyGraphData(BaseModel):
    """Whether the dependency graph / SBOM endpoint is available."""

    enabled: bool = False


class RepoTreeEntry(BaseModel):
    """A single entry from the Git tree API response."""

    model_config = ConfigDict(extra="ignore")

    path: str
    mode: str | None = None
    type: str | None = None
    sha: str | None = None
    size: int | None = None
    url: str | None = None


class RepoTreeData(BaseModel):
    """Repository tree data returned by the Git tree API."""

    model_config = ConfigDict(extra="ignore")

    sha: str | None = None
    url: str | None = None
    truncated: bool = False
    tree: list[RepoTreeEntry] = Field(default_factory=list)
    access: str = "ok"


class LargeBlobData(BaseModel):
    """Blob metadata for files that exceed the configured size threshold."""

    sha: str | None = None
    size_bytes: int
    path: str


class ReferenceItem(BaseModel):
    """A single code-search hit referencing this repository."""

    full_name: str
    path: str | None = None
    archived: bool = False


class ReferenceData(BaseModel):
    """All cross-repo code search references, classified by archive status."""

    items: list[ReferenceItem] = Field(default_factory=list)
    active_references: list[str] = Field(default_factory=list)
    archive_references: list[str] = Field(default_factory=list)


# ── Org-level API response models ────────────────────────────────────


class OrgMembersData(BaseModel):
    """Organisation member counts and 2FA compliance."""

    total_members: int = 0
    members_without_2fa: list[str] = Field(default_factory=list)


class OrgActionsData(BaseModel):
    """Org-level Actions configuration — runners, permissions, secrets."""

    self_hosted_runners: int = 0
    allowed_actions_policy: str | None = None
    org_secrets_count: int = 0
    default_workflow_permissions: str | None = None


class InstalledApp(BaseModel):
    """A single installed GitHub App with its granted permissions."""

    model_config = ConfigDict(extra="ignore")

    app_slug: str = ""
    installation_id: int | None = None
    repository_selection: str | None = None
    permissions: dict[str, str] = Field(default_factory=dict)


class OrgWebhooksData(BaseModel):
    """Org webhooks and installed GitHub Apps."""

    webhooks_count: int = 0
    installed_apps: list[str] = Field(default_factory=list)
    installed_apps_detail: list[InstalledApp] = Field(default_factory=list)


class OrgRulesetsData(BaseModel):
    """Org-level repository rulesets."""

    count: int = 0
    rulesets: list[dict[str, Any]] = Field(default_factory=list)


class OrgOverviewData(BaseModel):
    """Organisation overview plus selected security posture settings."""

    access: str = "ok"
    data: dict[str, Any] = Field(default_factory=dict)


class OrgOutsideCollaboratorsData(BaseModel):
    """Outside collaborators in the organisation."""

    access: str = "ok"
    collaborators: list[dict[str, Any]] = Field(default_factory=list)


class OrgTeamsData(BaseModel):
    """Organisation teams metadata."""

    access: str = "ok"
    teams: list[dict[str, Any]] = Field(default_factory=list)


class OrgAuditLogData(BaseModel):
    """Recent org audit log entries."""

    access: str = "ok"
    entries: list[dict[str, Any]] = Field(default_factory=list)


class OrgCodeScanningAlertsData(BaseModel):
    """Organisation code scanning alert summary."""

    access: str = "ok"
    open_count: int = 0
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool = False


class OrgSecretScanningAlertsData(BaseModel):
    """Organisation secret scanning alert summary."""

    access: str = "ok"
    open_count: int = 0
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool = False


# ── Top-level repo data aggregate ────────────────────────────────────


class RepoData(BaseModel):
    """Single record stored per-repo in the SQLite ``repo_data`` table.

    Every field is ``Optional`` so a row that was only partially collected
    (e.g. the process was interrupted mid-run) is always valid and can be
    read back and continued with ``--resume``.

    The collector populates this incrementally:
    ``storage.upsert(full_name, RepoData(alerts=AlertData(...)))``
    merges just the ``alerts`` key into the existing row without touching
    anything else.

    Computed fields (``days_since_push``, ``age_days``, ``flags``) are
    added by transforms in ``core/transforms.py`` before the compiler
    reads the data.
    """

    # Endpoint-populated fields
    repo_details: RepoDetails | None = None
    repo_archived_at: RepoArchivedAt | None = None
    alerts: AlertData | None = None
    branch_protection: BranchProtection | None = None
    repo_rulesets: RepoRulesetsData | None = None
    community: CommunityProfile | None = None
    codeowners: CodeownersData | None = None
    workflows: WorkflowData | None = None
    repo_actions_permissions: RepoActionsPermissionsData | None = None
    latest_workflow_run: LatestWorkflowRunData | None = None
    fork_template: ForkTemplateData | None = None
    dependency_graph: DependencyGraphData | None = None
    repo_tree: RepoTreeData | None = None
    references: ReferenceData | None = None
    default_branch_commit: DefaultBranchCommitData | None = None

    # Transform-computed fields
    days_since_push: int | None = None
    age_days: int | None = None
    flags: list[str] = Field(default_factory=list)
    repo_tree_transform: RepoTreeProcessedData | None = None

    # Collection metadata
    collected_at: str | None = None


class RepoTreeProcessedData(BaseModel):
    """Derived repository tree summary used by the repo tree transform.

    Captures the largest blob in the tree plus any blobs exceeding the
    configured soft limit.
    """

    repo: str | None = None
    largest_blob_bytes: int = 0
    largest_blob_path: str | None = None
    large_blobs: list[LargeBlobData] = Field(default_factory=list)
    exceeds_soft_limit: bool = False
    exceeds_hard_limit: bool = False


class TriggerRiskFinding(BaseModel):
    """Result of analysing workflow trigger configuration risk."""

    repo: str = ""
    workflow_path: str = ""
    triggers_found: str = ""
    risky_triggers: str = ""
    risk_level: str = ""
    has_pull_request_target: bool = False
    has_issue_comment: bool = False
    has_repository_dispatch: bool = False
    has_workflow_dispatch: bool = False
    posture: str = ""
