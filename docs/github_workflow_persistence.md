# GitHub Workflow Persistence Guide

This document describes what data `github_workflow` persists, how stage toggles affect data collection, and how the persisted tables can be surfaced in the dashboard.

## Purpose

The workflow audit now follows a fetch-once and analyse-once model for workflow files:

1. Collect repository/workflow baseline and additional metadata into SQLite.
2. Build workflow rows from cached data.
3. Fetch workflow file contents once for enabled deep-analysis stages.
4. Analyse each workflow file once and fan out results to actions, permissions, credentials, and trigger-risk outputs.

This reduces repeated GitHub API and workflow-content fetches in multi-stage runs.

## Database Path

Configured in `config/audit_config.yaml` under:

- `workflow_audit.database_path`
- Default: `internal/github_workflow_posture.db`

## Persisted Tables

The script writes to the baseline cache plus stage-specific analysis tables.

### Baseline cache table

- `repo_data`
- Created by `core.storage.SqliteRepoStorage`
- Holds per-repo JSON payloads (`RepoData`) from baseline/additional collection stages

### Stage-specific workflow analysis tables

- `github_actions_usage_detail`
  - One row per action reference found in workflow YAML
  - Columns: `repo`, `workflow_path`, `action_name`, `version`, `owner`, `is_pinned`, `pin_type`
- `github_actions_usage_summary`
  - Aggregated action usage counts
  - Columns: `action_name`, `times_used`
- `github_actions_owner_summary`
  - Aggregated owner/provider usage counts
  - Columns: `owner`, `actions_referenced`
- `github_actions_pinning_per_repo`
  - Per-repo pinning metrics
  - Columns: `repo`, `total_refs`, `pinned`, `unpinned`, `compliance_pct`
- `permissions`
  - Per-workflow permissions posture
  - Columns: `repo`, `workflow_path`, `has_explicit_permissions`, `permissions_value`, `has_write_permissions`, `finding`
- `credentials`
  - Per-workflow credential posture
  - Columns: `repo`, `workflow_path`, `has_id_token_write`, `oidc_actions`, `credential_secrets_found`, `posture`
- `credentials_per_repo`
  - Per-repo credential summary
  - Columns: `repo`, `total_workflows`, `oidc`, `long_lived_credentials`, `mixed`, `no_cloud_auth_detected`, `could_not_load`
- `triggers`
  - Per-workflow trigger risk
  - Columns:
    - `repo`
    - `workflow_path`
    - `triggers_found`
    - `risky_triggers`
    - `risk_level`
    - `has_pull_request_target`
    - `has_issue_comment`
    - `has_repository_dispatch`
    - `has_workflow_dispatch`
    - `posture`
- `triggers_per_repo`
  - Per-repo trigger risk summary
  - Columns: `repo`, `total_workflows`, `high_risk`, `medium_risk`, `low_risk`, `no_risk`, `could_not_load`

## Stage Toggles and Their Effect

All toggles are in `workflow_audit`.

- `collect_baseline_data` (stage 2)
  - Collects repo details and workflow inventory into `repo_data`.
- `collect_additional_data` (stage 3)
  - Collects repo Actions permissions and latest workflow run data into `repo_data`.
- `gen_posture_reports` (stage 5)
  - Writes posture CSV and text summary files from cached data.
- `actions_analysis` (stage 6)
  - Writes actions CSV outputs and the three actions tables listed above.
- `permissions_analysis` (stage 7)
  - Writes permissions CSV output and `permissions` table.
- `credentials_analysis` (stage 8)
  - Writes credentials CSV outputs and `credentials` plus `credentials_per_repo` tables.
- `trigger_risk_analysis` (stage 9)
  - Writes trigger CSV outputs and `triggers` plus `triggers_per_repo` tables.
- `use_cache`
  - Resume mode for collection stages (skip already-cached endpoint data where possible).

Notes:

- Stage 4 (row building) always runs. It reads from SQLite and prepares row sets used by later stages.
- Workflow file fetch/analysis runs once when any of these toggles is enabled: `actions_analysis`, `permissions_analysis`, `credentials_analysis`, `trigger_risk_analysis`.

## Scope Controls (file vs org)

Top-level config controls repository selection scope:

- `repo_search_scope: file`
  - Uses `default_repo_list` or `--repo-file`.
- `repo_search_scope: org`
  - Pulls repos from the org API.
- `repo_limit`
  - Applies a cap after scope resolution.

CLI overrides:

- `--repos owner/repo ...` targets explicit repositories.
- `--repo-file path/to/repos.yaml` overrides default repo list file (when using file scope).

## Stage-Specific Run Patterns

Example config fragment for selected stages:

```yaml
repo_search_scope: file
repo_limit: 200
workflow_audit:
  use_cache: true
  collect_baseline_data: true
  collect_additional_data: true
  gen_posture_reports: false
  actions_analysis: true
  permissions_analysis: false
  credentials_analysis: false
  trigger_risk_analysis: false
```

Typical run sequence:

1. Baseline cache build (or refresh): enable stages 2 and 3.
2. Analytical run: keep `use_cache: true`, disable/re-enable stage toggles as needed.
3. Optional report-only run: disable collection stages and enable `gen_posture_reports`.

## Dashboard Integration Ideas

The persisted tables are ready for direct dashboard tabs/pages without reparsing workflow files.

Suggested views:

- Actions usage
  - Source: `github_actions_usage_summary`, `github_actions_owner_summary`
  - Visuals: top actions bar chart, top owners leaderboard
- Pinning posture
  - Source: `github_actions_pinning_per_repo`
  - Visuals: repo compliance table sorted by `unpinned`, filter for non-compliant repos
- Permissions posture
  - Source: `permissions`
  - Visuals: finding distribution, list of workflows with write scopes
- Credentials posture
  - Source: `credentials_per_repo`, drill-through to `credentials`
  - Visuals: stacked posture counts per repo, details panel per workflow
- Trigger risk posture
  - Source: `triggers_per_repo`, drill-through to `triggers`
  - Visuals: high/medium risk counts, repo ranking by high-risk workflows

Implementation suggestion:

- Add read helpers in `core/dashboard_service.py` for each table.
- Keep table-to-UI mapping in `dashboard/layouts` and filtering/state logic in `dashboard/callbacks`.
- Use repo name as the shared key for cross-stage drill-down.

## Operational Guidance

- First run in a new database should keep `collect_baseline_data` and `collect_additional_data` enabled.
- If running analysis-only stages with no prior cache, outputs may be empty because `repo_data` has no workflow inventory yet.
- Keep `use_cache: true` for iterative analysis tuning to minimize API calls.
