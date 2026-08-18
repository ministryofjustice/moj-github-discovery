# Org Security Posture Persistence Guide

This document describes what `org_security_posture` persists, how caching behaves, and how persisted data can be reused in dashboards.

Related documentation:

- [README.md](../README.md)
- [docs/audit-cli-script-outputs.md](./audit-cli-script-outputs.md)
- [docs/setup.md](./setup.md)

## Purpose

The org posture audit collects organization-scoped controls and signals, then writes:

1. Excel outputs for audit review.
2. SQLite tables for querying and future dashboard integration.
3. Cached supply chain section data for faster repeated runs.

Persistence exists to keep workbook outputs and queryable data aligned.

## Database Path

Configured in `config/audit_config.yaml` under:

- `org_security_posture.database_path`
- Default: `internal/org_security_posture.db`

The same SQLite file stores cache and persisted detail tables.

## Persisted Tables

### Cache table

- `org_cache`
  - Owned by `SqliteOrgStorage`
  - Stores cached section payload plus update timestamp
  - Used currently for dependency supply chain section reuse

### Org settings and identity posture

- `org_settings`
  - Row-based key/value format
  - Columns: `org`, `audited_at`, `setting_name`, `setting_value`
  - Example setting names: `name`, `public_repo_count`, `default_repository_permission`
- `teams`
  - Columns: `org`, `audited_at`, `team_name`, `slug`, `description`, `privacy`, `notification_setting`, `permission`, `parent`
- `outside_collaborators`
  - Columns: `org`, `audited_at`, `login`, `id`
- `twofa_disabled`
  - Columns: `org`, `audited_at`, `login`

### Webhooks and integrations

- `org_webhooks`
  - Detailed hook rows, not count-only
  - Columns: `org`, `audited_at`, `hook_id`, `name`, `active`, `events`, `url`, `config_url`, `created_at`, `updated_at`
- `org_github_apps`
  - Columns: `org`, `audited_at`, `app_slug`, `installation_id`, `repository_selection`, `permissions`

### Actions posture

- `org_actions_runners`
  - Columns: `org`, `audited_at`, `runner_id`, `name`, `os`, `status`, `busy`, `labels`
- `org_actions_secrets`
  - Columns: `org`, `audited_at`, `name`, `visibility`, `created_at`, `updated_at`

### GHAS alerts

- `org_code_scanning_alerts`
  - Columns: `org`, `audited_at`, `rule_id`, `severity`, `repo`, `state`
- `org_secret_scanning_alerts`
  - Columns: `org`, `audited_at`, `secret_type`, `repo`, `state`, `created_at`

### Org rulesets

- `org_rulesets`
  - Columns: `org`, `audited_at`, `ruleset_id`, `name`, `target`, `enforcement`, `raw_json`
  - `raw_json` keeps full payload for later parsing without losing fields

## Collection and Cache Behavior

Unlike `github_workflow`, this script does not use stage toggles for sections. It runs all org endpoints in one pass.

Relevant config:

- `org_security_posture.use_cache`
  - Controls whether cached dependency supply chain section data is reused
  - Does not disable other endpoint collection

Notes:

- On each run, table writes are append-style with the current `audited_at` value for traceability.
- If you want strict latest-snapshot semantics per table, add explicit table clear logic before writes.

## Workbook and Persistence Alignment

The script writes workbook sheets from report payload sections, while persistence writes table rows directly.

Current mapping examples:

- Workbook `Webhooks` sheet uses `report -> 5_webhooks_integrations -> details -> webhooks -> hooks`
- SQLite `org_webhooks` stores the same hook-level detail rows
- Workbook `Rulesets` sheet uses `report -> 6_rulesets -> details -> rulesets`
- SQLite `org_rulesets` stores summarized columns plus `raw_json`
- Workbook `Self-Hosted Runners` and `Org Secrets` use actions detail rows
- SQLite mirrors these as `org_actions_runners` and `org_actions_secrets`

## Rulesets Access Notes

If the summary shows `org_rulesets_count` as `no_access (...)`, the endpoint call failed. The endpoint path is correct:

- `/orgs/{org}/rulesets`

Common cause is auth scope/permission mismatch for org rulesets.

- GitHub App auth can fail when app permissions do not include required org rulesets visibility.
- PAT auth with appropriate org admin level scopes may be required depending on org policy.

The script logs a warning with access detail when rulesets access is not `ok`.

## Dashboard Integration Ideas

These persisted tables can back a dedicated org posture dashboard page:

- Settings panel from `org_settings` key/value rows
- Teams and collaborators tables from `teams` and `outside_collaborators`
- Actions operations view from `org_actions_runners` and `org_actions_secrets`
- Integration inventory from `org_webhooks` and `org_github_apps`
- GHAS views from `org_code_scanning_alerts` and `org_secret_scanning_alerts`
- Governance view from `org_rulesets`

Implementation suggestion:

- Add org-table readers in `core/dashboard_service.py`
- Keep visualization layout logic in `dashboard/layouts`
- Keep filter and pagination behavior in `dashboard/callbacks`

## Operational Guidance

- Run with PAT or App auth depending on required org endpoints.
- If rulesets are expected but missing, re-run with PAT and compare summary access output.
- Use `use_cache: true` for repeated runs when supply chain section freshness is acceptable.
- For strict freshness, set `use_cache: false` in `config/audit_config.yaml`.
