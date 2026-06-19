# Repository Audit Tool

[![Ministry of Justice Repository Compliance Badge](https://github-community.service.justice.gov.uk/repository-standards/api/moj-github-discovery/badge)](https://github-community.service.justice.gov.uk/repository-standards/moj-github-discovery)

A comprehensive Python toolset for auditing GitHub repositories across organizations. Analyzes:

- Organisation Security posture
- GitHub Actions Workflows
- Repository Management Lifecycle (Archival Candidacy)
- Security Alerts
- Adherence to [MOJ Github community standards](https://github-community.service.justice.gov.uk/repository-standards/guidance).

## Setup

Follow the dedicated setup guidance under `docs/setup.md` to get all pre-requisites installed and configured where appropriate.

[Setup Docs](./docs/setup.md)

For guidance on extending the core module and contributing changes, see
[CONTRIBUTING.md](./docs/CONTRIBUTING.md).

## Core Architecture

The project is structured so CLI scripts stay thin while the `core/` package owns
collection, storage, and report shaping.

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                CLI entry points                                                                 │
│  list_repos.py  archive_repos.py  org_security_posture.py   github_workflow.py, alert_metrics.py  lfs_script.py │
│  dashboard.py / dashboard_cli.py (UI layers)                                                                    │
└───────────────────────────────┬────────────────────┬────────────────────────────────────────────────────────────┘
        │                    │
      ┌───────▼───────┐    ┌──────▼────────┐
      │  collector.py  │    │  compiler.py   │
      │ (fetch + store │    │ (read SQLite → │
      │  immediately)  │    │  Excel/CSV)    │
      └──┬────┬────┬───┘    └──────┬────────┘
         │    │    │               │
       ┌───────▼┐ ┌▼────▼──┐     ┌───────▼────────┐
       │github_ │ │storage  │     │ transforms.py  │
       │api.py  │ │.py      │     │ (flags, age,   │
       │(all EP │ │(SQLite  │     │ derived fields)│
       │ calls) │ │ R/W)    │     └────────────────┘
       └───┬────┘ └─────────┘
           │
     ┌─────▼──────────┐
     │ github_client  │
     │ .py (session,  │
     │  retry, rate   │
     │  limiting)     │
     └────────────────┘
```

### Using The Core Module

- Use collector-driven scripts (`list_repos.py`, `archive_repos.py`, `org_security_posture.py`) to fetch once and persist data.
- Reuse stored data for repeated analysis/reporting to avoid repeated API calls.
- Keep UI scripts focused on presentation and action triggers, not GitHub API plumbing.

### Extending The Core Module

- Add/extend endpoint models in `core/models.py` and endpoint logic in `core/github_api.py`.
- Register endpoint classes in the endpoint registries consumed by collectors.
- Keep output shaping in `core/presenters.py` and data enrichment in `core/transforms.py`.
- Add focused unit tests first (`tests/test_github_api.py`, `tests/test_collector.py`, `tests/test_presenters.py`, `tests/test_transforms.py`).
- Add any script-specific config to `config/audit_config.yaml` with a corresponding model in `core/config.py`.

## Usage Overview

### CLI Args

- `--config-file <path/to/config.yaml>` - Path to config file for audit script to reference, defaults to `config/audit_config.yaml` if not provided.
- `--auth` - Specify a (single) auth method if required `pat, app, cli` - will default check each method sequentially if not provided.
- `--scripts` - One or more scripts to be executed by the audit CLI. Current options are:
  - `alert_metrics`
  - `archive_repos`
  - `github_workflow`
  - `lfs_script`
  - `list_repos`
  - `org_security_posture`
- `--all` - Trigger all the scripts in sequence
  - **note:** this will take a significant amount of time due to rate limiting, consider running on an extremely small subset of repos if testing
- `--repo` - Specify a single repository to target in the form `owner/repo` - currently only applies to `alert_metrics`
- `--repos` - Specify one or more repos to scan e.g. `owner/repo owner/repo1` - currently only applies to `github_workflow`

### Local Terminal

After running `uv sync`, the audit CLI can be triggered for any given script(s) under the `scripts/` directory.

```shell
# Install CLI and dependencies
uv sync

# Display Help Information around CLI Args
uv run audit-cli --help

# Run a specific script e.g. list_repos.py
uv run audit-cli --scripts list_repos

# Run multiple scripts, authenticating via PAT
uv run audit-cli --scripts alert_metrics lfs_script --auth pat

# Run a given script with a custom config file
uv run audit-cli --scripts list_repos --config-file config/audit_config.yaml

# Run github_workflow.py against a specific set of repos
uv run audit-cli --scripts github_workflow --repos ministryofjustice/<repo1> ministryofjustice/<repo2> 

# Run alert_metrics against a specific repo
uv run audit-cli --scripts alert_metrics --repo ministryofjustice/<repo name>
```

### Virtual Environment (Venv)

- Install the CLI and dependencies: `uv sync`
- Initialise a venv: `source .venv/bin/activate`
- Run the CLI: `audit-cli <args>`
- Deactivate when done: `deactivate`

## Global Config Attributes

- `github_organization` - The GitHub organisation for the scripts to run against - default `ministryofjustice`
- `repo_list_file` - Path to the repo list YAML file to be referenced by the scripts - defaults to `repo_list.yaml` at project root.

## Output Directory Configuration

Audit output locations are configured in `config/audit_config.yaml`.

- Set global output and internal roots via `output_paths`.
- Set per-script output folders via each script's `output_subdir`.
- If these roots are changed, update any Docker volume mounts accordingly.

## Script-Specific Usage

### 1. `list_repos.py` - Audit Repositories From a File

Audits repositories listed in a repo file (YAML preferred), persists results in
the core SQLite storage, and optionally exports an Excel workbook.

**Usage:**

```bash
uv run audit-cli --scripts list_repos --config-file config/audit_config.yaml --auth pat
```

**Config Parameters:**

- `database_path: <path>` - SQLite path for core storage (default: `internal/repo_audit.db`).
- `output_filename: <filename>.xlsx` - Export results to Excel file `<filename>.xlsx`. Requires `openpyxl`.
- `repo_limit: <N>` - Crop the loaded `repo_list_file` list to the first N entries before collection - ideal for adhoc quick checks.
- `use_cache: true/false` - Resume mode: skip endpoint calls for data already present in the SQLite cache (still fetches missing data).
- `standard_endpoints_only: true/false` - Use the reduced endpoint set for faster runs. By default, `list_repos.py` collects all repo endpoints.
- `sort_by_field: <column>` - Sort by repo field. Defaults to last updated (`pushed_at`).
- `sort_ascending: <true/false>` - Sort order for `sort_by_field`, defaults to `false` / descending

**Examples:**

```bash
# Audit all repos from file
uv run audit-cli --scripts list_repos --config-file config/audit_config.yaml --auth app
```

### 2. `archive_repos.py` - Find Archive Candidates

Builds a repository inventory focused on age, inactivity, archival state, and whether archived repositories still appear to have ongoing interest or references.
The script caches repo metadata and code-search results locally so repeated runs can be much faster.

**Usage:**

```bash
uv run audit-cli --scripts archive_repos --config-file path/to/config.yaml --auth pat
```

**Config Parameters:**

- `database_path: "path/to/file.db"` - SQLite path for core storage (default: `internal/repo_audit.db`).
- `output_filename: "file.csv / file.xlsx"` - Export the full results set to CSV or Excel of given filename under `outputs/archive_repos/`
- `page_num: null/<int>` - Process only one page of cached/fetched repos (100 repos per page, 0-indexed). `null` for full estate.
- `repo_limit: null/<int>` - Limit the number of repositories loaded from the organisation. `null` for full estate.
- `sort_by_field: "field"` - Sort by a result column. Default is `days_since_push`
- `sort_ascending: true/false` - Sort order for `sort_by_field`, defaults to `false` / descending
- `use_cache: true/false` - Resume mode: skip endpoint calls for data already present in the SQLite cache (still fetches missing data).
- **Namespace Crossref Config:**
  - `enabled: true/false` - Opt-in cross-reference: compare archived repos with namespace folders in a separate repo.
  - `target_repo: "repo_name"` - Namespace repository name (default: `cloud-platform-environments`).
  - `target_branch: "branch"` - Branch to inspect in namespace repository (default: `main`).
  - `root_folder: "folder"` - Top-level namespace directory path (default: `namespaces`).

**Output:**

- CSV to `outputs/archive_repos`
- Core storage is persisted in SQLite (`repo_data` table) under `internal/`
- JSON to stdout by default.
- When `namespace_crossref` is enabled and JSON is printed, output is an object with `records` and `namespace_crossref_summary`
- Elapsed time and progress information on stderr

**Useful fields in the output:**

- `days_since_push` and `age_days` to identify stale repositories
- archived-repo follow-up indicators such as open issues, stars, watchers, and references from other repositories
- dependency graph and internal reference signals that help flag archives needing another review
- `has_namespace_folder` and `archived_with_namespace_folder` when `--namespace-crossref` is enabled

**Examples:**

```bash
# Export archive candidates to CSV using specific config parameters
uv run audit-cli --scripts archive_repos --config-file path/to/config.yaml --auth pat
```

### 3. `org_security_posture.py` - Audit Organisation Security Posture

Performs an organisation-level audit that complements the per-repo scripts. It collects high-level security and operational controls such as:

- 2FA enforcement
- outside collaborators
- teams
- audit-log activity
- code-scanning and secret-scanning alerts
- Actions posture
- secrets
- webhooks
- installed apps
- rulesets
- supply-chain signals

**Usage:**

```bash
uv run audit-cli --scripts org_security_posture --config-file /path/to/config.yaml --auth pat/app/cli
```

**Config Parameters:**

- `database_path: <path>` - SQLite path for core storage (default: `internal/org_security_posture.db`).
- `output_filename: <filename>.xlsx` - Export results to Excel file `<filename>.xlsx`. Requires `openpyxl`.
- `use_cache: true/false` - Resume mode: skip endpoint calls for data already present in the SQLite cache for supply chain analysis (still fetches missing data).

**Output:**

- A summary printed to stderr
- Excel workbook output to `outputs/org_security_posture/`
- Cached results stored in `internal/org_security_posture.db` for reuse on later runs

**Examples:**

```bash
# Export a workbook for review (org + output file come from config), authenticating via PAT specifically
uv run audit-cli --scripts org_security_posture --config-file config/audit_config.yaml --auth pat
```

### 4. `dashboard.py` - Interactive Web Dashboard

Launches an interactive Dash web dashboard to browse and manage repository audits. Allows searching, filtering, and running new audits directly from the UI.

**Usage:**

```bash
uv run python scripts/dashboard.py [options]
```

**Options:**

- `--db <path>` - Custom database path (default: `internal/repo_audit.db`)

**Examples:**

```bash
# Start dashboard with default database
export GITHUB_TOKEN=ghp_xxxx
uv run python scripts/dashboard.py

# Start with custom database
uv run python scripts/dashboard.py --db /tmp/audit.db
```

**Features:**

- Search and filter repositories by name
- Filter by flagged status

> Both the dashboard and command‑line tools now reuse a persistent GitHub
> API session and perform work in parallel where possible, delivering
> noticeably faster results on large orgs. Each script also reports the
> elapsed time after completion (and the timers will print even if you
> interrupt or error out).

- Click any row to view detailed audit information
- Run audits on-demand from the dashboard
- View security metrics, alerts, and compliance status
- Color-coded risk flags

**Access:** Open <http://localhost:8050> in your browser

### 5. `testEnv.py` - Diagnose GitHub CLI Authentication

Diagnoses why `gh` authentication might differ between environments (e.g., terminal vs Jupyter in Codespaces).

**Usage:**

```bash
uv run python utils/testEnv.py
```

**Output:**

- Environment variables (PATH, HOME, config locations)
- Token presence and SHA256 prefix (redacted)
- `gh auth status`
- `gh api /user`
- Organization repository listing
- Multiple authentication variants tested
- Interpretation guide

**Examples:**

```bash
# Diagnose auth in current environment
uv run python utils/testEnv.py

# In Jupyter cell
!uv run python utils/testEnv.py

# With custom token
export GH_TOKEN=ghp_xxxx
uv run python utils/testEnv.py
```

### 6. `github_workflow.py` - Assess GitHub Actions Workflow Posture

Assesses the posture of GitHub Actions workflows across repositories in an organization.
It collects data on:

- workflow files
- actions permissions
- latest runs

to identify repositories using Actions, archived repos with workflows, and candidates for disabling Actions.

**Usage:**

```bash
uv run audit-cli --scripts github_workflow [options]
```

**Config Parameters:**

- `database_path: <path>` - SQLite path for core storage (default: `internal/github_workflow_posture.db`).
- `output_prefix: <filename>` - Output filename prefix, only applies to `gen_posture_reports`.
- `repo_limit: null/<int>` - Limit the number of repositories loaded from the organisation. `null` for full estate.
- `use_cache: true/false` - Resume mode: skip endpoint calls for data already present in the SQLite cache (still fetches missing data).
- **Stage-specific toggles:**
  - `collect_baseline_data: true/false` - Toggle collection of repo metadata and workflow inventory.
  - `collect_additional_data: true/false` - Toggle collection of actions permissions-based data
  - `gen_posture_reports: true/false` - Toggle generation of base summary posture CSVs and text reports
  - `actions_analysis: true/false` - Toggle execution of actions analysis, what actions are used, how many are SHA pinned, etc.
  - `permissions_analysis: true/false` - Toggle execution of workflow permission configuration analysis.
  - `credentials_analysis: true/false` - Toggle execution of workflow credential usage analysis (OIDC vs Long-Lived)
  - `trigger_risk_analysis: true/false` - Toggle execution of workflow trigger risk analysis.

**Output:**

- All outputs by default are sent to `outputs/github_workflow_posture`

- **Posture Reports:**
  - Text summary report (`_audit_summary.txt` suffix) summarising base analysis and posture of workflows
  - CSV summary of workflow data for repos analysed  (`_repo_summary.csv` suffix)
  - CSV providing details of workflows per repository analysed (`_workflow_details.csv`)
- **Actions Analysis:**
  - `github_actions_owner_summary.csv` - Outlines the most commonly used action providers through the workflows analysed
  - `github_actions_pinning_per_repo.csv` - Compares the pinned vs unpinned by SHA actions per repository.
  - `github_actions_unpinned_detail.csv` - Outlines per-workflow in each repository pinned/unpinned by SHA metrics for actions.
  - `github_actions_usage_summary.csv` - CSV summary count of the most common actions used throughout the workflows analysed
  - `github_actions_usage_detail.csv` - CSV detailed report outlining actions used throughout each workflow file, version, pinning, and owner.
- **Permissions Analysis:**
  - `github_workflow_permissions.csv` - CSV report of permission configuration risks associated with the analysed repositories.
- **Credentials Analysis:**
  - `github_workflow_credential_posture.csv` - Per-workflow per repository breakdown of OIDC vs long-lived credential usage.
  - `github_workflow_credential_posture_per_repo.csv` - CSV breakdown of OIDC vs Long-lived credential usage per repository analysed.
- **Trigger Risk Analysis:**
  - `github_workflow_trigger_risk.csv` - Per-workflow per repository breakdown of workflow trigger configuration risk.
  - `github_workflow_trigger_risk_per_repo.csv` - CSV breakdown of workflow trigger configuration risk per repository analysed.

**Examples:**

```bash
# Scan Using Config File and Repo List


# Scan Only Particular Set of Repos

```

### 7. `alert_metrics.py` - Assess GitHub Security Alerts

Exports repository-level alert metrics for code scanning, dependabot, and secret scanning alerts.

**Usage:**

```bash
uv run audit-cli --scripts alert_metrics [options]
```

**Config Parameters:**

- `max_alerts: <int>` - Maximum number of alerts to pull for analysis across the estate
- `output_filename: <filename>.csv` - File name for summary report results are exported to, stored in `outputs/github_alerts/`
- `repo_limit: <int>` - Only consider the first `<x>` amount of repositories pulled by the script e.g. `400`, `1000`, etc.

**Output:**

- CSV file with alert details including id, type, repo, created_at, remediated_at, state, severity, ttr_days

**Examples:**

```bash
# Export alerts for org to default CSV, using a given config file and authenticating via PAT
uv run audit-cli --scripts alert_metrics --config-file config/audit_config.yaml --auth pat

# Run script against single repository
uv run audit-cli --scripts alert_metrics --config-file config/audit_config.yaml --repo ministryofjustice/example-repo
```

### 8. `lfs_script.py` - Assess for Unwanted Large Files within GitHub

Analyzes GitHub repositories for large file storage (LFS) issues by checking blob sizes against predefined thresholds (soft: 50MB, hard: 100MB).
It generates a master Excel summary of repos exceeding thresholds and individual CSV summaries for each repository.

**Usage:**

```bash
uv run audit-cli --scripts lfs_script --config-file config/audit_config.yaml --auth pat
```

**Config Parameters:**

- `database_path`: SQLite path for core storage (default: `internal/lfs_audit.db`).
- `soft_limit_mb: <int>`: Integer soft/warning file size limit in Megabytes. Defaults to 50.
- `hard_limit_mb: <int>`: Integer hard file size limit in Megabytes. Defaults to 100.
- `output_filename: <filename>.xlsx` - Filename for summary output Excel File under `outputs/lfs_analysis`
- `use_cache: true/false` - Resume mode: skip endpoint calls for data already present in the SQLite cache (still fetches missing data).

**Output:**

- Master Excel file (`repos_exceeding_thresholds.xlsx`) summarizing repos with large files
- Individual CSV files in `repo_summaries/` directory for each repository's blob details

**Examples:**

```bash
# Run the LFS analysis
uv run audit-cli --scripts lfs_script
```

## Database Schema

### `repo_data` Table

Core storage uses a single SQLite table that stores one merged JSON payload per repository:

| Column    | Type      | Description                                 |
| --------- | --------- | ------------------------------------------- |
| full_name | TEXT (PK) | Repository full name (`owner/repo`)         |
| data      | TEXT      | JSON-serialized `RepoData` from core models |

## Audit Flags Explained

Each repo is assigned risk flags:

- `archived` - Repository is archived (no longer maintained)
- `fork` - Repository is a fork
- `no_license` - No license file present
- `public_unprotected_default_branch` - Public repo with unprotected default branch
- `dependabot_alerts_present` - Dependabot has found vulnerable dependencies
- `secret_alerts_present` - Secret scanning alerts exist
- `code_scanning_alerts_present` - Code scanning alerts exist
- `no_security_policy` - Missing SECURITY.md
- `no_code_of_conduct` - Missing CODE_OF_CONDUCT
- `no_actions_workflows` - No CI/CD workflows configured
- `no_detected_tests` - CI/CD exists but no test detection
- `no_detected_linting` - CI/CD exists but no lint detection

## Workflow

### Single Organization Audit

```bash
# 1. Audit all repos in organization
export GITHUB_TOKEN=ghp_xxxx
uv run python scripts/list_repos.py --config-file config/audit_config.yaml

# 2. Launch dashboard to explore results
uv run python scripts/dashboard.py

# 3. Click on repos to view details or run deeper audits
```

### Archive Review Workflow

```bash
# 1. Generate a CSV of old or archived repositories
uv run audit-cli --scripts archive_repos --config-file config/audit_config.yaml
```

### Organisation Security Posture Review

```bash
# 1. Generate an organisation-wide posture workbook
uv run audit-cli --scripts org_security_posture --config-file config/audit_config.yaml

# 2. Set `use_cache: false` in config/audit_config.yaml to run without cache when you need fresh data
uv run audit-cli --scripts org_security_posture --config-file config/audit_config.yaml

# 3. Limit supply-chain checks to repos listed in repo_list.yaml - adjust repo_list_file for alternate lists
uv run audit-cli --scripts org_security_posture --config-file config/audit_config.yaml
```

### Batch Audit Using File

```bash
# Create repo_list.yaml
cat > repo_list.yaml <<EOF
# You can annotate this file with comments
repos:
  # Core services
  - owner/repo1
  - owner/repo2
  # Legacy
  - owner/repo3
EOF

# Audit them
export GITHUB_TOKEN=ghp_xxxx
uv run audit-cli --scripts list_repos

# View in dashboard
uv run python scripts/dashboard.py
```

### Continuous Monitoring

```bash
# Re-run audits to update the core storage database
export GITHUB_TOKEN=ghp_xxxx
uv run audit-cli --scripts list_repos

# Dashboard automatically shows updated data
uv run python scripts/dashboard.py
```

## Troubleshooting

### "Command failed: gh api ..." Error

- Ensure `gh` CLI is installed: `which gh`
- Authenticate with `gh`: `gh auth login`
- Check token has correct scopes (requires `repo` and `read:org`)

### Authentication Issues Between Environments

```bash
uv run python utils/testEnv.py
```

This will diagnose differences in PATH, HOME, and token availability.

### JSON Parse Errors in Dashboard

- Ensure the database file exists and is valid
- Check that previous audits completed successfully
- Try running a fresh audit: Click "Run Audit" button

### Database Locked Error

- Close other instances of the dashboard
- Ensure no other processes are accessing the database

## Examples

### Export audit to XLSX report

```bash
export GITHUB_TOKEN=ghp_xxxx
uv run audit-cli --scripts list_repos
```

### Audit specific critical repos

```bash
export GITHUB_TOKEN=ghp_xxxx
uv run audit-cli --scripts list_repos
uv run python scripts/dashboard.py
# Select each repo and click "Run Audit" for updated details in core storage
```

### Use dashboard to identify high-risk repos

```bash
export GITHUB_TOKEN=ghp_xxxx
uv run python scripts/list_repos.py --repo-file repo_list.yaml --db ./path/to/repo_audit.db
uv run python scripts/dashboard.py
# Filter by "Show only repos with flags"
```

### Export archive candidate data

```bash
uv run audit-cli --scripts archive_repos --config-file config/audit_config.yaml
```

### Export organisation posture report

```bash
uv run audit-cli --scripts org_security_posture
```

## License

Part of the investigate repository.
