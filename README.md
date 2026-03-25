# Repository Audit Tool

A comprehensive Python toolset for auditing GitHub repositories across organizations. Analyzes:

- Security posture
- CI/CD workflows
- Branch Protection
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
┌────────────────────────────────────────────────────────────────────────────┐
│                                CLI entry points                            │
│  list_repos.py  archive_repos.py  org_security_posture.py                 │
│  dashboard.py / dashboard_cli.py (UI layers)                              │
└───────────────────────────────┬────────────────────┬───────────────────────┘
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

## Scripts

### 1. `list_repos.py` - Audit Repositories From a File

Audits repositories listed in a repo file (YAML preferred), persists results in
the core SQLite storage, and optionally exports an Excel workbook.

**Usage:**

```bash
python list_repos.py --repo-file <file> [options]
```

**Options:**

- `--repo-file <file>` - Repositories to audit. Preferred format is YAML (`repos:` list of `owner/repo` strings) and comments are supported.
- `--db <path>` - SQLite path for core storage (default: `repo_audit.db` in project root).
- `--excel <path>` - Export results to Excel file. Requires `openpyxl`.
- `--limit <N>` - Crop the loaded `--repo-file` list to the first N entries before collection.
- `--sort [-]column` - Sort by repo field (`-` prefix for descending). Defaults to last updated (`pushed_at` desc).

**Examples:**

```bash
# Audit all repos from file and print JSON output
python list_repos.py --repo-file repo_list.yaml

# Export to Excel
python list_repos.py --repo-file repo_list.yaml --excel report.xlsx

# Limit processing to first 50 repos in file
python list_repos.py --repo-file repo_list.yaml --limit 50

# Use a custom core storage database path
python list_repos.py --repo-file repo_list.yaml --db /tmp/audit.db

# Sort output by stars ascending
python list_repos.py --repo-file repo_list.yaml --sort +stargazers
```

### 2. `archive_repos.py` - Find Archive Candidates

Builds a repository inventory focused on age, inactivity, archival state, and whether archived repositories still appear to have ongoing interest or references. The script caches repo metadata and code-search results locally so repeated runs can be much faster.

**Usage:**

```bash
python archive_repos.py <org> [options]
```

**Options:**

- `--csv <path>` - Export the full results set to CSV.
- `--limit <N>` - Limit the number of repositories loaded from the organisation.
- `--page-num <N>` - Process only one page of cached/fetched repos (100 repos per page, 0-indexed).
- `--sort [-]column` - Sort by a result column. Default is `days_since_push` ascending. Prefix with `-` for descending.
- `--audit-db [path]` - Use a custom SQLite path for core storage persistence. If omitted, the script uses `repo_audit.db` beside the script. If provided without a path, it also defaults to `repo_audit.db`.
- `--cache-only` - Do not call the GitHub API. Use only existing local caches.

**Output:**

- CSV when `--csv` is used
- Core storage is persisted in SQLite (`repo_data` table)
- JSON to stdout when `--csv` is not provided and `--audit-db` is not explicitly supplied
- Elapsed time and progress information on stderr

**Useful fields in the output:**

- `days_since_push` and `age_days` to identify stale repositories
- archived-repo follow-up indicators such as open issues, stars, watchers, and references from other repositories
- dependency graph and internal reference signals that help flag archives needing another review

**Examples:**

```bash
# Export archive candidates to CSV
python archive_repos.py ministryofjustice --csv archivable.csv

# Reuse local caches only for a fast rerun
python archive_repos.py ministryofjustice --cache-only --csv archivable.csv

# Process only page 2 of the org inventory and write to the audit database
python archive_repos.py ministryofjustice --page-num 2 --audit-db

# Sort by oldest last push and print JSON to stdout
python archive_repos.py ministryofjustice --sort days_since_push
```

### 3. `org_security_posture.py` - Audit Organisation Security Posture

Performs an organisation-level audit that complements the per-repo scripts. It collects high-level security and operational controls such as 2FA enforcement, outside collaborators, teams, audit-log activity, code-scanning and secret-scanning alerts, Actions posture, secrets, webhooks, installed apps, rulesets, and supply-chain signals.

**Usage:**

```bash
python org_security_posture.py <org> [--excel path] [--json] [--repo-limit N] [--no-cache]
```

**Options:**

- `--excel <path>` - Write the report to a multi-sheet Excel workbook.
- `--json` - Also print the full report as JSON.
- `--repo-limit <N>` - Limit how many repositories are sampled for repo-level posture checks. Default is `100`.
- `--no-cache` - Ignore the saved posture cache and fetch fresh data.

**Output:**

- A summary printed to stderr
- JSON to stdout by default
- Excel workbook output when `--excel` is supplied
- Cached results stored in `.posture_cache_<org>.pkl` for reuse on later runs

**Examples:**

```bash
# Print the full organisation posture report as JSON
python org_security_posture.py ministryofjustice

# Export a workbook for review
python org_security_posture.py ministryofjustice --excel moj-security-posture.xlsx

# Export Excel and JSON using a smaller repo sample
python org_security_posture.py ministryofjustice --excel moj-security-posture.xlsx --json --repo-limit 50

# Force a fresh pull instead of using the local cache
python org_security_posture.py ministryofjustice --no-cache
```

### 4. `dashboard.py` - Interactive Web Dashboard

Launches an interactive Dash web dashboard to browse and manage repository audits. Allows searching, filtering, and running new audits directly from the UI.

**Usage:**

```bash
python dashboard.py [options]
```

**Options:**

- `--db <path>` - Custom database path (default: `repo_audit.db`)

**Examples:**

```bash
# Start dashboard with default database
export GITHUB_TOKEN=ghp_xxxx
python dashboard.py

# Start with custom database
python dashboard.py --db /tmp/audit.db
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
python testEnv.py
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
python testEnv.py

# In Jupyter cell
!python testEnv.py

# With custom token
export GH_TOKEN=ghp_xxxx
python testEnv.py
```

## Database Schema

### `repo_data` Table

Core storage uses a single SQLite table that stores one merged JSON payload per repository:

| Column    | Type      | Description                                   |
| --------- | --------- | --------------------------------------------- |
| full_name | TEXT (PK) | Repository full name (`owner/repo`)           |
| data      | TEXT      | JSON-serialized `RepoData` from core models   |

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
python list_repos.py --repo-file repo_list.yaml --excel audit_results.xlsx

# 2. Launch dashboard to explore results
python dashboard.py

# 3. Click on repos to view details or run deeper audits
```

### Archive Review Workflow

```bash
# 1. Generate a CSV of old or archived repositories
python archive_repos.py ministryofjustice --csv archivable.csv

# 2. Re-run quickly from the local caches while refining filters
python archive_repos.py ministryofjustice --cache-only --csv archivable.csv

# 3. Optionally persist to a custom SQLite file for downstream analysis
python archive_repos.py ministryofjustice --audit-db /tmp/archive-audit.db
```

### Organisation Security Posture Review

```bash
# 1. Generate an organisation-wide posture workbook
python org_security_posture.py ministryofjustice --excel moj-security-posture.xlsx

# 2. Re-run without cache when you need fresh data
python org_security_posture.py ministryofjustice --no-cache --json
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
python list_repos.py --repo-file repo_list.yaml --db repo_audit.db

# View in dashboard
python dashboard.py
```

### Continuous Monitoring

```bash
# Re-run audits to update the core storage database
export GITHUB_TOKEN=ghp_xxxx
python list_repos.py --repo-file repo_list.yaml --db repo_audit.db

# Dashboard automatically shows updated data
python dashboard.py
```

## Troubleshooting

### "Command failed: gh api ..." Error

- Ensure `gh` CLI is installed: `which gh`
- Authenticate with `gh`: `gh auth login`
- Check token has correct scopes (requires `repo` and `read:org`)

### Authentication Issues Between Environments

```bash
python testEnv.py
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
python list_repos.py --repo-file repo_list.yaml --limit 20 --excel github_audit.xlsx
```

### Audit specific critical repos

```bash
export GITHUB_TOKEN=ghp_xxxx
python list_repos.py --repo-file repo_list.yaml --limit 2 --db repo_audit.db
python dashboard.py
# Select each repo and click "Run Audit" for updated details in core storage
```

### Use dashboard to identify high-risk repos

```bash
export GITHUB_TOKEN=ghp_xxxx
python list_repos.py --repo-file repo_list.yaml --db repo_audit.db
python dashboard.py
# Filter by "Show only repos with flags"
```

### Export archive candidate data

```bash
python archive_repos.py ministryofjustice --csv archivable.csv
python archive_repos.py ministryofjustice --cache-only --sort -days_since_push
```

### Export organisation posture report

```bash
python org_security_posture.py ministryofjustice --excel moj-security-posture.xlsx
python org_security_posture.py ministryofjustice --json --repo-limit 50
```

## License

Part of the investigate repository.
