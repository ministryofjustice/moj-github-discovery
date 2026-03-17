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

## Scripts

### 1. `list_repos.py` - List and Audit Organization Repositories

Lists repositories from a GitHub organization and audits each one, storing results in a SQLite database.
Internally the script reuses a single HTTP session and processes multiple repos in parallel, so it should be reasonably fast even for large organizations.
Output defaults depend on options provided.

**Usage:**

```bash
python list_repos.py <org> [options]
```

> Running the command with **no options** will print the 10 most recently updated
> repositories for the organisation to stdout as JSON. Using `--excel` or
> `--audit-db` (or specifying a limit) changes this behaviour as described below.

**Options:**

- `--excel <path>` - Export results to Excel file (full list unless `--limit` set). Requires the `openpyxl` package.
- `--limit <N>` - Maximum number of repos to fetch (default: 400; when no other options provided output is limited to 10)
- `--sort [-]column` - Sort by repo field (`-` prefix for descending). Defaults to last updated (`pushed_at` desc).
- `--repo-file <file>` - Audit repos listed in a file (one per line, format: `owner/repo`)
- `--audit-db [path]` - Write audit rows to SQLite database (default: `repo_audit.db` in current directory; optional custom path).
  - Writes full list unless `--limit` set.
- `--no-alerts` - Skip security alert queries (dependabot/code-scanning/secret-scanning). Useful when your token lacks access or to speed up runs.

**Examples:**

```bash
# Default behaviour: show 10 most recent repos on stdout
python list_repos.py github

# Full export to Excel (ignores the default 10 limit unless --limit set)
python list_repos.py github --excel report.xlsx

# Full audit database write (400‑repo default, override with --limit)
python list_repos.py github --audit-db

# Limit results to 50 and also write to Excel
python list_repos.py github --limit 50 --excel report.xlsx

# Audit repos from a file, still respect any --limit value
python list_repos.py github --repo-file repos.txt --limit 20

# Write audit entries to a custom database path
python list_repos.py github --audit-db /tmp/audit.db

# Sort by stars ascending and (with no other options) output ten most recent
python list_repos.py github --sort +stargazers
```

### 2. `audit_repo.py` - Audit Single Repository

Performs a detailed audit of a single repository and saves results to the database. Outputs full JSON report to stdout.

**Usage:**

```bash
python audit_repo.py <owner/repo> [options]
```

**Options:**

- `--db <path>` - Custom database path (default: `repo_audit.db`)

**Output:**

- Detailed JSON audit report printed to stdout
- Data saved to `audits` table in SQLite database
- Status message printed to stderr

**Examples:**

```bash
# Audit a repository
export GITHUB_TOKEN=ghp_xxxx
python audit_repo.py github/cli

# Audit and save to custom database
python audit_repo.py github/copilot-docs --db /tmp/custom.db

# Capture JSON output to file
python audit_repo.py github/cli > audit_report.json
```

**Audit Includes:**

- Repository metadata (visibility, fork status, language, activity)
- Security alerts (Dependabot, code scanning, secret scanning)
- Branch protection status
- Community files (SECURITY.md, CODE_OF_CONDUCT, CONTRIBUTING)
- GitHub Actions workflows
- Workflow analysis (test & lint detection)
- Risk flags (archived, public unprotected, missing policies, etc.)

### 3. `archive_repos.py` - Find Archive Candidates

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
- `--audit-db [path]` - Write rows to the `repo_rows` table in SQLite. If omitted, no database write occurs. If the flag is provided without a path, the default is `repo_audit.db` beside the script.
- `--cache-only` - Do not call the GitHub API. Use only existing local caches.

**Output:**

- CSV when `--csv` is used
- SQLite rows when `--audit-db` is used
- JSON to stdout when neither `--csv` nor `--audit-db` is provided
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

### 4. `org_security_posture.py` - Audit Organisation Security Posture

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

### 5. `dashboard.py` - Interactive Web Dashboard

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

### 6. `testEnv.py` - Diagnose GitHub CLI Authentication

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

### `repo_rows` Table

Contains summary information written by scripts such as `list_repos.py` and `archive_repos.py`:

| Column     | Type      | Description                                 |
| ---------- | --------- | ------------------------------------------- |
| full_name  | TEXT (PK) | Repository full name (owner/repo)           |
| audit_json | TEXT      | JSON data including metadata, alerts, flags |

### `audits` Table

Contains detailed audit information from `audit_repo.py`:

| Column     | Type      | Description                       |
| ---------- | --------- | --------------------------------- |
| full_name  | TEXT (PK) | Repository full name (owner/repo) |
| audit_json | TEXT      | Complete nested audit JSON        |

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
python list_repos.py myorg --excel audit_results.xlsx

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

# 3. Optionally store the same rows in SQLite for downstream analysis
python archive_repos.py ministryofjustice --audit-db
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
# Create repos.txt
cat > repos.txt <<EOF
owner/repo1
owner/repo2
owner/repo3
EOF

# Audit them
export GITHUB_TOKEN=ghp_xxxx
python list_repos.py owner --repo-file repos.txt --audit-db

# View in dashboard
python dashboard.py
```

### Continuous Monitoring

```bash
# Re-run audit with `--audit-db` to update the dashboard database
export GITHUB_TOKEN=ghp_xxxx
python list_repos.py myorg --audit-db

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
python list_repos.py github --limit 20 --excel github_audit.xlsx
```

### Audit specific critical repos

```bash
export GITHUB_TOKEN=ghp_xxxx
python audit_repo.py github/cli > cli_audit.json
python audit_repo.py github/copilot-docs > copilot_audit.json
```

### Use dashboard to identify high-risk repos

```bash
export GITHUB_TOKEN=ghp_xxxx
python list_repos.py myorg --audit-db
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
