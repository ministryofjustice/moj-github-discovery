# Repository Audit Tool

A comprehensive Python toolset for auditing GitHub repositories across organizations. Analyzes security posture, CI/CD workflows, branch protection, security alerts, and community standards.

## Setup

### Prerequisites

- Python 3.7+
- GitHub CLI (`gh`) installed and authenticated
- GitHub personal access token with appropriate scopes

### Environment Variables

Set your GitHub token as an environment variable:

```bash
# Using a personal access token
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# Or if using the GitHub CLI default:
export GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
```

The tools will automatically use whichever token is available (checks both `GH_TOKEN` and `GITHUB_TOKEN`).

### Installation

```bash
pip install -r requirements-dashboard.txt
```

## Scripts

### 1. `fetch_repos.py` - Fetch Full Repository Metadata

Fetches all fields returned by the GitHub API for every repository in an
organization and optionally saves the raw JSON into a lightweight SQLite
"full-repos" database.  This is useful if you need the unfiltered data for
later analysis or want a snapshot without any audit augmentation.

**Usage:**
```bash
python fetch_repos.py <org> [options]
```

**Options:**
- `--limit <N>` - stop after N repositories (default: 5000, i.e. effectively
  no limit for most orgs).
- `--db <path>` - path to a SQLite database.  When provided a table named
  `full_repos` will be created (columns `full_name` and `repo_json`) and each
  repository's JSON blob will be inserted.  Omit this option to write the
  raw list to stdout.

**Examples:**
```bash
# write all repo metadata to a file
python fetch_repos.py github > repos.json

# store results in a database for later querying
python fetch_repos.py github --db /tmp/full-repos.db

# only fetch the first 50 repos and dump to stdout
python fetch_repos.py github --limit 50
```


### 2. `list_repos.py` - List and Audit Organization Repositories

Lists repositories from a GitHub organization and audits each one, storing results in a SQLite database.  Internally the script reuses a single HTTP session and processes multiple repos in parallel, so it should be reasonably fast even for large organizations. Output defaults depend on options provided.

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
- `--audit-db [path]` - Write audit rows to SQLite database (default: `repo_audit.db` in current directory; optional custom path). Writes full list unless `--limit` set.
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

### 3. `dashboard.py` - Interactive Web Dashboard

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

> Both the dashboard and command‑line tools now reuse a persistent GitHub
> API session and perform work in parallel where possible, delivering
> noticeably faster results on large orgs.
- Click any row to view detailed audit information
- Run audits on-demand from the dashboard
- View security metrics, alerts, and compliance status
- Color-coded risk flags

**Access:** Open http://localhost:8050 in your browser

### 4. `testEnv.py` - Diagnose GitHub CLI Authentication

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
Contains summary information from `list_repos.py`:

| Column | Type | Description |
|--------|------|-------------|
| full_name | TEXT (PK) | Repository full name (owner/repo) |
| audit_json | TEXT | JSON data including metadata, alerts, flags |

### `audits` Table
Contains detailed audit information from `audit_repo.py`:

| Column | Type | Description |
|--------|------|-------------|
| full_name | TEXT (PK) | Repository full name (owner/repo) |
| audit_json | TEXT | Complete nested audit JSON |

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

## License

Part of the investigate repository.
