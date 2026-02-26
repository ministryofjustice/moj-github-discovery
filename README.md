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

### 1. `list_repos.py` - List and Audit Organization Repositories

Lists repositories from a GitHub organization and audits each one, storing results in a SQLite database.

**Usage:**
```bash
python list_repos.py <org> [options]
```

**Options:**
- `--db <path>` - Custom database path (default: `repo_audit.db`)
- `--excel <path>` - Export results to Excel file
- `--limit <N>` - Maximum number of repos to fetch (default: 400)
- `--repos <repo1,repo2>` - Audit specific repos (format: `owner/repo`)
- `--repo-file <file>` - Audit repos listed in a file (one per line, format: `owner/repo`)

**Examples:**

```bash
# Audit all repos in 'github' organization
export GITHUB_TOKEN=ghp_xxxx
python list_repos.py github

# Audit with limit and export to Excel
python list_repos.py github --limit 50 --excel report.xlsx

# Audit specific repos
python list_repos.py github --repos github/cli,github/copilot-docs

# Audit repos from file
python list_repos.py github --repo-file repos.txt

# Custom database location
python list_repos.py github --db /tmp/audit.db
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

### Batch Audit Specific Repos

```bash
# Create repos.txt
cat > repos.txt <<EOF
owner/repo1
owner/repo2
owner/repo3
EOF

# Audit them
export GITHUB_TOKEN=ghp_xxxx
python list_repos.py owner --repo-file repos.txt --db batch_audit.db

# View in dashboard
python dashboard.py --db batch_audit.db
```

### Continuous Monitoring

```bash
# Re-run audit with `--db` to update existing database
export GITHUB_TOKEN=ghp_xxxx
python list_repos.py myorg --db myorg_audit.db

# Dashboard automatically shows updated data
python dashboard.py --db myorg_audit.db
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
python list_repos.py myorg --db myorg.db
python dashboard.py --db myorg.db
# Filter by "Show only repos with flags"
```

## License

Part of the investigate repository.
