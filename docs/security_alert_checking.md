# Security Alert Check Pipeline

This guide documents the three files used by the security alert check flow:

- [security-tools/security_alert_check.yml](../security-tools/security_alert_check.yml)
- [scripts/alert_metrics.py](../scripts/alert_metrics.py)
- [security-tools/sla_wrapper.py](../security-tools/sla_wrapper.py)

It explains what each file does, how the end-to-end flow works, and how to update each file safely.

## End-to-End Flow

1. The workflow checks out the current repository.
2. It installs Python dependencies.
3. It clones the moj-github-discovery repository into a nested folder named moj-github-discovery.
4. It applies compatibility patches to files inside the cloned copy.
5. It runs [scripts/alert_metrics.py](../scripts/alert_metrics.py) from the cloned copy to generate github_alerts_limited.csv.
6. It runs [security-tools/sla_wrapper.py](../security-tools/sla_wrapper.py) from the cloned copy to evaluate SLA status.
7. The job fails when an SLA breach is detected or when any earlier workflow step errors.

## File 1: security-tools/security_alert_check.yml

### Purpose

Defines a GitHub Actions job that collects security alerts for the current repository and checks them against SLA thresholds.

### How It Works

- Trigger:
  - Runs on pull requests and pushes.
- Permissions:
  - Uses read-only repository and security-events permissions.
- Runtime:
  - Uses Ubuntu runner and Python 3.11.
- Data collection:
  - Runs [scripts/alert_metrics.py](../scripts/alert_metrics.py) against the repository from github.repository.
- SLA decision:
  - Runs [security-tools/sla_wrapper.py](../security-tools/sla_wrapper.py), which exits with non-zero status on breach.

Important implementation detail:

- Most commands use paths prefixed with moj-github-discovery/... because the workflow clones a second copy of this repo at runtime.

### How To Update Safely

- Keep path context consistent:
  - If you keep the clone step, continue using moj-github-discovery/... paths.
  - If you remove the clone step, update all command paths to point to checked-out workspace files directly.
- Keep token scope minimal:
  - Use a PAT only if required by the alert API access pattern.
  - Prefer least-privilege secret values.
- Keep output filename alignment:
  - If you change the collector output filename, also update CSV_FILE in [security-tools/sla_wrapper.py](../security-tools/sla_wrapper.py).
- Keep patch steps aligned with upstream code:
  - This workflow patches files in-place at runtime.
  - If upstream source changes, the string replacement patch logic may stop matching and should be revised.

### Common Pitfalls

- Putting this workflow outside .github/workflows means GitHub Actions will not auto-discover it.
- Changing clone directory name without updating prefixed file paths breaks commands.

## File 2: scripts/alert_metrics.py

### Purpose

Collects repository security alerts from GitHub APIs and writes normalized alert records to CSV.

### How It Works

- Reads runtime/config values via core config models.
- Builds a GitHub client with selected auth mode.
- Determines target repos:
  - Single repo when --repo is passed.
  - Organization-wide list otherwise.
- For each repo, fetches:
  - code_scanning alerts
  - dependabot alerts
  - secret_scanning alerts
- Normalizes each alert row with fields such as:
  - id, type, repo, archive_status, created_at, remediated_at, state, severity, ttr_days
- Writes CSV using the compiler helper and prints summary stats.

### How To Update Safely

- Preserve output schema stability:
  - [security-tools/sla_wrapper.py](../security-tools/sla_wrapper.py) expects columns including severity, created_at, and state.
  - If you rename or remove columns, update downstream readers in the same change.
- Preserve date format compatibility:
  - created_at and remediated_at should stay ISO-8601 compatible for downstream parsing.
- Handle API variance defensively:
  - Keep non-dict checks and exception handling to avoid hard failure on partial API anomalies.
- Be careful with limits:
  - max_alerts is a global cap across all repos, not per repo.
  - Repo ordering can affect which alerts are included when capped.

### Common Pitfalls

- Changing severity mapping without updating SLA thresholds can cause false breach/no-breach results.
- Removing archive status fallback logic may reduce resilience on permission-limited repos.

## File 3: security-tools/sla_wrapper.py

### Purpose

Evaluates open alerts from CSV against severity-based SLA thresholds and sets CI pass/fail status.

### How It Works

- Reads github_alerts_limited.csv.
- Parses created_at timestamps.
- Ignores non-open alerts.
- For each open alert with known severity:
  - Computes age in days.
  - Compares age against SLA thresholds:
    - critical: 7
    - high: 14
    - medium: 30
    - low: 90
- Emits GitHub Actions annotations:
  - warning for within-SLA open alerts
  - error for out-of-SLA alerts
- Exits with code 1 when at least one breach is found, otherwise exits 0.

### How To Update Safely

- Keep CSV contract in sync:
  - If alert CSV field names change in [scripts/alert_metrics.py](../scripts/alert_metrics.py), update reader keys here.
- Keep exit semantics intentional:
  - Non-zero exit means workflow failure.
  - Only change this behavior if policy changes are explicit.
- Add explicit handling for missing or empty input if needed:
  - Current base file assumes the CSV exists and has headers.
  - If your environment can produce empty files, add a guard before reading.

### Common Pitfalls

- A missing CSV file causes runtime failure before SLA logic runs.
- Severity labels outside SLA map are skipped silently.

## Safe Change Checklist

Before merging updates across these files:

1. Confirm workflow command paths still match runtime working directory assumptions.
2. Confirm output filename and CSV columns are still consistent between collector and SLA checker.
3. Run a local dry run:
   - Collector generates CSV.
   - SLA checker reads that CSV and returns expected exit status.
4. Test at least two scenarios:
   - No open alerts.
   - One known SLA breach.
5. If patch-at-runtime logic is still used, verify patch search strings still match upstream file content.
