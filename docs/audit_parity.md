# Comparing Authentication Methods

This guide explains how to compare audit outputs produced with PAT authentication and GitHub App authentication using `utils/audit_data_parity.py` with `config/audit_parity_config.yaml`.

## Purpose

Parity checks are used to validate:

- coverage parity: whether both auth methods return the same repo or metric identifiers
- data parity: whether shared identifiers contain the same field values

## Prerequisites

Before running parity checks, confirm all of the following:

- Python dependencies are installed (see `docs/setup.md` and `pyproject.toml`)
- PAT and App output files already exist at the paths configured in `config/audit_parity_config.yaml`
- each configured `id_column` exists in both corresponding PAT and App files
- for Excel inputs, the configured `sheet_name` exists when provided
- run the command from repository root so relative paths in config resolve correctly

Typical setup command:

```bash
uv sync --group dev
```

## How It Works

`utils/audit_data_parity.py`:

1. Loads `config/audit_parity_config.yaml`
2. Iterates each entry under `comparisons`
3. Loads PAT/App files as CSV or Excel
4. Normalizes missing values to `N/A`
5. Compares identifier coverage using `id_column`
6. Optionally compares field values for matched identifiers
7. Writes output reports to `audit_parity_output/`

## Config Attributes

Each script under `comparisons` supports:

- `id_column`: column used as the unique identifier for matching records between PAT and App outputs
- `pat_file`: PAT-generated output file path
- `app_file`: App-generated output file path
- `file_type`: input format (`csv` or `excel`)
- `sheet_name` (optional): Excel sheet to read for this comparison
- `comparison_level`: intended comparison mode (`full` or `coverage`)

Comparison modes:

- `full`: run coverage comparison and field-level value comparison
- `coverage`: run identifier coverage only

## Script Comparison Overview

Current entries in `config/audit_parity_config.yaml`:

```yaml
comparisons:
  list_repos:
    id_column: "full_name"
    pat_file: "outputs/list_repos/list_repos_top_50_pat.xlsx"
    app_file: "outputs/list_repos/list_repos_top_50_app.xlsx"
    file_type: "excel"
    comparison_level: "full"

  archive_repos:
    id_column: "full_name"
    pat_file: "outputs/archive_repos/archivable_top_50_pat.csv"
    app_file: "outputs/archive_repos/archivable_top_50_app.csv"
    file_type: "csv"
    comparison_level: "full"

  org_security_posture:
    id_column: "metric"
    pat_file: "outputs/org_security_posture/moj-security-posture_pat.xlsx"
    app_file: "outputs/org_security_posture/moj-security-posture_app.xlsx"
    file_type: "excel"
    sheet_name: "Summary"
    comparison_level: "full"

  alert_metrics:
    id_column: "repo"
    pat_file: "outputs/alert_metrics/alerts_top_50_pat.csv"
    app_file: "outputs/alert_metrics/alerts_top_50_app.csv"
    file_type: "csv"
    comparison_level: "coverage" # only check repo coverage, skip field differences due to large data size
```

## Run Commands

Default config path:

```bash
uv run python utils/audit_data_parity.py
```

Custom config path:

```bash
uv run python utils/audit_data_parity.py config/audit_parity_config.yaml
```

## Outputs

Reports are written under `audit_parity_output/`:

- `new_repos_<script_name>.xlsx`
  - always generated
  - contains identifiers present in App output and not in PAT output

- `diffs_<script_name>.xlsx`
  - generated only when full comparison is enabled and differences are found
  - includes one sheet per differing field

## Troubleshooting

- `Error: '<id_column>' column not found...`
  - ensure both files include the same identifier column header

- Excel sheet issues
  - check that `sheet_name` is correct and exists in the workbook

- no differences file produced
  - expected when no field-level differences are detected

- path/file not found
  - verify outputs exist and that paths in config are relative to repo root

## Implementation Note

`comparison_level` is currently read from the top-level config object in `utils/audit_data_parity.py`, not per-script config entry.
If per-script behavior is required, update the script to read `conf.get("comparison_level", "full")` inside the loop.
