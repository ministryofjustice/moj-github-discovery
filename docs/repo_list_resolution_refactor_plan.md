# Repo List Resolution Refactor Plan

Status: deferred to a separate branch.

## Goal

Unify repository selection logic under `core/repo_list.py` while keeping script behavior explicit, testable, and backwards compatible.

## Proposed Scope

1. Add a shared resolver in `core/repo_list.py`.
2. Keep current precedence explicit and documented:
   - CLI `--repos` values when provided.
   - Configured repo list file (for example `repo_list_file` from audit config).
   - Optional default `repo_list.yaml` in working directory if still desired.
   - Org API listing fallback (where script semantics permit it).
3. Return both resolved repos and a source label for observability.
4. Wire scripts incrementally to the shared resolver:
   - `scripts/list_repos.py`
   - `scripts/github_workflow.py`
   - `scripts/lfs_script.py`
   - `scripts/org_security_posture.py`
5. Decide whether a top-level CLI arg override is needed in `main.py` (for example `--repo-file`) and document final UX.

## Compatibility Guardrails

1. No Docker image dependency on bundling `repo_list.yaml`.
2. Preserve existing Make targets and default args behavior.
3. Preserve script-specific validation and failure messages where possible.
4. Avoid changing auth behavior while changing repo resolution.

## Test Plan

1. Unit tests for resolver precedence and limit handling in `tests/test_repo_list.py`.
2. Script-level tests for each consumer’s expected fallback order.
3. Main CLI argument parsing tests only if a new flag is introduced.
4. Smoke check with:
   - `make audit-cli-smoke`
   - `make audit-dashboard-run`

## Suggested Branch Workflow

1. Create branch from current baseline.
2. Implement resolver + tests first.
3. Migrate one script at a time with tests.
4. Run full test suite and Docker smoke checks.
5. Open PR with migration notes and behavior matrix.
