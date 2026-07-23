# GitHub Estate Analysis Scripts

## API Call Overlap and Pull-Once Model

**Purpose:** identify where the same exact values are being pulled across scripts, so the data can be collected once and reused to reduce duplicate GitHub API calls.

## Executive Summary

- The largest duplication is between `list_repos.py` and `archive_repos.py`.
- Most audit flags do not need their own API calls.
- Organisation-level metrics should be split between org-level settings and derived aggregates.
- Introduce a shared collection/cache layer and generate outputs from shared data.

## Common Values Collected Multiple Times

| Value          | Appears In                                               | Collect Once From                 |
| -------------- | -------------------------------------------------------- | --------------------------------- |
| org            | list_repos.py, archive_repos.py                          | repo inventory context            |
| repo           | list_repos.py, archive_repos.py, alert_metrics.py        | repo inventory context            |
| full_name      | list_repos.py, archive_repos.py, repo_data table         | repo object                       |
| private        | list_repos.py, archive_repos.py                          | repo object                       |
| archived       | list_repos.py, archive_repos.py, audit flags             | repo object                       |
| fork           | list_repos.py, archive_repos.py, audit flags             | repo object                       |
| pushed_at      | list_repos.py, archive_repos.py                          | repo object                       |
| default_branch | list_repos.py, archive_repos.py, org_security_posture.py | repo object / org default setting |
| language       | list_repos.py, archive_repos.py                          | repo object                       |
| open_issues    | list_repos.py, archive_repos.py                          | repo object                       |
| stargazers     | list_repos.py, archive_repos.py                          | repo object                       |
| flags          | list_repos.py, archive_repos.py, audit flags             | derived locally                   |

## Derived Values That Should Not Make API Calls

| Derived Value                     | Needs Only                        |
| --------------------------------- | --------------------------------- |
| days_since_push                   | pushed_at                         |
| age_days                          | created_at                        |
| days_since_archived               | archived_at                       |
| archived audit flag               | archived                          |
| fork audit flag                   | fork                              |
| dependabot_alerts_present         | dependabot_alerts                 |
| secret_alerts_present             | secret_scanning_alerts            |
| code_scanning_alerts_present      | code_scanning_alerts              |
| public_unprotected_default_branch | private, default_branch_protected |
| no_actions_workflows              | workflow detection result         |
| no_detected_tests                 | workflow content scan result      |
| no_detected_linting               | workflow content scan result      |

## Security Values And Repeated Concepts

| Value / Concept        | Appears In                                   | Better Approach                                            |
| ---------------------- | -------------------------------------------- | ---------------------------------------------------------- |
| Dependabot alerts      | dependabot_alerts, dependabot_alerts_present | Pull alert count once, derive flag locally.                |
| Code scanning alerts   | multiple code scanning fields                | Pull repo alert counts once, aggregate org totals locally. |
| Secret scanning alerts | multiple secret scanning fields              | Pull repo alert counts once, aggregate org totals locally. |
| Branch protection      | branch protection fields and counts          | Pull once, derive repo and org metrics.                    |
| Rulesets               | ruleset fields and org_rulesets_count        | Pull once at appropriate level.                            |

## Workflow Values

Collect workflow files once per repository and derive summaries and flags from that result.

## Values That Are Probably Standalone

- LFS / large files
- Alert remediation metrics
- Org-only settings

## Recommended Pull-Once Model

1. `repo_inventory`
2. `repo_security`
3. `repo_workflows`
4. `repo_alerts`
5. `org_security`
6. `repo_large_files`

## Generate Outputs From Cached Data

- `list_repos.py` → repo_inventory + repo_security + audit_flags
- `archive_repos.py` → repo_inventory + archive-specific fields
- `org_security_posture.py` → org_security + aggregates
- `github_workflow.py` → repo_workflows + inventory data
- `alert_metrics.py` → repo_alerts
- `lfs_script.py` → repo_large_files
- `repo_data table` → stored normalised data
- audit flags → derived locally

## Implementation Note

Treat `list_repos.py` / repo inventory as the base collection layer and stop `archive_repos.py` from re-pulling basic repository metadata.
Separate collection from reporting and generate outputs from a shared cache.
