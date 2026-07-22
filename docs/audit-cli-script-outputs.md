# Audit-CLI Script Output Terms

A concise reference of the fields, headings, and audit flags produced per script linked to `audit-cli`.

## list_repos.py

| Specific Terms / Headings                         |
| ------------------------------------------------- |
| org                                               |
| repo                                              |
| full_name                                         |
| private                                           |
| archived                                          |
| fork                                              |
| fork_source                                       |
| is_generated_from_template                        |
| template_source                                   |
| pushed_at                                         |
| default_branch                                    |
| language                                          |
| open_issues                                       |
| stargazers                                        |
| dependabot_access                                 |
| dependabot_alerts                                 |
| code_scanning_access                              |
| code_scanning_alerts                              |
| secret_scanning_access                            |
| secret_scanning_alerts                            |
| default_branch_protected                          |
| protection_settings                               |
| branch_protection_enforce_admins                  |
| branch_protection_dismiss_stale_reviews           |
| ruleset_dismiss_stale_reviews                     |
| branch_protection_required_approving_review_count |
| branch_protection_required_signatures             |
| ruleset_enforce_admins                            |
| ruleset_dismiss_stale_reviews                     |
| ruleset_require_code_owner_reviews                |
| ruleset_required_approving_review_count           |
| ruleset_required_signatures                       |
| codeowners                                        |
| codeowners_path                                   |
| flags                                             |

## archive_repos.py

| Specific Terms / Headings                 |
| ----------------------------------------- |
| org                                       |
| repo                                      |
| full_name                                 |
| private                                   |
| archived                                  |
| disabled                                  |
| fork                                      |
| dependency_graph_enabled                  |
| references                                |
| archive_references                        |
| archived_at                               |
| active_references                         |
| pushed_at                                 |
| default_branch                            |
| language                                  |
| open_issues                               |
| stargazers                                |
| watchers                                  |
| forks                                     |
| description                               |
| created_at                                |
| updated_at                                |
| size                                      |
| is_template                               |
| security_and_analysis                     |
| secret_scanning                           |
| secret_scanning_push_protection           |
| dependabot_security_updates               |
| secret_scanning_non_provider_patterns     |
| secret_scanning_ai_detection              |
| secret_scanning_validity_checks           |
| secret_scanning_delegated_alert_dismissal |
| flags                                     |
| days_since_push                           |
| age_days                                  |
| days_since_archived                       |

## org_security_posture.py

| Specific Terms / Headings       |
| ------------------------------- |
| org_name                        |
| public_repos                    |
| total_private_repos             |
| 2fa_requirement_enabled         |
| default_repo_permission         |
| default_branch                  |
| total_members                   |
| members_without_2fa             |
| outside_collaborators           |
| teams_count                     |
| code_scanning_open_alerts       |
| credential_scanning_open_alerts |
| repos_checked_for_supply_chain  |
| repos_with_sbom                 |
| repos_with_branch_protection    |
| self_hosted_runners             |
| allowed_actions_policy          |
| org_credential_count            |
| default_workflow_permissions    |
| org_webhooks_count              |
| installed_github_apps           |
| org_rulesets_count              |

## github_workflow.py

### Posture Report

| Specific Terms / Headings                          |
| -------------------------------------------------- |
| Total repositories scanned                         |
| Repos using GitHub Actions                         |
| Repos NOT using GitHub Actions                     |
| Total workflow files found                         |
| Active repos with workflows                        |
| Active repos without workflows                     |
| Archived repos with workflows                      |
| Archived repos without workflows                   |
| Candidates for disabling Actions                   |
| TOP REPOSITORIES BY WORKFLOW COUNT                 |
| ARCHIVED REPOS WITH WORKFLOWS (DISABLE CANDIDATES) |
| ACTIVE REPOS: ACTIONS ENABLED BUT NO WORKFLOWS     |

### Actions Analysis

| Specific Terms / Headings |
| ------------------------- |
| owner                     |
| actions_referenced        |
| action_name               |
| times_used                |

### Permissions Analysis

| Specific Terms / Headings |
| ------------------------- |
| repo,workflow_path        |
| has_explicit_permissions  |
| permissions_value         |
| has_write_permissions     |
| finding                   |

### Credentials Analysis

| Specific Terms / Headings |
| ------------------------- |
| repo                      |
| workflow_path             |
| has_id_token_write        |
| oidc_actions              |
| credential_secrets_found  |
| posture                   |
| total_workflows           |
| oidc                      |
| long_lived_credentials    |
| mixed                     |
| no_cloud_auth_detected    |
| could_not_load            |

### Trigger Risk Analysis

| Specific Terms / Headings |
| ------------------------- |
|                           |

## alert_metrics.py

| Specific Terms / Headings |
| ------------------------- |
| id                        |
| type                      |
| repo                      |
| created_at                |
| remediated_at             |
| state                     |
| severity                  |
| ttr_days                  |

## lfs_script.py

| Specific Terms / Headings |
| ------------------------- |
| Repository                |
| Largest Blob Bytes        |
| Largest blob path         |
| Exceeds Soft Limit        |
| Exceeds Hard Limit        |
| SHA                       |
| size_bytes                |
| path                      |

## repo_data table Schema (SQLite)

| Specific Terms / Headings       |
| ------------------------------- |
| full_name (e.g. `{org}/{repo}`) |
| data                            |

## Audit Flags

| Flag                              | Definition                                     |
| --------------------------------- | ---------------------------------------------- |
| archived                          | Repository is archived (no longer maintained). |
| fork                              | Repository is a fork.                          |
| no_license                        | No license file present.                       |
| public_unprotected_default_branch | Public repo with unprotected default branch.   |
| dependabot_alerts_present         | Dependabot has found vulnerable dependencies.  |
| secret_alerts_present             | Secret scanning alerts exist.                  |
| code_scanning_alerts_present      | Code scanning alerts exist.                    |
| no_security_policy                | Missing SECURITY.md.                           |
| no_code_of_conduct                | Missing CODE_OF_CONDUCT.                       |
| no_actions_workflows              | No CI/CD workflows configured.                 |
| no_detected_tests                 | CI/CD exists but no test detection.            |
| no_detected_linting               | CI/CD exists but no lint detection.            |
