# Audit-CLI Script Output Terms

A concise reference of the fields, headings, and audit flags produced per script linked to `audit-cli`.

## list_repos.py

| Specific Terms / Headings       | Description                                                                                                    |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| org                             | github organisation (e.g. `ministryofjustice`)                                                                 |
| repo                            | github repository name e.g. `developer-experience-documentation`                                               |
| full_name                       | {org}/{repo} e.g. `ministryofjustice/developer-experience-documentation`                                       |
| private                         | (Boolean) - Is the repository private?                                                                         |
| archived                        | (Boolean) - Is the repository archived?                                                                        |
| fork                            | (Boolean) - Is the repository a fork of another repository?                                                    |
| fork_source                     | Fork repo name (if applicable)?                                                                                |
| is_generated_from_template      | (Boolean) - Is the repository generated via a template?                                                        |
| template_source                 | Template repo name (if applicable)                                                                             |
| last_pushed_at                  | Timestamp for last push activity to default branch                                                             |
| last_pushed_activity            | Timestamp for last push activity to any branch                                                                 |
| default_branch                  | Default branch for repository e.g. `main`, `master`, etc.                                                      |
| language                        | Core programming language used within repository.                                                              |
| open_issues                     | Integer count of number of open issues within repository                                                       |
| stargazers                      | Integer count of number of stargazers against repository repository                                            |
| dependabot_access               | Verification of dependabot presence and                                                                        |
| dependabot_alerts               | Integer count of dependabot alerts                                                                             |
| code_scanning_access            | Verification of access to dependabot code scanning alerts via `/repos/o/r/code-scanning/alerts?state=open`     |
| code_scanning_alerts            | Integer count of open code scanning alerts                                                                     |
| secret_scanning_access          | Verification of access to dependabot secret scanning alerts via `/repos/o/r/secret-scanning/alerts?state=open` |
| secret_scanning_alerts          | Integer count of open secret scanning alerts                                                                   |
| default_branch_protected        | Boolean check for if default branch is protected via classic branch protection or repo rulesets                |
| compliance_method               | branch_protection, rulesets, or none (no protection)                                                           |
| branch_protection_enabled       | Boolean check for if branch protection is enabled (classic branch protection)                                  |
| has_active_rulesets             | Boolean check for if the repository has active rulesets (at least 1 targeting the default branch)              |
| protection_settings             | settings list under classic branch protection for deefault branch e.g. `enforce_admins`, `required_signatures` |
| enforce_admins                  | Boolean check for if `enforce_admins` is enabled (classic branch protection only)                              |
| dismiss_stale_reviews           | Boolean check for if `dismiss_stale_reviews` is enabled (classic branch protection or rulesets)                |
| required_approving_review_count | Integer count of required approving reviews if `required_pull_requests` is enabled                             |
| required_signatures             | Boolean check for if `required_signatures` is enabled (classic branch protection or rulesets)                  |
| codeowners                      | Boolean check for if `dismiss_stale_reviews` is enabled (classic branch protection or rulesets)                |
| codeowners_path                 | Path for `CODEOWNERS` file if found                                                                            |
| flags                           | List of flags as per [audit-flags](#audit-flags) - derived from field results above                            |

## archive_repos.py

| Specific Terms / Headings                 | Description                                                              |
| ----------------------------------------- | ------------------------------------------------------------------------ |
| org                                       | github organisation (e.g. `ministryofjustice`)                           |
| repo                                      | github repository name e.g. `developer-experience-documentation`         |
| full_name                                 | {org}/{repo} e.g. `ministryofjustice/developer-experience-documentation` |
| private                                   | (Boolean) - Is the repository private?                                   |
| archived                                  | (Boolean) - Is the repository archived?                                  |
| disabled                                  |                                                                          |
| fork                                      |                                                                          |
| dependency_graph_enabled                  |                                                                          |
| references                                |                                                                          |
| archive_references                        |                                                                          |
| archived_at                               |                                                                          |
| active_references                         |                                                                          |
| pushed_at                                 |                                                                          |
| default_branch                            |                                                                          |
| language                                  |                                                                          |
| open_issues                               |                                                                          |
| stargazers                                |                                                                          |
| watchers                                  |                                                                          |
| forks                                     |                                                                          |
| description                               |                                                                          |
| created_at                                |                                                                          |
| updated_at                                |                                                                          |
| size                                      |                                                                          |
| is_template                               |                                                                          |
| security_and_analysis                     |                                                                          |
| secret_scanning                           |                                                                          |
| secret_scanning_push_protection           |                                                                          |
| dependabot_security_updates               |                                                                          |
| secret_scanning_non_provider_patterns     |                                                                          |
| secret_scanning_ai_detection              |                                                                          |
| secret_scanning_validity_checks           |                                                                          |
| secret_scanning_delegated_alert_dismissal |                                                                          |
| flags                                     |                                                                          |
| days_since_push                           |                                                                          |
| age_days                                  |                                                                          |
| days_since_archived                       |                                                                          |

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
