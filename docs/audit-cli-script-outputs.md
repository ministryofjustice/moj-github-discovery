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
| last_push_activity              | Timestamp for last push activity to any branch                                                                 |
| default_branch                  | Default branch for repository e.g. `main`, `master`, etc.                                                      |
| language                        | Core programming language used within repository.                                                              |
| open_issues                     | Integer count of number of open issues within repository                                                       |
| stargazers                      | Integer count of stargazers for the repository                                                                 |
| dependabot_access               | Dependabot alerts API access status ("ok" or an error message if the call failed)                              |
| dependabot_alerts               | Integer count of dependabot alerts                                                                             |
| code_scanning_access            | Verification of access to dependabot code scanning alerts via `/repos/o/r/code-scanning/alerts?state=open`     |
| code_scanning_alerts            | Integer count of open code scanning alerts                                                                     |
| secret_scanning_access          | Verification of access to dependabot secret scanning alerts via `/repos/o/r/secret-scanning/alerts?state=open` |
| secret_scanning_alerts          | Integer count of open secret scanning alerts                                                                   |
| default_branch_protected        | Boolean check for if default branch is protected via classic branch protection or repo rulesets                |
| compliance_method               | branch_protection, rulesets, or none (no protection)                                                           |
| branch_protection_enabled       | Boolean check for if branch protection is enabled (classic branch protection)                                  |
| has_active_rulesets             | Boolean check for if the repository has active rulesets (at least 1 targeting the default branch)              |
| protection_settings             | settings list under classic branch protection for default branch e.g. `enforce_admins`, `required_signatures`  |
| enforce_admin_protection        | Boolean check for if `enforce_admins` is enabled (classic branch protection only)                              |
| dismiss_stale_reviews           | Boolean check for if `dismiss_stale_reviews` is enabled (classic branch protection or rulesets)                |
| required_approving_review_count | Integer count of required approving reviews if `required_pull_requests` is enabled                             |
| required_signatures             | Boolean check for if `required_signatures` is enabled (classic branch protection or rulesets)                  |
| codeowners                      | (Boolean) - Whether a `CODEOWNERS` file was found in the repository                                            |
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
| disabled                                  | (Boolean) - Has the repository been disabled?                            |
| fork                                      | (Boolean) - Is the repository a fork of another repository?              |
| dependency_graph_enabled                  | Security setting showing whether the dependency graph is enabled.        |
| references                                | Count of detected inbound or linked references to the repository.        |
| archive_references                        | Count of references relevant to archive decision checks.                 |
| archived_at                               | Timestamp of when the repository was archived.                           |
| active_references                         | Count of references indicating the repository may still be in use.       |
| pushed_at                                 | Timestamp of last push activity.                                         |
| default_branch                            | Default branch name for the repository.                                  |
| language                                  | Primary repository language reported by GitHub.                          |
| open_issues                               | Integer count of open issues.                                            |
| stargazers                                | Integer count of repository stargazers.                                  |
| watchers                                  | Integer count of repository watchers/subscribers.                        |
| forks                                     | Integer count of repository forks.                                       |
| description                               | Repository description text.                                             |
| created_at                                | Timestamp of repository creation.                                        |
| updated_at                                | Timestamp of last repository metadata update.                            |
| size                                      | Repository size metric reported by GitHub.                               |
| is_template                               | (Boolean) - Is the repository configured as a template?                  |
| security_and_analysis                     | Nested GitHub security-and-analysis settings object.                     |
| secret_scanning                           | Secret scanning feature state from security settings.                    |
| secret_scanning_push_protection           | Push protection state for secret scanning.                               |
| dependabot_security_updates               | Dependabot security updates feature state.                               |
| secret_scanning_non_provider_patterns     | Secret scanning non-provider pattern detection setting state.            |
| secret_scanning_ai_detection              | Secret scanning AI-detection setting state.                              |
| secret_scanning_validity_checks           | Secret scanning validity check setting state.                            |
| secret_scanning_delegated_alert_dismissal | Delegated alert dismissal setting state for secret scanning.             |
| flags                                     | List of derived audit flags for archive posture checks.                  |
| days_since_push                           | Integer number of days since last push activity.                         |
| age_days                                  | Integer repository age in days since creation.                           |
| days_since_archived                       | Integer number of days since repository was archived.                    |

## org_security_posture.py

| Specific Terms / Headings       | Description                                                                 |
| ------------------------------- | --------------------------------------------------------------------------- |
| org_name                        | GitHub organisation name under assessment.                                  |
| public_repos                    | Integer count of public repositories in the organisation.                   |
| total_private_repos             | Integer count of private repositories in the organisation.                  |
| 2fa_requirement_enabled         | (Boolean) - Is two-factor authentication required for organisation members? |
| default_repo_permission         | Default repository permission level for organisation members.               |
| default_branch                  | Default branch naming convention used at organisation level (if set).       |
| total_members                   | Integer count of organisation members.                                      |
| members_without_2fa             | Integer count of members without two-factor authentication enabled.         |
| outside_collaborators           | Integer count of outside collaborators.                                     |
| teams_count                     | Integer count of teams in the organisation.                                 |
| code_scanning_open_alerts       | Integer count of open code scanning alerts across scoped repositories.      |
| credential_scanning_open_alerts | Integer count of open credential/secret scanning alerts.                    |
| repos_checked_for_supply_chain  | Integer count of repositories assessed for supply-chain indicators.         |
| repos_with_sbom                 | Integer count of repositories with detectable SBOM artefacts.               |
| repos_with_branch_protection    | Integer count of repositories with default branch protection enabled.       |
| self_hosted_runners             | Integer count of configured self-hosted GitHub Actions runners.             |
| allowed_actions_policy          | Organisation policy defining which GitHub Actions are allowed.              |
| org_credential_count            | Integer count of organisation-level credentials/secrets detected.           |
| default_workflow_permissions    | Default token permission setting for GitHub Actions workflows.              |
| org_webhooks_count              | Integer count of organisation webhooks configured.                          |
| installed_github_apps           | Count or list of installed GitHub Apps for the organisation.                |
| org_rulesets_count              | Integer count of organisation rulesets configured.                          |

## github_workflow.py

### Posture Report

| Specific Terms / Headings                          | Description                                                                          |
| -------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Total repositories scanned                         | Total number of repositories included in workflow posture analysis.                  |
| Repos using GitHub Actions                         | Number of repositories with GitHub Actions enabled/observed.                         |
| Repos NOT using GitHub Actions                     | Number of repositories without GitHub Actions usage detected.                        |
| Total workflow files found                         | Total number of workflow YAML files discovered across repositories.                  |
| Active repos with workflows                        | Number of non-archived repositories that contain workflow files.                     |
| Active repos without workflows                     | Number of non-archived repositories with no workflow files detected.                 |
| Archived repos with workflows                      | Number of archived repositories that still contain workflow files.                   |
| Archived repos without workflows                   | Number of archived repositories with no workflow files detected.                     |
| Candidates for disabling Actions                   | Derived count of repositories likely suitable for Actions disablement.               |
| TOP REPOSITORIES BY WORKFLOW COUNT                 | Report subsection listing repositories with the highest workflow-file counts.        |
| ARCHIVED REPOS WITH WORKFLOWS (DISABLE CANDIDATES) | Report subsection listing archived repositories with retained workflows.             |
| ACTIVE REPOS: ACTIONS ENABLED BUT NO WORKFLOWS     | Report subsection listing active repositories with Actions enabled but no workflows. |

### Actions Analysis

| Specific Terms / Headings | Description                                                          |
| ------------------------- | -------------------------------------------------------------------- |
| owner                     | Owner/namespace of the referenced action (e.g. `actions`, `github`). |
| actions_referenced        | Full action reference as used in workflows (including version ref).  |
| action_name               | Parsed action name component from the action reference.              |
| times_used                | Integer count of how many times the action is referenced.            |

### Permissions Analysis

| Specific Terms / Headings | Description                                                                  |
| ------------------------- | ---------------------------------------------------------------------------- |
| repo,workflow_path        | Repository name and workflow file path identifying the analysed workflow.    |
| has_explicit_permissions  | (Boolean) - Whether explicit `permissions` are defined in the workflow/job.  |
| permissions_value         | Raw permissions configuration value extracted from the workflow.             |
| has_write_permissions     | (Boolean) - Whether any effective write-level token permissions are present. |
| finding                   | Derived assessment statement for the workflow permissions posture.           |

### Credentials Analysis

| Specific Terms / Headings | Description                                                                      |
| ------------------------- | -------------------------------------------------------------------------------- |
| repo                      | Repository name containing the analysed workflow(s).                             |
| workflow_path             | Path to the workflow file within the repository.                                 |
| has_id_token_write        | (Boolean) - Whether workflow permissions include `id-token: write`.              |
| oidc_actions              | Actions or workflow steps indicating OIDC-based cloud authentication usage.      |
| credential_secrets_found  | Credential-like secrets or long-lived auth signals detected in workflow content. |
| posture                   | Derived credential posture category for the workflow/repository.                 |
| total_workflows           | Integer count of workflows assessed in the scope.                                |
| oidc                      | Integer count of workflows classified as OIDC-auth based.                        |
| long_lived_credentials    | Integer count of workflows classified as long-lived-credential based.            |
| mixed                     | Integer count of workflows containing both OIDC and long-lived patterns.         |
| no_cloud_auth_detected    | Integer count of workflows with no cloud auth signal detected.                   |
| could_not_load            | Integer count of workflows that could not be parsed or loaded.                   |

### Trigger Risk Analysis

| Specific Terms / Headings | Description                                                        |
| ------------------------- | ------------------------------------------------------------------ |
| TBD                       | Placeholder until stable trigger-risk output fields are finalised. |

## alert_metrics.py

| Specific Terms / Headings | Description                                                             |
| ------------------------- | ----------------------------------------------------------------------- |
| id                        | Alert identifier from the source security alert system.                 |
| type                      | Alert type/category (e.g. dependabot, code scanning, secret scanning).  |
| repo                      | Repository name associated with the alert.                              |
| created_at                | Timestamp when the alert was created/opened.                            |
| remediated_at             | Timestamp when the alert was remediated/closed (if applicable).         |
| state                     | Current alert state (e.g. open, fixed, dismissed).                      |
| severity                  | Severity level assigned to the alert.                                   |
| ttr_days                  | Time-to-remediate in days, derived from creation and remediation dates. |

## lfs_script.py

| Specific Terms / Headings | Description                                                             |
| ------------------------- | ----------------------------------------------------------------------- |
| Repository                | Repository name for the analysed Git LFS/blob data.                     |
| Largest Blob Bytes        | Size in bytes of the largest blob detected in the repository.           |
| Largest blob path         | File path of the largest blob detected in the repository.               |
| Exceeds Soft Limit        | (Boolean) - Whether largest blob exceeds the configured soft threshold. |
| Exceeds Hard Limit        | (Boolean) - Whether largest blob exceeds the configured hard threshold. |
| SHA                       | Git SHA hash of the blob object.                                        |
| size_bytes                | Blob size in bytes for the listed blob record.                          |
| path                      | Repository-relative file path for the listed blob record.               |

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
