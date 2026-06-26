# Repository List Maintenance

## Overview

As of 26/06/2026, many of the scripts in the audit-cli rely on the `repo_list.yaml` at the root of the repo to act as the single source of truth.
However, this list may become inaccurate over time, repos may be deleted, some may become more active or inactive, etc.
In this case, the repo_list may need refreshing. This can be achieved by using the utility script `repo_list_maintenance.py` under `utils/`.

## Usage

`repo_list_maintenance.py` can be triggered with the following arguments, defaults are noted:

1. `--org`: GitHub Organisation to focus on - defaults to `ministryofjustice`
2. `--repo-file`: Path to the repo list file to be updated - defaults to `repo_list.yaml` at the root of the repo
3. `--target-count`: Integer count of the final number of repos that the YAML file should be populated with
4. `--mode`: Action mode for script - option of `supplement` (add repos with no checks), `validate` (check repos present), or `both` - defaults to `both`.
5. `--fail-on-validation`: (Optional) - will exit with code 1 if validation fails
6. `--missing-report`: Optional path to write a report on missing repos found within the YAML file.
7. `--prune-missing`: Remove wrong-org and missing repos no longer found within the existing repo file.
8. `--auth`: Authentication method for GitHub API, options are `pat`, `app`, or `cli`. Authentication details are noted in [setup.md](setup.md)

## Creating a New Repo List

A new repository YAML list can be created via the following steps:

1. Create the YAML file in the desired location e.g. `my_repo_list.yaml` , `config/my_repo_list.yaml` and add `repos:` at the top as shown below:

    ```yaml
    repos:
    ```

2. Run `repo_list_maintenance.py`, specifying the desired arguments:

    ```shell
    uv run python utils/repo_list_maintenance.py --repo-file my_repo_list.yaml
    ```

3. Verify the repo list created, and update `config/audit_config.yaml` to reference it as required.

## Updating an Existing List

In the event some adhoc updates are needed e.g. a repo is being sunset and references need to be removed, follow the steps outlined below:

1. In the existing repo list YAML file, remove any desired repositories e.g. `repo-d`, `repo-e`:

    ```yaml
    repos:
    - myorg/repo-a
    - myorg/repo-b
    - myorg/repo-c
    - myorg/repo-d
    - myorg/repo-e
    ```

2. Verify the intended outcomes e.g. if the total count was 5, is 5 still the target, or should more be added?
3. Run `repo_list_maintenance.py`, specifying the desired arguments:

    ```shell
    uv run python utils/repo_list_maintenance.py --repo-file my_repo_list.yaml
    ```

4. Verify the repo list created, and update `config/audit_config.yaml` to reference it as required.

## Development Opportunities

- Currently, `repo_list_maintenance.py` does expect the file specified in the `--repo-file` argument to be present
  - The script could be updated to create the file if not present with the expected structure.
- There is no option to fully overwrite/refresh the list at present
  - for example, if a top 400 list is requiring a refresh, running the script will only supplement if the target is not present.
  - This could only be achieved by deleting all entries under `repos:` in the given file.
- If a YAML/database is to be the primary reference point for the audit scripts:
  - A scheduled job could be considered via GitHub Actions to update the repo's list on a regular basis.
