"""GitHub Actions workflow posture discovery.

Refactored to use core modules:
    - Repo discovery / loading      core.github_api.list_org_repos, core.repo_list
    - HTTP transport                core.github_client.GitHubHttpClient
    - Workflow + repo data          RepoCollector with typed repo-scoped endpoints
    - Script config                 core.config.load_audit_config

Not yet in core (local implementations retained):
    - Workflow YAML uses: parsing
"""

import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

import pandas as pd

from core.collector import RepoCollector
from core.compiler import CsvCompiler
from core.config import AuditConfig, WorkflowAuditConfig
from core.github_api import (
    LatestWorkflowRunEndpoint,
    RepoActionsPermissionsEndpoint,
    RepoDetailsEndpoint,
    WorkflowsEndpoint,
    fetch_repo_file_text,
)
from core.github_client import GitHubHttpClient
from core.models import RepoData
from core.output_paths import OutputPathResolver
from core.presenters import (
    workflow_repo_data_to_detail_rows,
    workflow_repo_data_to_summary_row,
    write_workflow_summary,
)
from core.repo_list import resolve_repo_selection
from core.storage import SqliteRepoStorage
from core.transforms import (
    CredentialPostureTransform,
    TriggerRiskTransform,
    parse_actions_from_content,
    parse_workflow_permissions,
)
from core.validation import direct_invocation_guard

section_break = "\n" + ("=" * 80) + "\n"
sub_section_break = "\n" + ("-" * 80) + "\n"


# --- Workflow file parsing ------------------------------------------------
def fetch_workflow_file_contents(
    client: GitHubHttpClient,
    detail_rows: list[dict[str, Any]],
) -> dict[str, str | None]:
    """
    fetch the text content of all workflow files in the detail_rows list for downstream analysis.
    Returns a dict mapping workflow file paths to their text content (or None if the file could not be fetched).
    """
    contents: dict[str, str | None] = {}
    for i, row in enumerate(detail_rows):
        key = f"{row['repo']}/{row['path']}"
        contents[key] = fetch_repo_file_text(
            client,
            row["owner"],
            row["repo_name"],
            row["path"],
        )
        if (i + 1) % 100 == 0:
            print(f"  Fetched {i + 1} / {len(detail_rows)} workflow files")
            time.sleep(0.1)
    return contents


def analyse_workflow_file_contents(
    detail_rows: list[dict[str, Any]],
    workflow_contents: dict[str, str | None],
    config: WorkflowAuditConfig,
) -> dict[str, list[dict[str, Any]]]:
    """Single-pass through each workflow's file contents, extracting data based on enabled analysis stages"""
    workflow_analysis_results: dict[str, list[dict[str, Any]]] = {
        "actions": [],
        "permissions": [],
        "credentials": [],
        "triggers": [],
    }

    total = len(detail_rows)
    for i, row in enumerate(detail_rows):
        key = f"{row['repo']}/{row['path']}"
        content = workflow_contents.get(key)

        if (i + 1) % 100 == 0:
            print(f"  Analysed {i + 1} / {total} workflow files", file=sys.stderr)
        if content is None:
            print(f"No content for {key}, skipping analysis", file=sys.stderr)
            # Emit explicit could_not_load rows for enabled analyses.
            if config.permissions_analysis:
                workflow_analysis_results["permissions"].append(
                    {
                        "repo": row["repo"],
                        "workflow_path": row["path"],
                        "has_explicit_permissions": False,
                        "permissions_value": "",
                        "has_write_permissions": False,
                        "finding": "could_not_load",
                    }
                )
            if config.credentials_analysis:
                workflow_analysis_results["credentials"].append(
                    {
                        "repo": row["repo"],
                        "workflow_path": row["path"],
                        "has_id_token_write": False,
                        "oidc_actions": "",
                        "credential_secrets_found": "",
                        "posture": "could_not_load",
                    }
                )
            if config.trigger_risk_analysis:
                workflow_analysis_results["triggers"].append(
                    {
                        "repo": row["repo"],
                        "workflow_path": row["path"],
                        "triggers_found": "",
                        "risky_triggers": "",
                        "risk_level": "",
                        "has_pull_request_target": False,
                        "has_issue_comment": False,
                        "has_repository_dispatch": False,
                        "has_workflow_dispatch": False,
                        "posture": "could_not_load",
                    }
                )
            continue

        # Actions Analysis
        if config.actions_analysis:
            workflow_analysis_results["actions"].extend(
                parse_actions_from_content(content, row["repo"], row["path"])
            )
        if config.permissions_analysis:
            parsed_permissions = parse_workflow_permissions(content)
            workflow_analysis_results["permissions"].append(
                {
                    "repo": row["repo"],
                    "workflow_path": row["path"],
                    **parsed_permissions,
                }
            )
        if config.credentials_analysis:
            parsed_cred = CredentialPostureTransform.assess_credential_posture(content)
            workflow_analysis_results["credentials"].append(
                {
                    "repo": row["repo"],
                    "workflow_path": row["path"],
                    **parsed_cred,
                }
            )
        if config.trigger_risk_analysis:
            parsed_trigger = TriggerRiskTransform.assess_trigger_risk(content)
            workflow_analysis_results["triggers"].append(
                {
                    "repo": row["repo"],
                    "workflow_path": row["path"],
                    **parsed_trigger,
                }
            )
    return workflow_analysis_results


# --- Summary report -------------------------------------------------------


def _persist_rows(
    storage: SqliteRepoStorage,
    table_name: str,
    schema: dict[str, str],
    rows: list[dict[str, Any]],
) -> None:
    """Create table if needed and write rows when data is available."""
    storage.create_table(table_name, schema)
    if rows:
        storage.write_rows(table_name, rows)


# --- Stage functions ------------------------------------------------------


def collect_baseline(
    client: GitHubHttpClient,
    repo_list: list[str],
    storage: SqliteRepoStorage,
    resume: bool,
) -> None:
    """Stage 2: Collect baseline repo metadata and workflow inventory."""
    collector = RepoCollector(
        storage=storage,
        client=client,
        endpoints=[
            RepoDetailsEndpoint,
            WorkflowsEndpoint,
        ],
    )
    primary_org = repo_list[0].split("/", 1)[0]
    collector.collect(primary_org, repos=repo_list, resume=resume)


def collect_additional(
    client: GitHubHttpClient,
    repo_list: list[str],
    storage: SqliteRepoStorage,
    resume: bool,
) -> None:
    """Stage 3: Collect remaining workflow posture data."""
    primary_org = repo_list[0].split("/", 1)[0]

    # 3.1 Collect repo-level Actions permissions for all repos
    collector = RepoCollector(
        storage=storage,
        client=client,
        endpoints=[RepoActionsPermissionsEndpoint],
    )
    collector.collect(primary_org, repos=repo_list, resume=resume)

    # 3.2 Collect latest workflow run only for repos that have workflows
    repos_with_workflows: list[str] = []
    for full_name in repo_list:
        data = storage.read(full_name) or RepoData()
        if data.workflows and data.workflows.count > 0:
            repos_with_workflows.append(full_name)
    if repos_with_workflows:
        collector = RepoCollector(
            storage=storage,
            client=client,
            endpoints=[LatestWorkflowRunEndpoint],
        )
        collector.collect(
            primary_org,
            repos=repos_with_workflows,
            resume=resume,
        )


def build_rows(
    repo_list: list[str], storage: SqliteRepoStorage
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Stage 4: Read collected data and build output row sets.

    Always runs — downstream stages need ``detail_rows``. Reads are cheap
    (SQLite only) so there is no gain from toggling this off. if the
    cache is empty ( e.g Stages 2/3 were skipped before any prior run
    populated it), this returns empty rows for the affected repos and
    lets later stages no-op gracefully, rather than crash.
    """
    repo_rows: list[dict[str, Any]] = []
    detail_rows: list[dict[str, Any]] = []
    total = len(repo_list)
    for idx, full_name in enumerate(repo_list, start=1):
        print(f"[{idx}/{total}] Augmenting {full_name}...", file=sys.stderr)
        try:
            data = storage.read(full_name) or RepoData()
        except sqlite3.OperationalError as exc:
            print(
                f" Cache unavailable for {full_name} ({exc}). "
                "Skipping row build - likely Stages 2/3 were disabled "
                "before the cache was populated.",
                file=sys.stderr,
            )
            data = RepoData()
        repo_rows.append(workflow_repo_data_to_summary_row(full_name, data))
        detail_rows.extend(workflow_repo_data_to_detail_rows(full_name, data))
    return repo_rows, detail_rows


def write_posture_reports(
    output_prefix: str,
    repo_rows: list[dict[str, Any]],
    detail_rows: list[dict[str, Any]],
    output_dir: Path,
) -> None:
    """Stage 5: Write repo-level posture reports."""
    prefix = output_prefix
    repo_summary_path = output_dir / f"{prefix}_repo_summary.csv"
    workflow_details_path = output_dir / f"{prefix}_workflow_details.csv"
    summary_text_report_path = output_dir / f"{prefix}_summary.txt"

    repo_count = CsvCompiler.write_rows(str(repo_summary_path), repo_rows)
    details_count = CsvCompiler.write_rows(str(workflow_details_path), detail_rows)
    print(f"Wrote {repo_summary_path} ({repo_count} rows)")
    print(f"Wrote {workflow_details_path} ({details_count} rows)")
    write_workflow_summary(str(summary_text_report_path), repo_rows, detail_rows)

    total = len(repo_rows)
    print(
        f"\nDone. Scanned {total} repos, "
        f"found {sum(1 for r in repo_rows if r.get('has_workflows'))} using GitHub Actions "
        f"with {len(detail_rows)} total workflow files.",
        file=sys.stderr,
    )


def actions_analysis(
    all_actions: list[dict[str, Any]],
    output_dir: Path,
    storage: SqliteRepoStorage,
) -> None:
    """Stage 6: Write action usage + SHA pinning outputs from analysed rows."""
    # 6. Analyse most common GitHub Actions used
    print("\n--- Analysing actions used across workflows ---")

    # Organise Output Paths
    actions_analysis_path_base = output_dir / "actions_analysis"
    actions_analysis_path_base.mkdir(parents=True, exist_ok=True)
    # Actions Usage and Ownership
    action_usage_detail_path = (
        actions_analysis_path_base / "github_actions_usage_detail.csv"
    )
    action_usage_summary_path = (
        actions_analysis_path_base / "github_actions_usage_summary.csv"
    )
    action_owner_summary_path = (
        actions_analysis_path_base / "github_actions_owner_summary.csv"
    )
    action_pinning_path = (
        actions_analysis_path_base / "github_actions_pinning_per_repo.csv"
    )
    action_unpinned_detail_path = (
        actions_analysis_path_base / "github_actions_unpinned_detail.csv"
    )

    print(f"Total action references found: {len(all_actions)}")

    # Usage Detail to SQLite
    usage_detail_schema = {
        "repo": "TEXT",
        "workflow_path": "TEXT",
        "action_name": "TEXT",
        "version": "TEXT",
        "owner": "TEXT",
        "is_pinned": "INTEGER",
        "pin_type": "TEXT",
    }
    _persist_rows(
        storage,
        "github_actions_usage_detail",
        usage_detail_schema,
        all_actions,
    )

    usage_detail_count = CsvCompiler.write_rows(
        str(action_usage_detail_path),
        all_actions,
    )
    print(f"Wrote {action_usage_detail_path} ({usage_detail_count} rows)")

    # If nothing was parsed, write empty CSVs with the right headers and bail.
    if not all_actions:
        empty_usage = pd.DataFrame(columns=["action_name", "times_used"])
        empty_owner = pd.DataFrame(columns=["owner", "actions_referenced"])
        empty_pinning = pd.DataFrame(
            columns=[
                "repo",
                "total_refs",
                "pinned",
                "unpinned",
                "compliance_pct",
            ]
        )
        CsvCompiler.write_dataframe(action_usage_summary_path, empty_usage)
        CsvCompiler.write_dataframe(action_owner_summary_path, empty_owner)
        CsvCompiler.write_dataframe(action_pinning_path, empty_pinning)
        print(f"Wrote {action_usage_summary_path} (0 rows)")
        print(f"Wrote {action_owner_summary_path} (0 rows)")
        print(f"Wrote {action_pinning_path} (0 rows)")
        print("Unique actions: 0")
        print("Unique owners: 0")
        print("\n--- Analysing SHA pinning compliance ---")
        print("Total action references: 0")
        print("Pinned to SHA: 0")
        print("Unpinned (mutable tag): 0")
        print(f"Wrote {action_unpinned_detail_path} (0 rows)")
        print("Repos with unpinned actions: 0")
        print("Repos fully pinned: 0")
        return

    # Build the master DataFrame once and reuse for every aggregation.
    df = pd.DataFrame(all_actions)

    # Action usage summary: count references per action_name, sort descending.
    usage_summary_df = (
        df.groupby("action_name", sort=False)
        .size()
        .reset_index(name="times_used")
        .sort_values(by="times_used", ascending=False, kind="stable")
        .reset_index(drop=True)
    )

    usage_summary_df_schema = {col: "TEXT" for col in usage_summary_df.columns}
    _persist_rows(
        storage,
        "github_actions_usage_summary",
        usage_summary_df_schema,
        usage_summary_df.to_dict("records"),
    )

    CsvCompiler.write_dataframe(action_usage_summary_path, usage_summary_df)
    print(f"Wrote {action_usage_summary_path} ({len(usage_summary_df)} rows)")

    # Owner summary: count references per owner, sort descending.
    owner_summary_df = (
        df.groupby("owner", sort=False)
        .size()
        .reset_index(name="actions_referenced")
        .sort_values(by="actions_referenced", ascending=False, kind="stable")
        .reset_index(drop=True)
    )

    # Owner Summary to SQLite
    owner_summary_df_schema = {col: "TEXT" for col in owner_summary_df.columns}
    _persist_rows(
        storage,
        "github_actions_owner_summary",
        owner_summary_df_schema,
        owner_summary_df.to_dict("records"),
    )

    CsvCompiler.write_dataframe(action_owner_summary_path, owner_summary_df)
    print(f"Wrote {action_owner_summary_path} ({len(owner_summary_df)} rows)")

    print(f"Unique actions: {len(usage_summary_df)}")
    print(f"Unique owners: {len(owner_summary_df)}")

    # 6b. SHA pinning compliance
    print("\n--- Analysing SHA pinning compliance ---")

    # Unpinned detail: rows that have a version but aren't pinned to a SHA.
    versioned = df[df["version"] != "none"]
    unpinned_df = versioned[~versioned["is_pinned"]]
    pinned_df = df[df["is_pinned"]]

    print(f"Total action references: {len(df)}")
    print(f"Pinned to SHA: {len(pinned_df)}")
    print(f"Unpinned (mutable tag): {len(unpinned_df)}")

    unpinned_count = CsvCompiler.write_rows(
        str(action_unpinned_detail_path),
        unpinned_df.to_dict("records"),
    )
    print(f"Wrote {action_unpinned_detail_path} ({unpinned_count} rows)")

    # Per-repo pinning compliance: total / pinned / unpinned / pct, sorted by
    # most unpinned first.
    if versioned.empty:
        pinning_df = pd.DataFrame(
            columns=[
                "repo",
                "total_refs",
                "pinned",
                "unpinned",
                "compliance_pct",
            ]
        )
    else:
        pinning_df = (
            versioned.groupby("repo", sort=False)
            .agg(
                total_refs=("is_pinned", "size"),
                pinned=("is_pinned", "sum"),
            )
            .reset_index()
        )
        pinning_df["unpinned"] = pinning_df["total_refs"] - pinning_df["pinned"]
        pinning_df["compliance_pct"] = (
            (pinning_df["pinned"] / pinning_df["total_refs"].clip(lower=1)) * 100
        ).round(1)
        pinning_df = pinning_df[
            ["repo", "total_refs", "pinned", "unpinned", "compliance_pct"]
        ]
        pinning_df = pinning_df.sort_values(
            by="unpinned", ascending=False, kind="stable"
        ).reset_index(drop=True)

    # Per-repo pinning compliance to SQLite
    pinning_df_schema = {col: "TEXT" for col in pinning_df.columns}
    _persist_rows(
        storage,
        "github_actions_pinning_per_repo",
        pinning_df_schema,
        pinning_df.to_dict("records"),
    )
    CsvCompiler.write_dataframe(action_pinning_path, pinning_df)
    print(f"Wrote {action_pinning_path} ({len(pinning_df)} rows)")
    print(
        f"Repos with unpinned actions: "
        f"{int((pinning_df['unpinned'] > 0).sum()) if not pinning_df.empty else 0}"
    )
    print(
        f"Repos fully pinned: "
        f"{int((pinning_df['unpinned'] == 0).sum()) if not pinning_df.empty else 0}"
    )


def permissions_analysis(
    all_permissions: list[dict[str, Any]],
    output_dir: Path,
    storage: SqliteRepoStorage,
) -> None:
    """Stage 7: Write workflow permissions posture outputs."""
    print("\n--- Analysing workflow permissions ---")
    permissions_analysis_path_base = output_dir / "permissions_analysis"
    permissions_analysis_path_base.mkdir(parents=True, exist_ok=True)

    permissions_schema = {
        "repo": "TEXT",
        "workflow_path": "TEXT",
        "has_explicit_permissions": "BOOLEAN",
        "permissions_value": "TEXT",
        "has_write_permissions": "BOOLEAN",
        "finding": "TEXT",
    }
    _persist_rows(storage, "permissions", permissions_schema, all_permissions)

    permissions_analysis_path = (
        permissions_analysis_path_base / "github_workflow_permissions.csv"
    )
    perms_count = CsvCompiler.write_rows(
        str(permissions_analysis_path),
        all_permissions,
    )
    print(f"Wrote {permissions_analysis_path} ({perms_count} rows)")

    # Tally findings via pandas value_counts for clarity.
    if all_permissions:
        finding_counts = pd.DataFrame(all_permissions)["finding"].value_counts()
    else:
        finding_counts = pd.Series(dtype=int)

    no_block = int(finding_counts.get("no_permissions_block", 0))
    write_all = int(finding_counts.get("write-all", 0))
    has_write_count = int(finding_counts.get("has_write_scope", 0))
    compliant_count = int(finding_counts.get("compliant", 0))
    skipped = int(finding_counts.get("could_not_load", 0))

    print(f"No permissions block: {no_block}")
    print(f"permissions: write-all: {write_all}")
    print(f"Has write scope: {has_write_count}")
    print(f"Compliant (read-only): {compliant_count}")
    print(f"Could not load: {skipped}")


def credentials_analysis(
    all_credential_findings: list[dict[str, Any]],
    output_dir: Path,
    storage: SqliteRepoStorage,
) -> None:
    """Stage 8: Write OIDC vs long-lived credentials outputs."""
    print("\n--- Assessing OIDC vs long-lived credentials ---")

    credentials_schema = {
        "repo": "TEXT",
        "workflow_path": "TEXT",
        "has_id_token_write": "INTEGER",
        "oidc_actions": "TEXT",
        "credential_secrets_found": "TEXT",
        "posture": "TEXT",
    }
    _persist_rows(
        storage,
        "credentials",
        credentials_schema,
        all_credential_findings,
    )

    credentials_analysis_path_base = output_dir / "credentials_analysis"
    credentials_analysis_path_base.mkdir(parents=True, exist_ok=True)
    credentials_analysis_path = (
        credentials_analysis_path_base / "github_workflow_credential_posture.csv"
    )

    cred_count = CsvCompiler.write_rows(
        str(credentials_analysis_path),
        all_credential_findings,
    )
    print(f"Wrote {credentials_analysis_path} ({cred_count} rows)")

    repo_cred_summary: dict[str, dict[str, int]] = {}
    for f in all_credential_findings:
        repo = f["repo"]
        if repo not in repo_cred_summary:
            repo_cred_summary[repo] = {
                "oidc": 0,
                "long_lived_credentials": 0,
                "mixed": 0,
                "no_cloud_auth_detected": 0,
                "could_not_load": 0,
                "total_workflows": 0,
            }
        repo_cred_summary[repo]["total_workflows"] += 1
        repo_cred_summary[repo][f["posture"]] += 1

    cred_repo_rows = [
        {
            "repo": repo,
            "total_workflows": counts["total_workflows"],
            "oidc": counts["oidc"],
            "long_lived_credentials": counts["long_lived_credentials"],
            "mixed": counts["mixed"],
            "no_cloud_auth_detected": counts["no_cloud_auth_detected"],
            "could_not_load": counts["could_not_load"],
        }
        for repo, counts in sorted(
            repo_cred_summary.items(),
            key=lambda x: x[1]["long_lived_credentials"],
            reverse=True,
        )
    ]

    cred_repo_analysis_path = (
        credentials_analysis_path_base
        / "github_workflow_credential_posture_per_repo.csv"
    )
    cred_repo_count = CsvCompiler.write_rows(
        str(cred_repo_analysis_path),
        cred_repo_rows,
    )
    print(f"Wrote {cred_repo_analysis_path} ({cred_repo_count} rows)")

    cred_per_repo_schema = {
        "repo": "TEXT",
        "total_workflows": "INTEGER",
        "oidc": "INTEGER",
        "long_lived_credentials": "INTEGER",
        "mixed": "INTEGER",
        "no_cloud_auth_detected": "INTEGER",
        "could_not_load": "INTEGER",
    }
    _persist_rows(
        storage,
        "credentials_per_repo",
        cred_per_repo_schema,
        cred_repo_rows,
    )

    oidc_only = sum(1 for f in all_credential_findings if f["posture"] == "oidc")
    long_lived = sum(
        1 for f in all_credential_findings if f["posture"] == "long_lived_credentials"
    )
    mixed = sum(1 for f in all_credential_findings if f["posture"] == "mixed")
    no_cloud = sum(
        1 for f in all_credential_findings if f["posture"] == "no_cloud_auth_detected"
    )
    skipped = sum(
        1 for f in all_credential_findings if f["posture"] == "could_not_load"
    )

    print(f"OIDC only: {oidc_only}")
    print(f"Long-lived credentials only: {long_lived}")
    print(f"Mixed (both): {mixed}")
    print(f"No cloud auth detected: {no_cloud}")
    print(f"Could not load: {skipped}")


def trigger_risk_analysis(
    all_trigger_findings: list[dict[str, Any]],
    output_dir: Path,
    storage: SqliteRepoStorage,
) -> None:
    """Stage 9: Write workflow trigger risk outputs."""
    print("\n--- Analysing workflow trigger risk ---")

    trigger_schema = {
        "repo": "TEXT",
        "workflow_path": "TEXT",
        "triggers_found": "TEXT",
        "risky_triggers": "TEXT",
        "risk_level": "TEXT",
        "has_pull_request_target": "INTEGER",
        "has_issue_comment": "INTEGER",
        "has_repository_dispatch": "INTEGER",
        "has_workflow_dispatch": "INTEGER",
        "posture": "TEXT",
    }
    _persist_rows(storage, "triggers", trigger_schema, all_trigger_findings)

    trigger_analysis_path = output_dir / "trigger_analysis"
    trigger_analysis_path.mkdir(parents=True, exist_ok=True)

    trigger_csv_path = trigger_analysis_path / "github_workflow_trigger_risk.csv"
    trigger_count = CsvCompiler.write_rows(
        str(trigger_csv_path),
        all_trigger_findings,
    )
    print(f"Wrote {trigger_csv_path} ({trigger_count} rows)")

    repo_trigger_summary: dict[str, dict[str, int]] = {}
    for f in all_trigger_findings:
        repo = f["repo"]
        if repo not in repo_trigger_summary:
            repo_trigger_summary[repo] = {
                "total_workflows": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "no_risk": 0,
                "could_not_load": 0,
            }
        repo_trigger_summary[repo]["total_workflows"] += 1
        if f["posture"] == "could_not_load":
            repo_trigger_summary[repo]["could_not_load"] += 1
        elif f["risk_level"] == "high":
            repo_trigger_summary[repo]["high_risk"] += 1
        elif f["risk_level"] == "medium":
            repo_trigger_summary[repo]["medium_risk"] += 1
        elif f["risk_level"] == "low":
            repo_trigger_summary[repo]["low_risk"] += 1
        else:
            repo_trigger_summary[repo]["no_risk"] += 1

    trigger_repo_rows = [
        {
            "repo": repo,
            "total_workflows": counts["total_workflows"],
            "high_risk": counts["high_risk"],
            "medium_risk": counts["medium_risk"],
            "low_risk": counts["low_risk"],
            "no_risk": counts["no_risk"],
            "could_not_load": counts["could_not_load"],
        }
        for repo, counts in sorted(
            repo_trigger_summary.items(),
            key=lambda x: x[1]["high_risk"],
            reverse=True,
        )
    ]

    trigger_repo_analysis_path = os.path.join(
        trigger_analysis_path, "github_workflow_trigger_risk_per_repo.csv"
    )
    trigger_summary_count = CsvCompiler.write_rows(
        trigger_repo_analysis_path,
        trigger_repo_rows,
    )
    print(f"Wrote {trigger_repo_analysis_path} ({trigger_summary_count} rows)")

    trigger_per_repo_schema = {
        "repo": "TEXT",
        "total_workflows": "INTEGER",
        "high_risk": "INTEGER",
        "medium_risk": "INTEGER",
        "low_risk": "INTEGER",
        "no_risk": "INTEGER",
        "could_not_load": "INTEGER",
    }
    _persist_rows(
        storage,
        "triggers_per_repo",
        trigger_per_repo_schema,
        trigger_repo_rows,
    )

    high_count = sum(1 for f in all_trigger_findings if f["risk_level"] == "high")
    medium_count = sum(1 for f in all_trigger_findings if f["risk_level"] == "medium")
    low_count = sum(1 for f in all_trigger_findings if f["risk_level"] == "low")
    no_risk_count = sum(1 for f in all_trigger_findings if f["risk_level"] == "none")
    could_not_load_count = sum(
        1 for f in all_trigger_findings if f["posture"] == "could_not_load"
    )

    print(f"High risk: {high_count}")
    print(f"Medium risk: {medium_count}")
    print(f"Low risk: {low_count}")
    print(f"No risk: {no_risk_count}")
    print(f"Could not load: {could_not_load_count}")


# --- Main orchestrator ----------------------------------------------------


def _skip(stage_label: str, toggle_name: str) -> None:
    print(
        f"Skipping {stage_label}: {toggle_name} disabled in config",
        file=sys.stderr,
    )


def run(
    config: AuditConfig,
    auth: str | None,
    base_output_dir: str,
    base_internal_dir: str,
    **kwargs,
) -> None:
    resolver = OutputPathResolver(config, base_output_dir, base_internal_dir)
    workflow_config = config.workflow_audit
    output_dir = resolver.script_output_dir(workflow_config.output_subdir)
    db_path = resolver.database_path(workflow_config.database_path)

    org = config.github_organization
    repo_limit = config.repo_limit
    repo_file = (
        config.default_repo_list
        if kwargs.get("repo_file") is None
        else kwargs.get("repo_file")
    )
    repo_search_scope = config.repo_search_scope
    out_prefix = workflow_config.output_prefix
    resume = workflow_config.use_cache
    repos = kwargs.get("repos", None)

    # GitHub Workflow Config Debug
    print(section_break, file=sys.stderr)
    print("github_workflow to be executed with the following config:", file=sys.stderr)

    print(section_break, file=sys.stderr)

    print(f"Database Path: {db_path}", file=sys.stderr)
    print(f"Repo Search Scope: {repo_search_scope}", file=sys.stderr)
    print(f"Repo Limit: {config.repo_limit}", file=sys.stderr)
    if repo_search_scope == "file":
        print(f"Repo File: {repo_file}", file=sys.stderr)
    print(f"Use_Cache: {resume}", file=sys.stderr)
    print(f"Output Dir: {output_dir}", file=sys.stderr)
    print(f"Output Prefix: {out_prefix}", file=sys.stderr)
    print(section_break, file=sys.stderr)

    client = GitHubHttpClient(auth_method=auth)

    # Stage 1 - resolve_repo_list. (mandatory)
    try:
        repo_list = resolve_repo_selection(
            config,
            auth,
            repos=kwargs.get("repos", None),
            repo_file=kwargs.get("repo_file", None),
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"Error resolving repo selection: {e}", file=sys.stderr)
        sys.exit(2)
    if not repo_list:
        print(
            "No repositories found in repo file (after applying any limit).",
            file=sys.stderr,
        )
        return

    storage = SqliteRepoStorage(str(db_path))

    # Stage 2 - collect_baseline
    if workflow_config.collect_baseline_data:
        collect_baseline(client, repo_list, storage, resume)
    else:
        _skip("Stage 2", "collect_baseline_data")

    # Stage 3 - collect_additional
    if workflow_config.collect_additional_data:
        collect_additional(client, repo_list, storage, resume)
    else:
        _skip("Stage 3", "collect_additional_data")

    # Stage 4 - always runs; reads from SQLite and produces detail_rows
    # that later stages depend on. Cheap enough that a toggle adds no value.
    repo_rows, detail_rows = build_rows(repo_list, storage)

    # Stage 4b - Fetch workflow file contents for downstream analysis
    workflow_contents: dict[str, str | None] = {}
    # If any of actions_analysis, permissions_analysis, credentials_analysis, or trigger_risk_analysis is enabled, fetch the workflow file contents for downstream analysis.
    workflow_analysis_results: dict[str, list[dict[str, Any]]] = {
        "actions": [],
        "permissions": [],
        "credentials": [],
        "triggers": [],
    }

    if any(
        [
            workflow_config.actions_analysis,
            workflow_config.permissions_analysis,
            workflow_config.credentials_analysis,
            workflow_config.trigger_risk_analysis,
        ]
    ):
        print(
            "\n--- Fetching workflow file contents for downstream analysis ---",
            file=sys.stderr,
        )
        workflow_contents = fetch_workflow_file_contents(client, detail_rows)
        workflow_analysis_results = analyse_workflow_file_contents(
            detail_rows,
            workflow_contents,
            workflow_config,
        )
    else:
        print(
            "\n--- Skipping workflow file content fetch (no downstream analysis enabled) ---",
            file=sys.stderr,
        )

    # Stage 5 - write_posture_reports
    if workflow_config.gen_posture_reports:
        write_posture_reports(out_prefix, repo_rows, detail_rows, output_dir)
    else:
        _skip("Stage 5", "gen_posture_reports")

    if workflow_config.actions_analysis:
        actions_analysis(workflow_analysis_results["actions"], output_dir, storage)

    # Stage 7 - permissions_analysis
    if workflow_config.permissions_analysis:
        permissions_analysis(
            workflow_analysis_results["permissions"], output_dir, storage
        )

    # Stage 8 - credentials_analysis
    if workflow_config.credentials_analysis:
        credentials_analysis(
            workflow_analysis_results["credentials"], output_dir, storage
        )

    # Stage 9 - trigger_risk_analysis
    if workflow_config.trigger_risk_analysis:
        trigger_risk_analysis(
            workflow_analysis_results["triggers"], output_dir, storage
        )

    print("--- Complete ---")


if __name__ == "__main__":
    direct_invocation_guard(__file__)
