"""
Script to analyze GitHub repositories for large file storage (LFS) issues.
It collects repository data, checks blob sizes against predefined thresholds,
and generates summary reports in CSV format.
"""

import os
import sys

import pandas as pd

from core.config import AuditConfig
from core.models import FieldDefinition, FieldsConfig, FieldType
from core.collector import RepoCollector
from core.github_api import GetRepoTreeEndpoint, RepoDetailsEndpoint
from core.output_paths import OutputPathResolver
from core.repo_list import load_repo_list_file
from core.storage import SqliteRepoStorage
from core.compiler import ExcelCompiler
from core.transforms import RepoTreeTransform


section_break = "\n" + ("=" * 80) + "\n"
sub_section_break = "\n" + ("-" * 80) + "\n"

# Configuration for the master report file that summarizes repos exceeding thresholds
master_report_config = FieldsConfig(
    fields=[
        FieldDefinition(
            source="repo_details.full_name",
            column="Repository",
            type=FieldType.string,
        ),
        FieldDefinition(
            source="repo_tree_transform.largest_blob_bytes",
            column="Largest Blob Bytes",
            type=FieldType.integer,
            default=0,
        ),
        FieldDefinition(
            source="repo_tree_transform.largest_blob_path",
            column="Largest blob path",
            type=FieldType.string,
            default="",
        ),
        FieldDefinition(
            source="repo_tree_transform.exceeds_soft_limit",
            column="Exceeds soft limit",
            type=FieldType.boolean,
            default=False,
        ),
        FieldDefinition(
            source="repo_tree_transform.exceeds_hard_limit",
            column="Exceeds hard limit",
            type=FieldType.boolean,
            default=False,
        ),
    ]
)


def run(
    config: AuditConfig,
    auth: str | None,
    base_output_dir: str,
    base_internal_dir: str,
    **kwargs,
):
    """
    Main function to orchestrate the LFS analysis process.
    Loads repository list, collects data from GitHub, generates master summary,
    and creates individual CSV summaries for each repository.
    """
    resolver = OutputPathResolver(config, base_output_dir, base_internal_dir)
    lfs_script_config = config.lfs_script

    # Define file paths from config
    database_path = resolver.database_path(lfs_script_config.database_path)
    github_organization = config.github_organization
    output_filename = lfs_script_config.output_filename
    output_file_path = resolver.script_output_file(
        lfs_script_config.output_subdir, output_filename
    )
    repo_summaries_dir = (
        resolver.script_output_dir(lfs_script_config.output_subdir) / "repo_summaries"
    )
    repo_summaries_dir.mkdir(exist_ok=True)
    repo_list_file = config.repo_list_file
    resume = (
        lfs_script_config.use_cache
    )  # Using 'use_cache' to determine if we should resume from existing data

    soft_limit_mb = int(lfs_script_config.soft_limit_mb)
    hard_limit_mb = int(lfs_script_config.hard_limit_mb)

    # Variable Debug

    print(section_break, file=sys.stderr)
    print(
        "LFS analysis to be executed with the following config values:", file=sys.stderr
    )
    print(section_break, file=sys.stderr)

    print(f"Database Path: {database_path}", file=sys.stderr)
    print(f"GitHub Organization: {github_organization}", file=sys.stderr)
    print(f"Output File Path: {output_file_path}", file=sys.stderr)
    print(f"Repo file: {repo_list_file}", file=sys.stderr)
    print(f"Soft limit (MB): {soft_limit_mb}", file=sys.stderr)
    print(f"Hard limit (MB): {hard_limit_mb}", file=sys.stderr)
    print(f"Resume from cache: {resume}", file=sys.stderr)
    print(sub_section_break, file=sys.stderr)

    # Ensure the repo list file exists
    if kwargs.get("repos"):
        repos = kwargs["repos"]
    else:
        if not os.path.exists(repo_list_file):
            print(
                f"<LFS Analysis> ERROR: Missing repo list file: {repo_list_file}",
                file=sys.stderr,
            )
            raise FileNotFoundError(f"Missing repo list file: {repo_list_file}")
        print("<LFS Analysis> Loading repository list from YAML file", file=sys.stderr)
        repos = load_repo_list_file(repo_list_file)
        print(f"<LFS Analysis> Loaded {len(repos)} repositories", file=sys.stderr)

    # Set up storage and collector for fetching repo data
    print("<LFS Analysis> Setting up storage and collector", file=sys.stderr)
    storage = SqliteRepoStorage(str(database_path))
    collector = RepoCollector(
        storage=storage,
        endpoints=[RepoDetailsEndpoint, GetRepoTreeEndpoint],
        auth_method=auth,
    )

    # Collect data for the primary organization and specified repos, resuming if interrupted
    print(
        f"<LFS Analysis> Collecting data for organization: {github_organization}",
        file=sys.stderr,
    )
    collector.collect(github_organization, repos=repos, resume=resume)
    print("<LFS Analysis> Data collection completed", file=sys.stderr)

    # Compile the master Excel file with repos exceeding thresholds
    print("<LFS Analysis> Compiling master Excel summary", file=sys.stderr)
    ExcelCompiler().compile(
        storage=storage,
        config=master_report_config,
        output_path=output_file_path,
        transforms=[
            RepoTreeTransform(
                soft_limit_mb=soft_limit_mb,
                hard_limit_mb=hard_limit_mb,
            )
        ],
    )
    print(f"<LFS Analysis> Master summary saved to {output_file_path}", file=sys.stderr)

    # Ensure output directory exists
    if not repo_summaries_dir.is_dir():
        print(
            f"<LFS Analysis> Creating output directory: {repo_summaries_dir}",
            file=sys.stderr,
        )
        repo_summaries_dir.mkdir(parents=True, exist_ok=True)

    # Generate individual CSV summaries for each repository
    print("<LFS Analysis> Generating individual CSV summaries", file=sys.stderr)
    for full_repo_name in repos:
        print(
            f"<LFS Analysis> Processing repository: {full_repo_name}", file=sys.stderr
        )
        # Retrieve stored data for the repo
        data = storage.read(full_repo_name)
        if not data:
            print(
                f"<LFS Analysis> ERROR: Expected data for {full_repo_name} in storage",
                file=sys.stderr,
            )
            raise RuntimeError(f"Expected data for {full_repo_name} in storage")

        # Extract blob information from the repo tree
        tree = data.repo_tree.tree if data.repo_tree else []
        blob_rows = [
            {
                "sha": item.sha,
                "size_bytes": item.size,
                "path": item.path,
            }
            for item in tree
            if item.type == "blob" and isinstance(item.size, int)
        ]

        # Save the blob data to a CSV file
        output_file = (
            repo_summaries_dir / f"{full_repo_name.replace('/', '_')}_summary.csv"
        )
        pd.DataFrame(blob_rows).to_csv(output_file, index=False)
        print(
            f"<LFS Analysis> Saved summary for {full_repo_name} to {output_file}",
            file=sys.stderr,
        )

    print("<LFS Analysis> LFS analysis script completed successfully", file=sys.stderr)
