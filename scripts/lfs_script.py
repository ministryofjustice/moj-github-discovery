"""
Script to analyze GitHub repositories for large file storage (LFS) issues.
It collects repository data, checks blob sizes against predefined thresholds,
and generates summary reports in CSV format.
"""

import argparse
import atexit
import os
import sys
import time

# add project root to path for core imports
# TODO: Remove once pyproject.toml is build-system configured
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd

from core.config import AuditConfig, load_audit_config
from core.models import FieldDefinition, FieldsConfig, FieldType
from core.collector import RepoCollector
from core.github_api import GetRepoTreeEndpoint, RepoDetailsEndpoint
from core.repo_list import load_repo_list_file
from core.storage import SqliteRepoStorage
from core.compiler import ExcelCompiler
from core.transforms import RepoTreeTransform
from core.utils import base_directory_setup

from pathlib import Path

section_break = "\n" + ("=" * 80) + "\n"
sub_section_break = "\n" + ("-" * 80) + "\n"

# Base directory configurations
# TODO: PROJECT_ROOT will be removed as an output of base_directory_setup once all scripts updated to use audit_config.yaml for repo_list loading
BASE_OUTPUT_DIR, BASE_INTERNAL_DIR, PROJECT_ROOT = base_directory_setup()

# Configure Output Directories
OUTPUT_DIR = os.path.join(BASE_OUTPUT_DIR, "lfs_analysis")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# File paths for input and output
REPO_SUMMARIES_DIR = os.path.join(OUTPUT_DIR, "repo_summaries")
MASTER_CSV_PATH = os.path.join(OUTPUT_DIR, "repos_exceeding_thresholds.xlsx")

__start_time: float | None = None


# TODO: Consider moving to core.utils as repeated across scripts or to main.py when shared entrypoint developed
def _report_elapsed() -> None:
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)


atexit.register(_report_elapsed)


def parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments for later use within the LFS analysis script."""
    parser = argparse.ArgumentParser(
        description="Analyze GitHub repositories for large file storage (LFS) issues and generate summary reports."
    )
    parser.add_argument(
        "--config-file",
        type=Path,
        default=None,
        help="Path to the audit configuration YAML file (optional, defaults to config/audit_config.yaml)",
    )
    parser.add_argument(
        "--auth",
        choices=["pat", "app", "cli"],
        default=None,
        help="Select GitHub authentication method explicitly (pat, app, or cli)",
    )
    return parser.parse_args()


# Configuration for the master CSV file that summarizes repos exceeding thresholds
master_csv_config = FieldsConfig(
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


def main():
    """
    Main function to orchestrate the LFS analysis process.
    Loads repository list, collects data from GitHub, generates master summary,
    and creates individual CSV summaries for each repository.
    """
    global __start_time
    __start_time = time.monotonic()

    print("<LFS Analysis> Starting LFS analysis script", file=sys.stderr)

    args = parse_args()

    config: AuditConfig = load_audit_config(args.config_file)

    lfs_script_config = config.lfs_script

    # Define file paths from config
    database_path = lfs_script_config.database_path
    if database_path is not None and not os.path.isabs(database_path):
        database_path = os.path.join(PROJECT_ROOT, database_path)
    github_organization = config.github_organization
    output_filename = lfs_script_config.output_filename
    if output_filename is not None and not os.path.isabs(output_filename):
        output_file_path = os.path.join(OUTPUT_DIR, output_filename)
    repo_list_file = config.repo_list_file
    if repo_list_file is not None and not os.path.isabs(repo_list_file):
        repo_list_file = os.path.join(PROJECT_ROOT, repo_list_file)
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
    if not os.path.exists(repo_list_file):
        print(
            f"<LFS Analysis> ERROR: Missing repo list file: {repo_list_file}",
            file=sys.stderr,
        )
        raise FileNotFoundError(f"Missing repo list file: {repo_list_file}")

    # Load the list of repositories from the YAML file
    print("<LFS Analysis> Loading repository list from YAML file", file=sys.stderr)
    repos = load_repo_list_file(repo_list_file)
    print(f"<LFS Analysis> Loaded {len(repos)} repositories", file=sys.stderr)

    # Set up storage and collector for fetching repo data
    print("<LFS Analysis> Setting up storage and collector", file=sys.stderr)
    storage = SqliteRepoStorage(database_path)
    collector = RepoCollector(
        storage=storage,
        endpoints=[RepoDetailsEndpoint, GetRepoTreeEndpoint],
        auth_method=args.auth,
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
        config=master_csv_config,
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
    if not os.path.isdir(REPO_SUMMARIES_DIR):
        print(
            f"<LFS Analysis> Creating output directory: {REPO_SUMMARIES_DIR}",
            file=sys.stderr,
        )
        os.makedirs(REPO_SUMMARIES_DIR)

    # Generate individual CSV summaries for each repository
    print("<LFS Analysis> Generating individual CSV summaries", file=sys.stderr)
    for full_repo_name in repos:
        # print(
        #     f"<LFS Analysis> Processing repository: {full_repo_name}", file=sys.stderr
        # )
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
        output_file = os.path.join(
            REPO_SUMMARIES_DIR, f"{full_repo_name.replace('/', '_')}_summary.csv"
        )
        pd.DataFrame(blob_rows).to_csv(output_file, index=False)
        # print(
        #     f"<LFS Analysis> Saved summary for {full_repo_name} to {output_file}",
        #     file=sys.stderr,
        # )

    print("<LFS Analysis> LFS analysis script completed successfully", file=sys.stderr)


if __name__ == "__main__":
    # Run the main function when the script is executed directly
    main()
