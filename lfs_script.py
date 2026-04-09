"""
Script to analyze GitHub repositories for large file storage (LFS) issues.
It collects repository data, checks blob sizes against predefined thresholds,
and generates summary reports in CSV format.
"""

import os
import sys
from pathlib import Path

import pandas as pd

from core.models import FieldDefinition, FieldsConfig, FieldType
from core.collector import RepoCollector
from core.github_api import GetRepoTreeEndpoint, RepoDetailsEndpoint
from core.repo_list import load_repo_list_file
from core.storage import SqliteRepoStorage
from core.compiler import ExcelCompiler
from core.transforms import RepoTreeTransform

# GitHub thresholds (bytes)
SOFT_LIMIT = 50 * 1024 * 1024
HARD_LIMIT = 100 * 1024 * 1024

# File paths for input and output
YAML_FILE = Path("repo_list.yaml")
DB_FILE = Path("repo_list.db")
OUTPUT_DIR = Path("repo_summaries")
MASTER_CSV = Path("repos_exceeding_thresholds.xlsx")

OUTPUT_DIR.mkdir(exist_ok=True)


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
    print("<LFS Analysis> Starting LFS analysis script", file=sys.stderr)

    # Ensure the repo list file exists
    if not YAML_FILE.exists():
        print(
            f"<LFS Analysis> ERROR: Missing repo list file: {YAML_FILE}",
            file=sys.stderr,
        )
        raise FileNotFoundError(f"Missing repo list file: {YAML_FILE}")

    # Load the list of repositories from the YAML file
    print("<LFS Analysis> Loading repository list from YAML file", file=sys.stderr)
    repos = load_repo_list_file(YAML_FILE)
    print(f"<LFS Analysis> Loaded {len(repos)} repositories", file=sys.stderr)

    # Set up storage and collector for fetching repo data
    print("<LFS Analysis> Setting up storage and collector", file=sys.stderr)
    storage = SqliteRepoStorage(DB_FILE)
    collector = RepoCollector(
        storage=storage,
        endpoints=[RepoDetailsEndpoint, GetRepoTreeEndpoint],
    )

    # Collect data for the primary organization and specified repos, resuming if interrupted
    primary_org = repos[0].split("/", 1)[0]
    print(
        f"<LFS Analysis> Collecting data for organization: {primary_org}",
        file=sys.stderr,
    )
    collector.collect(primary_org, repos=repos, resume=True)
    print("<LFS Analysis> Data collection completed", file=sys.stderr)

    # Compile the master Excel file with repos exceeding thresholds
    print("<LFS Analysis> Compiling master Excel summary", file=sys.stderr)
    ExcelCompiler().compile(
        storage=storage,
        config=master_csv_config,
        output_path=MASTER_CSV,
        transforms=[RepoTreeTransform()],
    )
    print(f"<LFS Analysis> Master summary saved to {MASTER_CSV}", file=sys.stderr)

    # Ensure output directory exists
    if not os.path.isdir(OUTPUT_DIR):
        print(
            f"<LFS Analysis> Creating output directory: {OUTPUT_DIR}", file=sys.stderr
        )
        os.makedirs(OUTPUT_DIR)

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
        output_file = OUTPUT_DIR / f"{full_repo_name.replace('/', '_')}_summary.csv"
        pd.DataFrame(blob_rows).to_csv(output_file, index=False)
        print(
            f"<LFS Analysis> Saved summary for {full_repo_name} to {output_file}",
            file=sys.stderr,
        )

    print("<LFS Analysis> LFS analysis script completed successfully", file=sys.stderr)


if __name__ == "__main__":
    # Run the main function when the script is executed directly
    main()
