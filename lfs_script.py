import os
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

YAML_FILE = Path("repo_list.yaml")
DB_FILE = Path("repo_list.db")
OUTPUT_DIR = Path("repo_summaries")
MASTER_CSV = Path("repos_exceeding_thresholds.xlsx")

OUTPUT_DIR.mkdir(exist_ok=True)


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
    if not YAML_FILE.exists():
        raise FileNotFoundError(f"Missing repo list file: {YAML_FILE}")

    repos = load_repo_list_file(YAML_FILE)

    storage = SqliteRepoStorage(DB_FILE)
    collector = RepoCollector(
        storage=storage,
        endpoints=[RepoDetailsEndpoint, GetRepoTreeEndpoint],
    )
    primary_org = repos[0].split("/", 1)[0]
    collector.collect(primary_org, repos=repos, resume=True)
    ExcelCompiler().compile(
        storage=storage,
        config=master_csv_config,
        output_path=MASTER_CSV,
        transforms=[RepoTreeTransform()],
    )
    if not os.path.isdir(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    for full_repo_name in repos:
        data = storage.read(full_repo_name)
        if not data:
            raise RuntimeError(f"Expected data for {full_repo_name} in storage")
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
        pd.DataFrame(blob_rows).to_csv(
            OUTPUT_DIR / f"{full_repo_name.replace('/', '_')}_summary.csv",
            index=False,
        )


if __name__ == "__main__":
    main()
