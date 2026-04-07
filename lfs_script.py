import csv
from pathlib import Path


from core.collector import RepoCollector
from core.github_api import GetRepoTreeEndpoint
from core.repo_list import load_repo_list_file
from core.storage import SqliteRepoStorage

# GitHub thresholds (bytes)
SOFT_LIMIT = 50 * 1024 * 1024
HARD_LIMIT = 100 * 1024 * 1024

YAML_FILE = Path("repo_list.yaml")
DB_FILE = Path("repo_list.db")
OUTPUT_DIR = Path("repo_summaries")
MASTER_CSV = Path("repos_exceeding_thresholds.csv")

OUTPUT_DIR.mkdir(exist_ok=True)


def find_largest_blob(tree: list[dict]) -> tuple[int, str, str | None]:
    largest_size = 0
    largest_path = ""
    largest_sha = None

    for item in tree:
        if item.get("type") != "blob":
            continue
        size = item.get("size")
        if not isinstance(size, int):
            continue

        if size > largest_size:
            largest_size = size
            largest_path = item.get("path", "")
            largest_sha = item.get("sha")

    return largest_size, largest_path, largest_sha


def scan_repo_via_api(repo_full_name, tree):
    large_blobs = []

    for item in tree:
        if item.get("type") != "blob" or not isinstance(item.get("size"), int):
            continue
        size = item["size"]
        if size >= SOFT_LIMIT:
            large_blobs.append((item.get("sha"), size, item.get("path")))

    largest_size, largest_path, _largest_sha = find_largest_blob(tree)

    return {
        "repo": repo_full_name,
        "largest_blob_bytes": largest_size,
        "largest_blob_path": largest_path,
        "large_blobs": large_blobs,
        "exceeds_soft_limit": largest_size > SOFT_LIMIT,
        "exceeds_hard_limit": largest_size > HARD_LIMIT,
    }


def write_repo_csv(repo_full_name: str, tree: list[dict]):
    sanitized = repo_full_name.replace("/", "_")
    output_file = OUTPUT_DIR / f"{sanitized}_summary.csv"

    with output_file.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["sha", "size_bytes", "path"])
        for item in tree:
            if item.get("type") != "blob" or not isinstance(item.get("size"), int):
                continue
            writer.writerow([item.get("sha"), item.get("size"), item.get("path")])

    return output_file


def main():
    if not YAML_FILE.exists():
        raise FileNotFoundError(f"Missing repo list file: {YAML_FILE}")

    repos = load_repo_list_file(YAML_FILE)

    storage = SqliteRepoStorage(DB_FILE)
    collector = RepoCollector(
        storage=storage,
        endpoints=[GetRepoTreeEndpoint],
    )
    primary_org = repos[0].split("/", 1)[0]
    collector.collect(primary_org, repos=repos, resume=False)

    # with MASTER_CSV.open("w", newline="") as f:
    #     writer = csv.writer(f)
    #     writer.writerow(
    #         [
    #             "repo",
    #             "largest_blob_bytes",
    #             "largest_blob_path",
    #             "exceeds_soft_limit",
    #             "exceeds_hard_limit",
    #         ]
    #     )

    for repo_full_name in repos:
        print(f"Processing: {repo_full_name}")
        data = storage.read(repo_full_name)
        writer = csv.writer(MASTER_CSV.open("a", newline=""))  # to be removed
        try:
            api_tree = data.get("repo_tree")["tree"]
            result = scan_repo_via_api(repo_full_name, api_tree)
            write_repo_csv(repo_full_name, api_tree)

            writer.writerow(
                [
                    result["repo"],
                    result["largest_blob_bytes"],
                    result["largest_blob_path"],
                    "yes" if result["exceeds_soft_limit"] else "no",
                    "yes" if result["exceeds_hard_limit"] else "no",
                ]
            )

            if result["large_blobs"]:
                print(
                    f"  Large blobs found: {len(result['large_blobs'])} >= {SOFT_LIMIT} bytes"
                )
            else:
                print("  No blobs above soft limit")

        except Exception as exc:
            print(f"  Error scanning {repo_full_name}: {exc}")


print("Done.")
print(f"Per-repo CSVs in: {OUTPUT_DIR}")
print(f"Master summary: {MASTER_CSV}")


if __name__ == "__main__":
    main()
