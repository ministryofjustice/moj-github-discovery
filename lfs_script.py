import csv
import os
from pathlib import Path
from urllib.parse import urlparse

import yaml

from core.github_client import GitHubHttpClient

# GitHub thresholds (bytes)
SOFT_LIMIT = 50 * 1024 * 1024
HARD_LIMIT = 100 * 1024 * 1024

YAML_FILE = Path("repo_list.yaml")
OUTPUT_DIR = Path("repo_summaries")
MASTER_CSV = Path("repos_exceeding_thresholds.csv")

OUTPUT_DIR.mkdir(exist_ok=True)


def load_token() -> str:
    token_file = Path(".token")
    if token_file.exists():
        return token_file.read_text().strip()

    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        return token

    raise RuntimeError("No GitHub token found. Set .token, GITHUB_TOKEN or GH_TOKEN.")


def normalize_repo_entry(entry: str) -> str:
    entry = entry.strip()
    if not entry:
        raise ValueError("Empty repo entry")

    # owner/repo or https://github.com/owner/repo(.git)
    if entry.startswith("http://") or entry.startswith("https://"):
        parsed = urlparse(entry)
        path = parsed.path.lstrip("/")
        if path.endswith(".git"):
            path = path[:-4]
        return path

    # already owner/repo
    if "/" in entry:
        return entry

    raise ValueError(f"Unrecognized repo entry format: {entry}")


def fetch_repo_tree(owner: str, repo: str, client: GitHubHttpClient) -> list[dict]:
    api_branch = client.get(f"/repos/{owner}/{repo}").get("default_branch") or "main"
    tree = client.get(f"/repos/{owner}/{repo}/git/trees/{api_branch}?recursive=1")

    if not isinstance(tree, dict) or "tree" not in tree:
        raise RuntimeError(f"Unexpected tree response for {owner}/{repo}: {tree}")

    return tree["tree"]


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


def scan_repo_via_api(repo_full_name: str, client: GitHubHttpClient):
    owner, _, repo = repo_full_name.partition("/")
    if not owner or not repo:
        raise ValueError(f"Bad repo full name: {repo_full_name}")

    tree = fetch_repo_tree(owner, repo, client)
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

    with YAML_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    repos = data.get("repos", [])
    if not isinstance(repos, list) or not repos:
        raise ValueError("repo_list.yaml must define a non-empty 'repos' list")

    token = load_token()
    client = GitHubHttpClient(token=token)

    with MASTER_CSV.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "repo",
                "largest_blob_bytes",
                "largest_blob_path",
                "exceeds_soft_limit",
                "exceeds_hard_limit",
            ]
        )

        for entry in repos:
            repo_full_name = normalize_repo_entry(str(entry))
            print(f"Processing: {repo_full_name}")

            try:
                api_tree = fetch_repo_tree(*repo_full_name.split("/", 1), client=client)
                result = scan_repo_via_api(repo_full_name, client)
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
