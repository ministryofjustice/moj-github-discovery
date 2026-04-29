import json
import sqlite3
import requests

# -----------------------------
# CONFIGURATION
# -----------------------------
ORG = "ministryofjustice"
NAMESPACE_REPO = "cloud-platform-environments"
BRANCH = "main"

TOKEN_FILE = ".token"
DB_FILE = "repo_audit.db"

# -----------------------------
# LOAD TOKEN FROM .token FILE
# -----------------------------
with open(TOKEN_FILE, "r") as f:
    TOKEN = f.read().strip()

HEADERS = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}

# -----------------------------
# READ ARCHIVED REPOS FROM SQLITE DB
# -----------------------------
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

# repo_data stores a JSON blob in the data column.
cursor.execute("SELECT full_name, data FROM repo_data")
archived_repos = set()
row_count = 0
for full_name, data_json in cursor.fetchall():
    row_count += 1
    if not data_json:
        print(f"Skipping row {row_count}: {full_name} (no data)")
        continue
    try:
        repo_data = json.loads(data_json)
    except json.JSONDecodeError:
        print(f"Skipping row {row_count}: {full_name} (invalid JSON)")
        continue

    if not isinstance(repo_data, dict):
        print(
            f"Skipping row {row_count}: {full_name} (unexpected data type: {type(repo_data).__name__})"
        )
        continue

    repo_details = repo_data.get("repo_details")
    archived_flag = isinstance(repo_details, dict) and repo_details.get(
        "archived", False
    )
    print(f"Row {row_count}: {full_name} archived={archived_flag}")
    if archived_flag:
        archived_repos.add(full_name.split("/", 1)[-1])

conn.close()
print(f"Loaded {len(archived_repos)} archived repos from DB")
print(sorted(archived_repos))

# -----------------------------
# GET FULL REPO TREE (RECURSIVE)
# -----------------------------
tree_url = (
    f"https://api.github.com/repos/{ORG}/{NAMESPACE_REPO}/git/trees/"
    f"{BRANCH}?recursive=1"
)
print(f"Requesting namespace tree from: {tree_url}")
tree_resp = requests.get(tree_url, headers=HEADERS, timeout=10)
print(f"GitHub tree response status: {tree_resp.status_code}")
tree_data = tree_resp.json()
print("GitHub tree response payload keys:", list(tree_data.keys()))

if "tree" not in tree_data:
    raise RuntimeError("Could not retrieve repository tree. Check repo/branch/token.")

# -----------------------------
# EXTRACT NAMESPACE FOLDERS
# -----------------------------
namespace_folders = set()

for item in tree_data["tree"]:
    print(f"Inspecting tree item: {item.get('path')} (type={item.get('type')})")
    if item["type"] == "tree" and item["path"].startswith("namespaces/"):
        parts = item["path"].split("/")
        if len(parts) == 2:  # namespaces/<folder>
            print(f"Found namespace folder: {parts[1]}")
            namespace_folders.add(parts[1])

# -----------------------------
# CROSS-REFERENCE
# -----------------------------
orphaned = namespace_folders.intersection(archived_repos)

print("\n=== Archived repos that still have namespace folders ===")
if orphaned:
    for ns in sorted(orphaned):
        print(f"- {ns}")
else:
    print("No orphaned namespaces found.")
