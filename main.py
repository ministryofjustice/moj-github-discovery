import json
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd


def run_gh(args: List[str]) -> str:
    """Run a gh command and return stdout, raising on non-zero exit."""
    cmd = ["gh"] + args
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc.stdout


def gh_api(path: str, method: str = "GET", paginate: bool = False, params: Optional[List[str]] = None) -> Any:
    """Call gh api and parse JSON."""
    args = ["api", f"-X{method}"]
    if paginate:
        args.append("--paginate")
    if params:
        for p in params:
            args += ["-f", p]
    args.append(path)

    out = run_gh(args)
    # --paginate returns JSON objects separated by newlines sometimes; try to handle both.
    out = out.strip()
    if not out:
        return None
    if out[0] == "[" or out[0] == "{":
        return json.loads(out)
    # Fallback for NDJSON-like output
    lines = [json.loads(line) for line in out.splitlines() if line.strip()]
    # If each page is an array, flatten
    if lines and isinstance(lines[0], list):
        merged = []
        for page in lines:
            merged.extend(page)
        return merged
    return lines


def list_org_repos(org: str, limit: int = 400) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    page = 1
    per_page = 100

    while len(repos) < limit:
        batch = gh_api(
            f"/orgs/{org}/repos?per_page={per_page}&page={page}&sort=pushed&direction=desc"
        )
        if not batch:
            break
        if isinstance(batch, list):
            repos.extend(batch)
        else:
            break
        page += 1

    return repos[:limit]


def try_get(path: str) -> Tuple[Optional[Any], Optional[str]]:
    """Return (json, error_kind). error_kind in {'404','403','other'} or None."""
    try:
        return gh_api(path), None
    except RuntimeError as e:
        msg = str(e)
        if "HTTP 404" in msg:
            return None, "404"
        if "HTTP 403" in msg:
            return None, "403"
        return None, "other"


def count_alerts(owner: str, repo: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}

    dep, dep_err = try_get(f"/repos/{owner}/{repo}/dependabot/alerts?per_page=100")
    if dep_err == "403":
        result["dependabot_access"] = "forbidden"
        result["dependabot_alerts"] = None
    else:
        result["dependabot_access"] = "ok" if dep_err is None else dep_err
        result["dependabot_alerts"] = len(dep) if isinstance(dep, list) else 0

    cs, cs_err = try_get(f"/repos/{owner}/{repo}/code-scanning/alerts?per_page=100")
    if cs_err == "403":
        result["code_scanning_access"] = "forbidden"
        result["code_scanning_alerts"] = None
    else:
        result["code_scanning_access"] = "ok" if cs_err is None else cs_err
        result["code_scanning_alerts"] = len(cs) if isinstance(cs, list) else 0

    ss, ss_err = try_get(f"/repos/{owner}/{repo}/secret-scanning/alerts?per_page=100")
    if ss_err == "403":
        result["secret_scanning_access"] = "forbidden"
        result["secret_scanning_alerts"] = None
    else:
        result["secret_scanning_access"] = "ok" if ss_err is None else ss_err
        result["secret_scanning_alerts"] = len(ss) if isinstance(ss, list) else 0

    return result


def branch_protection(owner: str, repo: str, default_branch: str) -> Dict[str, Any]:
    prot, err = try_get(f"/repos/{owner}/{repo}/branches/{default_branch}/protection")
    if err == "404":
        return {"default_branch_protected": False}
    if err == "403":
        return {"default_branch_protected": None, "branch_protection_access": "forbidden"}
    if err is None:
        return {"default_branch_protected": True}
    return {"default_branch_protected": None, "branch_protection_access": err}


def main():
    if len(sys.argv) < 2:
        print("Usage: python audit_org.py <org> [output.xlsx]")
        sys.exit(2)

    org = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else f"{org}_security_audit.xlsx"

    repos = list_org_repos(org)

    rows: List[Dict[str, Any]] = []
    for r in repos:
        name = r["name"]
        owner = r["owner"]["login"]
        default_branch = r.get("default_branch")
        row = {
            "org": org,
            "repo": name,
            "full_name": r.get("full_name"),
            "private": r.get("private"),
            "archived": r.get("archived"),
            "fork": r.get("fork"),
            "pushed_at": r.get("pushed_at"),
            "default_branch": default_branch,
            "language": r.get("language"),
            "open_issues": r.get("open_issues_count"),
            "stargazers": r.get("stargazers_count"),
        }

        row.update(count_alerts(owner, name))
        if default_branch:
            row.update(branch_protection(owner, name, default_branch))

        # Simple heuristic risk flags (tune these)
        flags = []
        if row["archived"]:
            flags.append("archived")
        if row["fork"]:
            flags.append("fork")
        if row["private"] is False and not row.get("default_branch_protected"):
            flags.append("public_unprotected_default_branch")
        if (row.get("dependabot_alerts") or 0) > 0:
            flags.append("dependabot_alerts_present")
        if (row.get("secret_scanning_alerts") or 0) > 0:
            flags.append("secret_alerts_present")
        if (row.get("code_scanning_alerts") or 0) > 0:
            flags.append("code_scanning_alerts_present")

        row["flags"] = ", ".join(flags)
        rows.append(row)

    df = pd.DataFrame(rows)

    # Summary
    summary = pd.DataFrame(
        {
            "metric": [
                "repos_total",
                "repos_public",
                "repos_private",
                "repos_archived",
                "repos_with_dependabot_alerts",
                "repos_with_secret_alerts",
                "repos_with_code_scanning_alerts",
                "repos_unprotected_default_branch",
            ],
            "value": [
                len(df),
                int((df["private"] == False).sum()),
                int((df["private"] == True).sum()),
                int(df["archived"].sum()),
                int((df["dependabot_alerts"].fillna(0) > 0).sum()),
                int((df["secret_scanning_alerts"].fillna(0) > 0).sum()),
                int((df["code_scanning_alerts"].fillna(0) > 0).sum()),
                int((df["default_branch_protected"] == False).sum()),
            ],
        }
    )

    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Repos")
        summary.to_excel(writer, index=False, sheet_name="Summary")

    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
