"""Common utilities for GitHub repository auditing."""

import json
import sqlite3
import subprocess
from typing import Any, Dict, List, Optional, Tuple


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
    out = out.strip()
    if not out:
        return None
    if out[0] == "[" or out[0] == "{":
        return json.loads(out)
    lines = [json.loads(line) for line in out.splitlines() if line.strip()]
    if lines and isinstance(lines[0], list):
        merged = []
        for page in lines:
            merged.extend(page)
        return merged
    return lines


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
    """Count security alerts (dependabot, code-scanning, secret-scanning)."""
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
    """Check if the default branch is protected."""
    prot, err = try_get(f"/repos/{owner}/{repo}/branches/{default_branch}/protection")
    if err == "404":
        return {"default_branch_protected": False}
    if err == "403":
        return {"default_branch_protected": None, "branch_protection_access": "forbidden"}
    if err is None:
        return {"default_branch_protected": True}
    return {"default_branch_protected": None, "branch_protection_access": err}


def init_db(db_path: str, table_name: str = "audits") -> None:
    """Initialize SQLite database with a table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            full_name TEXT PRIMARY KEY,
            audit_json TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_to_db(db_path: str, full_name: str, data: Dict[str, Any], table_name: str = "audits") -> None:
    """Upsert data into SQLite database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        f"INSERT OR REPLACE INTO {table_name} (full_name, audit_json) VALUES (?, ?)",
        (full_name, json.dumps(data))
    )
    conn.commit()
    conn.close()
