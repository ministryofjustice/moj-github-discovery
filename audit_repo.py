#!/usr/bin/env python3
"""Audit a single GitHub repository for security and health.

Usage:
    python audit_repo.py owner/repo

The script will call the GitHub CLI (gh) to gather information about the
repository, count any security alerts (Dependabot, code scanning, secret
scanning), check default branch protection, and apply a few heuristic risk
flags.  Result is printed as JSON to stdout.

If you need to run this repeatedly against many repositories you can call it
from a loop or integrate it into other tooling.  See ``main.py`` in this
workspace for an example of how to audit an entire organization.
"""

import json
import subprocess
import sys
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


def repo_info(owner: str, repo: str) -> Dict[str, Any]:
    return gh_api(f"/repos/{owner}/{repo}")


def assess(owner: str, repo: str) -> Dict[str, Any]:
    info = repo_info(owner, repo)
    default_branch = info.get("default_branch")
    alerts = count_alerts(owner, repo)
    prot = branch_protection(owner, repo, default_branch) if default_branch else {}

    flags: List[str] = []
    if info.get("archived"):
        flags.append("archived")
    if info.get("fork"):
        flags.append("fork")
    if info.get("private") is False and not prot.get("default_branch_protected"):
        flags.append("public_unprotected_default_branch")
    if (alerts.get("dependabot_alerts") or 0) > 0:
        flags.append("dependabot_alerts_present")
    if (alerts.get("secret_scanning_alerts") or 0) > 0:
        flags.append("secret_alerts_present")
    if (alerts.get("code_scanning_alerts") or 0) > 0:
        flags.append("code_scanning_alerts_present")

    return {
        "repo": info,
        "alerts": alerts,
        "branch_protection": prot,
        "flags": flags,
    }


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python audit_repo.py owner/repo")
        sys.exit(2)

    spec = sys.argv[1]
    if "/" not in spec:
        print("Error: repository must be specified as owner/repo")
        sys.exit(2)

    owner, repo = spec.split("/", 1)
    result = assess(owner, repo)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
