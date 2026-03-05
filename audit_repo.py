#!/usr/bin/env python3
"""Audit a single GitHub repository for security and health.

Usage:
    python audit_repo.py owner/repo

The script will call the GitHub API to gather information about the
repository, count any security alerts (Dependabot, code scanning, secret
scanning), check default branch protection and community documentation, list
GitHub Actions workflows and apply a few heuristic risk flags.  These
metrics correspond to common DevOps/security checks such as:

  * presence of a license/SECURITY.md/CODE_OF_CONDUCT
  * whether CI workflows exist
  * whether the default branch is protected
  * open issue counts and activity metadata (returned in `repo` section)

Result is printed as JSON to stdout; the shape is:

By default the script also saves every result into a SQLite database named
`repo_audit.db` located in the same directory as this script.  You can
override the path with `--db` if desired.

  {
    "repo": { ... },                  # raw repo metadata
    "alerts": { ... },                # counts/access for scanning alerts
    "branch_protection": { ... },     # default branch status
    "community": { ... },             # documentation/policy file presence
    "workflows": {"count": N, ...}, # actions workflows info
    "flags": [ ... ]                  # simple heuristic warning labels
  }

Fields are documented in comments near their helpers, and the flags give a
quick at‑a‑glance summary of potential issues.

If you need to run this repeatedly against many repositories you can call it
from a loop or integrate it into other tooling.  See ``main.py`` in this
workspace for an example of how to audit an entire organization.
"""

import atexit
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# global start timestamp
__start_time: Optional[float] = None

def _report_elapsed() -> None:
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)

atexit.register(_report_elapsed)


from utils import gh_api, try_get, count_alerts, branch_protection, init_db, save_to_db, _get_session, fork_and_template_info, list_workflows, community_profile


def repo_info(owner: str, repo: str) -> Dict[str, Any]:
    # Basic repository metadata.  Contains most of the fields returned by
    # `gh api /repos/{owner}/{repo}`.  Useful values include:
    #   - private, fork, archived: visibility/special states
    #   - license: may be None if no license file is present
    #   - default_branch: name of the primary branch ("main"/"trunk" are
    #     preferred over "master")
    #   - has_issues, has_wiki, has_projects: indicates whether features are
    #     enabled
    #   - open_issues_count, watchers_count, stargazers_count: basic activity
    #   - topics: subject tags added by maintainers
    #
    return gh_api(f"/repos/{owner}/{repo}")


# `community_profile` moved to `utils.community_profile`


# `list_workflows` moved to `utils.list_workflows`


def analyze_workflows(owner: str, repo: str) -> Dict[str, Any]:
    # Fetch and analyze the actual workflow files to detect if they include
    # test or lint jobs/steps.  Returns a dict with:
    #   "has_tests": bool - True if ANY workflow mentions test-related keywords
    #   "has_linting": bool - True if ANY workflow mentions lint-related keywords
    #   "workflows_analyzed": int - number of workflows we examined
    #   "findings": dict - keyed by workflow name, lists detected keywords
    #
    # Common keywords searched:
    #   - test: test, pytest, jest, mocha, unittest, rspec, cargo test, vitest
    #   - lint: lint, eslint, pylint, flake8, black, prettier, clippy, rustfmt
    #
    test_keywords = [
        "test", "pytest", "jest", "mocha", "unittest", "rspec", "cargo test",
        "vitest", "tap", "ava", "jasmine", "nightwatch", "cypress", "vitest test"
    ]
    lint_keywords = [
        "lint", "eslint", "pylint", "flake8", "black", "prettier", "clippy",
        "rustfmt", "golangci-lint", "shellcheck", "shfmt", "hadolint", "yamllint"
    ]

    findings: Dict[str, List[str]] = {}
    has_tests = False
    has_linting = False
    workflows_analyzed = 0

    # Try to list files in .github/workflows/
    contents_path = f"/repos/{owner}/{repo}/contents/.github/workflows"
    workflow_files, err = try_get(contents_path)
    if err or not isinstance(workflow_files, list):
        # If we can't get the directory, return empty analysis
        return {
            "has_tests": False,
            "has_linting": False,
            "workflows_analyzed": 0,
            "findings": {},
            "note": "could not access .github/workflows directory",
        }

    # we'll fetch workflow files concurrently since network I/O is the
    # slowest part.
    session = _get_session()
    def fetch_and_scan(file_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(file_info, dict):
            return None
        name = file_info.get("name", "")
        download_url = file_info.get("download_url")
        if not download_url or not (name.endswith(".yml") or name.endswith(".yaml")):
            return None
        try:
            resp = session.get(download_url, timeout=10)
            resp.raise_for_status()
            content = resp.text
        except Exception:
            return None
        detected: List[str] = []
        lower = content.lower()
        for keyword in test_keywords:
            if keyword.lower() in lower:
                detected.append(f"test:{keyword}")
                return {"name": name, "detected": detected, "has_tests": True}
        for keyword in lint_keywords:
            if keyword.lower() in lower:
                detected.append(f"lint:{keyword}")
                return {"name": name, "detected": detected, "has_linting": True}
        return None

    futures = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        for fi in workflow_files:
            futures.append(executor.submit(fetch_and_scan, fi))
        for fut in as_completed(futures):
            res = fut.result()
            if not res:
                continue
            workflows_analyzed += 1
            name = res["name"]
            findings[name] = res.get("detected", [])
            if res.get("has_tests"):
                has_tests = True
            if res.get("has_linting"):
                has_linting = True

    return {
        "has_tests": has_tests,
        "has_linting": has_linting,
        "workflows_analyzed": workflows_analyzed,
        "findings": findings,
    }


def assess(owner: str, repo: str, no_alerts: bool = False) -> Dict[str, Any]:
    info = repo_info(owner, repo)
    default_branch = info.get("default_branch")
    alerts = {} if no_alerts else count_alerts(owner, repo)
    prot = branch_protection(owner, repo, default_branch) if default_branch else {}
    community = community_profile(owner, repo)
    workflows = list_workflows(owner, repo)
    workflow_analysis = analyze_workflows(owner, repo)
    fork_template = fork_and_template_info(info)

    # assemble a handful of simple flags to highlight potential concerns
    flags: List[str] = []
    if info.get("archived"):
        flags.append("archived")  # not receiving updates
    if fork_template.get("is_fork"):
        fork_source = fork_template.get("fork_source")
        if fork_source:
            flags.append(f"fork_of_{fork_source}")
        else:
            flags.append("fork")
    if fork_template.get("is_generated_from_template"):
        template_source = fork_template.get("template_source")
        if template_source:
            flags.append(f"generated_from_template_{template_source}")
        else:
            flags.append("generated_from_template")
    if info.get("license") is None:
        # absence of a license file; depending on policy this may be
        # considered a legal issue for open-source distributions.
        flags.append("no_license")
    if info.get("private") is False and not prot.get("default_branch_protected"):
        flags.append("public_unprotected_default_branch")
    if (alerts.get("dependabot_alerts") or 0) > 0:
        flags.append("dependabot_alerts_present")
    if (alerts.get("secret_scanning_alerts") or 0) > 0:
        flags.append("secret_alerts_present")
    if (alerts.get("code_scanning_alerts") or 0) > 0:
        flags.append("code_scanning_alerts_present")
    if not community.get("files", {}).get("security_policy"):
        flags.append("no_security_policy")
    if not community.get("files", {}).get("code_of_conduct"):
        flags.append("no_code_of_conduct")
    if len(workflows) == 0:
        flags.append("no_actions_workflows")
    if len(workflows) > 0 and not workflow_analysis.get("has_tests"):
        flags.append("no_detected_tests")
    if len(workflows) > 0 and not workflow_analysis.get("has_linting"):
        flags.append("no_detected_linting")

    # The returned dictionary contains several nested structures; clients can
    # inspect each to determine health/security posture.  For example:
    #   - repo['license'] being None means no license file.
    #   - community['files']['security_policy'] True signals a SECURITY.md.
    #   - workflows list length shows whether CI is defined.
    #   - workflow_analysis['has_tests'] indicates if testing is in workflows.
    #   - workflow_analysis['has_linting'] indicates if linting is in workflows.
    #   - prot['default_branch_protected'] False indicates missing status checks.
    #   - fork_template['is_fork'] indicates if repo is a fork, with fork_source showing parent
    #   - fork_template['is_generated_from_template'] indicates if repo created from template

    return {
        "repo": info,
        "alerts": alerts,
        "branch_protection": prot,
        "community": community,
        "workflows": {"count": len(workflows), "list": workflows},
        "workflow_analysis": workflow_analysis,
        "fork_and_template": fork_template,
        "flags": flags,
    }


def main() -> None:
    global __start_time
    __start_time = time.monotonic()
    # parse options after the repo spec
    no_alerts = False
    if len(sys.argv) < 2:
        print("Usage: python audit_repo.py owner/repo [--db database.db] [--no-alerts]")
        print("  owner/repo: the repository to audit (e.g., github/cli)")
        print("  --db database.db: optional override of default local DB")
        print("  --no-alerts: skip security alert lookups")
        sys.exit(2)

    spec = sys.argv[1]
    # default database located next to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(script_dir, "repo_audit.db")

    # allow override via --db and parse --no-alerts
    j = 2
    while j < len(sys.argv):
        if sys.argv[j] == "--db" and j + 1 < len(sys.argv):
            db_path = sys.argv[j + 1]
            j += 2
        elif sys.argv[j] == "--no-alerts":
            no_alerts = True
            j += 1
        else:
            break

    if "/" not in spec:
        print("Error: repository must be specified as owner/repo")
        sys.exit(2)

    owner, repo = spec.split("/", 1)
    full_name = f"{owner}/{repo}"
    result = assess(owner, repo, no_alerts=no_alerts)

    # always save to database
    init_db(db_path, table_name="audits")
    save_to_db(db_path, full_name, result, table_name="audits")
    print(f"Saved audit for {full_name} to {db_path}", file=sys.stderr)
    # Always print JSON to stdout
    print(json.dumps(result, indent=2))

    elapsed = time.monotonic() - __start_time
    print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)


if __name__ == "__main__":
    main()
