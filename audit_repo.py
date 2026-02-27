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

import json
import os
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests

from utils import gh_api, try_get, count_alerts, branch_protection, init_db, save_to_db


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


def community_profile(owner: str, repo: str) -> Dict[str, Any]:
    # The community profile endpoint gives a high-level view of repository
    # documentation and policy files.  The `files` dict indicates whether
    # items like SECURITY.md, CODE_OF_CONDUCT, CONTRIBUTING, etc.
    # are present.  The presence of a security policy is useful for
    # incident response and disclosure reporting; code of conduct helps
    # ensure a healthy contributor community.
    return gh_api(f"/repos/{owner}/{repo}/community/profile")


def list_workflows(owner: str, repo: str) -> List[Dict[str, Any]]:
    # Returns the array of GitHub Actions workflows configured for the
    # repository.  If the list is empty, the repo has no CI defined via
    # Actions.  You could also look in `.github/workflows` directly but this
    # API is convenient.
    out, err = try_get(f"/repos/{owner}/{repo}/actions/workflows")
    # on error, err may be '403' if not permitted; treat as empty list
    if isinstance(out, dict) and "workflows" in out:
        return out.get("workflows", [])
    return []


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

    for file_info in workflow_files:
        if not isinstance(file_info, dict):
            continue
        name = file_info.get("name", "")
        download_url = file_info.get("download_url")

        if not download_url or not (name.endswith(".yml") or name.endswith(".yaml")):
            continue

        # Fetch the workflow file content
        try:
            response = requests.get(download_url, timeout=10)
            response.raise_for_status()
            content = response.text
        except Exception:
            # If we can't fetch, skip this file
            continue

        workflows_analyzed += 1
        detected = []

        # Search for test keywords (case-insensitive)
        content_lower = content.lower()
        for keyword in test_keywords:
            if keyword.lower() in content_lower:
                detected.append(f"test:{keyword}")
                has_tests = True
                break  # Only count once per file

        # Search for lint keywords
        for keyword in lint_keywords:
            if keyword.lower() in content_lower:
                detected.append(f"lint:{keyword}")
                has_linting = True
                break  # Only count once per file

        if detected:
            findings[name] = detected

    return {
        "has_tests": has_tests,
        "has_linting": has_linting,
        "workflows_analyzed": workflows_analyzed,
        "findings": findings,
    }


def assess(owner: str, repo: str) -> Dict[str, Any]:
    info = repo_info(owner, repo)
    default_branch = info.get("default_branch")
    alerts = count_alerts(owner, repo)
    prot = branch_protection(owner, repo, default_branch) if default_branch else {}
    community = community_profile(owner, repo)
    workflows = list_workflows(owner, repo)
    workflow_analysis = analyze_workflows(owner, repo)

    # assemble a handful of simple flags to highlight potential concerns
    flags: List[str] = []
    if info.get("archived"):
        flags.append("archived")  # not receiving updates
    if info.get("fork"):
        flags.append("fork")
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

    return {
        "repo": info,
        "alerts": alerts,
        "branch_protection": prot,
        "community": community,
        "workflows": {"count": len(workflows), "list": workflows},
        "workflow_analysis": workflow_analysis,
        "flags": flags,
    }


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python audit_repo.py owner/repo [--db database.db]")
        print("  owner/repo: the repository to audit (e.g., github/cli)")
        print("  --db database.db: optional override of default local DB")
        sys.exit(2)

    spec = sys.argv[1]
    # default database located next to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(script_dir, "repo_audit.db")

    # allow override via --db
    if len(sys.argv) > 2 and sys.argv[2] == "--db" and len(sys.argv) > 3:
        db_path = sys.argv[3]

    if "/" not in spec:
        print("Error: repository must be specified as owner/repo")
        sys.exit(2)

    owner, repo = spec.split("/", 1)
    full_name = f"{owner}/{repo}"
    result = assess(owner, repo)

    # always save to database
    init_db(db_path, table_name="audits")
    save_to_db(db_path, full_name, result, table_name="audits")
    print(f"Saved audit for {full_name} to {db_path}", file=sys.stderr)
    # Always print JSON to stdout
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
