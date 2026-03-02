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


from utils import gh_api, try_get, count_alerts, branch_protection, init_db, save_to_db, _get_session, list_workflows, analyze_workflows, get_code_security_configuration


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




def assess(owner: str, repo: str, no_alerts: bool = False) -> Dict[str, Any]:
    info = repo_info(owner, repo)
    default_branch = info.get("default_branch")
    alerts = {} if no_alerts else count_alerts(owner, repo)
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
