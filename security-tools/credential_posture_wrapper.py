#!/usr/bin/env python3

import csv
import os
import sys

BREACH_POSTURES = {"long_lived_credentials"}
WARNING_POSTURES = {"mixed"}
IGNORED_POSTURES = {"oidc", "no_cloud_auth_detected", "none", ""}

CSV_FILE = os.environ.get(
    "CREDENTIAL_POSTURE_CSV",
    "output/github_workflow_posture/credentials_analysis/github_workflow_credential_posture.csv",
)


def main():
    if not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0:
        print(f"No credential posture data at {CSV_FILE}. Nothing to check.")
        sys.exit(0)

    breaches = []
    warnings = []

    with open(CSV_FILE) as f:
        reader = csv.DictReader(f)
        for row in reader:
            posture = (row.get("posture") or "").strip()
            repo = row.get("repo", "")
            workflow_path = row.get("workflow_path", "")

            if posture in IGNORED_POSTURES:
                continue
            if posture in BREACH_POSTURES:
                breaches.append((repo, workflow_path, posture))
            elif posture in WARNING_POSTURES:
                warnings.append((repo, workflow_path, posture))

    if breaches:
        print("::error::Long-lived credential usage detected")
        for repo, path, posture in breaches:
            print(f"::error::{repo} {path} - {posture}")

    if warnings:
        print("::warning::Mixed credential posture detected")
        for repo, path, posture in warnings:
            print(f"::warning::{repo} {path} - {posture}")

    print(
        f"Credential posture summary: "
        f"{len(breaches)} long-lived, {len(warnings)} mixed."
    )

    if breaches:
        sys.exit(1)

    print("No long-lived credential usage. Passing.")
    sys.exit(0)


if __name__ == "__main__":
    main()
