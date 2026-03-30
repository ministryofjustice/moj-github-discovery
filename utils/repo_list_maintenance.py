#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from core.github_api import list_org_repos
from core.github_client import GitHubHttpClient
from core.repo_list import load_repo_list_file

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Supplement repo_list.yaml with recent org repos and/or validate "
            "that listed repos exist in the target org."
        )
    )
    parser.add_argument(
        "--org",
        default="ministryofjustice",
        help="GitHub organization name (default: ministryofjustice)",
    )
    parser.add_argument(
        "--repo-file",
        default="repo_list.yaml",
        help="Path to repo list file (default: repo_list.yaml)",
    )
    parser.add_argument(
        "--target-count",
        type=int,
        default=400,
        help="Desired final number of repos when supplementing (default: 400)",
    )
    parser.add_argument(
        "--mode",
        choices=["supplement", "validate", "both"],
        default="both",
        help="Action mode: supplement, validate, or both (default: both)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview updates without writing file changes",
    )
    parser.add_argument(
        "--fail-on-validation",
        action="store_true",
        help="Exit with code 1 if validation finds issues",
    )
    parser.add_argument(
        "--missing-report",
        help="Optional path to write missing repos report",
    )
    parser.add_argument(
        "--prune-missing",
        action="store_true",
        help="Remove wrong-org and missing repos from the repo file",
    )
    return parser.parse_args()


def resolve_repo_file(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path

    cwd_candidate = (Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate

    return (PROJECT_ROOT / path).resolve()


def append_repos(repo_file: Path, repos_to_add: list[str]) -> None:
    text = repo_file.read_text(encoding="utf-8")
    if "repos:" not in text:
        raise ValueError(f"Expected top-level 'repos:' list in {repo_file}")

    new_text = text
    if not new_text.endswith("\n"):
        new_text += "\n"

    for repo in repos_to_add:
        new_text += f"- {repo}\n"

    repo_file.write_text(new_text, encoding="utf-8")


def write_repo_list(repo_file: Path, repos: list[str]) -> None:
    original_lines = repo_file.read_text(encoding="utf-8").splitlines()
    header_lines: list[str] = []

    for line in original_lines:
        header_lines.append(line)
        if line.strip() == "repos:":
            break

    if not header_lines or header_lines[-1].strip() != "repos:":
        raise ValueError(f"Expected top-level 'repos:' list in {repo_file}")

    new_lines = header_lines + [f"- {repo}" for repo in repos]
    repo_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def write_missing_report(
    report_file: Path,
    org: str,
    wrong_org: list[str],
    missing: list[str],
) -> None:
    lines = [
        f"org: {org}",
        f"wrong_org_count: {len(wrong_org)}",
        f"missing_count: {len(missing)}",
        "",
        "wrong_org_entries:",
    ]
    lines.extend(f"- {repo}" for repo in wrong_org)
    lines.append("")
    lines.append("missing_entries:")
    lines.extend(f"- {repo}" for repo in missing)
    report_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


def validate_repo_list(
    existing_repos: list[str],
    org: str,
    org_repo_set: set[str],
) -> tuple[list[str], list[str]]:
    expected_prefix = f"{org}/"
    wrong_org = [
        repo for repo in existing_repos if not repo.startswith(expected_prefix)
    ]
    missing = [
        repo
        for repo in existing_repos
        if repo.startswith(expected_prefix) and repo not in org_repo_set
    ]
    return wrong_org, missing


def main() -> None:
    args = parse_args()

    if args.target_count < 0:
        raise ValueError("--target-count must be >= 0")

    repo_file = resolve_repo_file(args.repo_file)
    existing_repos = load_repo_list_file(repo_file)
    existing_set = set(existing_repos)

    client = GitHubHttpClient()
    recent_org_repos = list_org_repos(
        args.org,
        client,
        type="all",
        sort="updated",
        direction="desc",
    )
    org_repo_set = set(recent_org_repos)

    validation_issues = 0
    if args.mode in {"validate", "both"}:
        wrong_org, missing = validate_repo_list(existing_repos, args.org, org_repo_set)
        print("Validation summary:")
        print(f"- Total listed repos: {len(existing_repos)}")
        print(f"- Repo names in org inventory: {len(org_repo_set)}")
        print(f"- Wrong org prefix entries: {len(wrong_org)}")
        print(f"- Missing in org inventory: {len(missing)}")

        if wrong_org:
            print("Wrong org prefix entries:")
            for repo in wrong_org:
                print(f"- {repo}")

        if missing:
            print("Listed but not found in org inventory:")
            for repo in missing:
                print(f"- {repo}")

        if args.missing_report:
            report_file = resolve_repo_file(args.missing_report)
            if args.dry_run:
                print(f"Dry run: would write missing report to {report_file}")
            else:
                write_missing_report(report_file, args.org, wrong_org, missing)
                print(f"Wrote missing report: {report_file}")

        if args.prune_missing and (wrong_org or missing):
            prune_set = set(wrong_org) | set(missing)
            cleaned_repos = [repo for repo in existing_repos if repo not in prune_set]
            removed_count = len(existing_repos) - len(cleaned_repos)
            if args.dry_run:
                print(f"Dry run: would prune {removed_count} repo(s) from {repo_file}")
            else:
                write_repo_list(repo_file, cleaned_repos)
                print(f"Pruned {removed_count} repo(s) from {repo_file}")
                existing_repos = cleaned_repos
                existing_set = set(existing_repos)

        validation_issues = len(wrong_org) + len(missing)

    if args.mode in {"supplement", "both"}:
        needed = args.target_count - len(existing_repos)
        print(f"Current count: {len(existing_repos)}")
        print(f"Target count: {args.target_count}")
        print(f"Needed: {max(0, needed)}")

        if needed > 0:
            missing_recent = [
                repo for repo in recent_org_repos if repo not in existing_set
            ]
            repos_to_add = missing_recent[:needed]

            print(f"Available missing recent repos: {len(missing_recent)}")
            if repos_to_add:
                print("Repos selected for append:")
                for repo in repos_to_add:
                    print(f"- {repo}")

                if args.dry_run:
                    print("Dry run complete; no file changes written.")
                else:
                    append_repos(repo_file, repos_to_add)
                    print(
                        f"Appended {len(repos_to_add)} repos to {repo_file}. "
                        f"New count: {len(existing_repos) + len(repos_to_add)}"
                    )
            else:
                print("No missing repos available to add.")
        else:
            print("No supplement needed; target count already met.")

    if args.fail_on_validation and validation_issues > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
