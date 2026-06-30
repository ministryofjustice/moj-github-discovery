#!/usr/bin/env python3
"""Validate uv version sync across repo pins, docs, and local environment."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

LINT_WORKFLOW = Path(".github/workflows/lint.yml")
PYTEST_WORKFLOW = Path(".github/workflows/pytest.yml")
DOCKERFILE = Path("docker-audit-cli/Dockerfile")
SETUP_DOC = Path("docs/setup.md")

UV_VERSION_YAML_RE = re.compile(r"uv-version:\s*\"(?P<version>\d+\.\d+\.\d+)\"")
UV_VERSION_DOCKER_RE = re.compile(r"\buv==(?P<version>\d+\.\d+\.\d+)\b")
UV_VERSION_SETUP_RE = re.compile(r"pins\s+`uv`\s+CLI\s+`(?P<version>\d+\.\d+\.\d+)`")
UV_LOCAL_RE = re.compile(r"uv\s+(?P<version>\d+\.\d+\.\d+)")


def parse_semver(version: str) -> tuple[int, int, int]:
    """Convert a semantic version string (x.y.z) into a sortable tuple."""
    parts = version.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])


def read_text(path: Path) -> str:
    """Read a UTF-8 text file and raise a clear error if it is missing."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"Required file not found: {path}") from exc


def extract_version(text: str, pattern: re.Pattern[str], source: str) -> str:
    """Extract a uv version string from text using the provided regex pattern."""
    match = pattern.search(text)
    if not match:
        raise RuntimeError(f"Could not extract uv version from {source}")
    return match.group("version")


def get_local_uv_version() -> str:
    """Return the locally resolved uv CLI version from `uv --version`."""
    try:
        result = subprocess.run(
            ["uv", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("uv executable not found on PATH.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"uv --version failed: {exc.stderr.strip()}") from exc

    output = result.stdout.strip()
    match = UV_LOCAL_RE.search(output)
    if not match:
        raise RuntimeError(f"Could not parse local uv version from output: {output}")
    return match.group("version")


def read_managed_versions() -> tuple[str, str, str, str]:
    """Read uv versions from workflow pins, Dockerfile pin, and setup docs."""
    lint_version = extract_version(
        read_text(LINT_WORKFLOW), UV_VERSION_YAML_RE, str(LINT_WORKFLOW)
    )
    pytest_version = extract_version(
        read_text(PYTEST_WORKFLOW), UV_VERSION_YAML_RE, str(PYTEST_WORKFLOW)
    )
    docker_version = extract_version(
        read_text(DOCKERFILE), UV_VERSION_DOCKER_RE, str(DOCKERFILE)
    )
    setup_version = extract_version(
        read_text(SETUP_DOC), UV_VERSION_SETUP_RE, str(SETUP_DOC)
    )
    return lint_version, pytest_version, docker_version, setup_version


def validate_managed_alignment(
    lint_version: str, pytest_version: str, docker_version: str
) -> tuple[int, str | None]:
    """Ensure managed uv pins in CI and Docker are aligned to a single version."""
    managed_versions = {lint_version, pytest_version, docker_version}
    if len(managed_versions) != 1:
        print("uv sync check failed: managed uv pins are not aligned.")
        print(f"- {LINT_WORKFLOW}: {lint_version}")
        print(f"- {PYTEST_WORKFLOW}: {pytest_version}")
        print(f"- {DOCKERFILE}: {docker_version}")
        print("Align these values before continuing.")
        return 1, None
    return 0, lint_version


def validate_setup_version(expected: str, setup_version: str) -> int:
    """Ensure docs/setup.md matches the managed uv version."""
    if setup_version == expected:
        return 0

    setup_semver = parse_semver(setup_version)
    expected_semver = parse_semver(expected)
    if setup_semver < expected_semver:
        print(
            "uv sync check failed: docs/setup.md is older than the Renovate-managed uv version."
        )
    else:
        print(
            "uv sync check failed: docs/setup.md does not match the Renovate-managed uv version."
        )
    print(f"- managed uv version: {expected}")
    print(f"- docs/setup.md version: {setup_version}")
    print("Update docs/setup.md to match the managed uv version.")
    return 1


def validate_local_version(expected: str) -> int:
    """Ensure local uv CLI version matches the managed version."""
    local_version = get_local_uv_version()
    if local_version == expected:
        return 0

    print("uv sync check failed: local uv version is out of sync.")
    print(f"- expected: {expected}")
    print(f"- local: {local_version}")
    print("Upgrade/reinstall uv and verify with: uv --version")
    return 1


def main() -> int:
    """Validate managed, documented, and local uv versions are fully aligned."""
    lint_version, pytest_version, docker_version, setup_version = (
        read_managed_versions()
    )

    alignment_status, expected = validate_managed_alignment(
        lint_version, pytest_version, docker_version
    )
    if alignment_status != 0:
        return alignment_status

    if expected is None:
        raise RuntimeError(
            "Expected uv version was not resolved after alignment check."
        )

    setup_status = validate_setup_version(expected, setup_version)
    if setup_status != 0:
        return setup_status

    local_status = validate_local_version(expected)
    if local_status != 0:
        return local_status

    print(f"uv sync check passed: managed/docs/local are all {expected}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as err:
        print(f"uv sync check error: {err}")
        raise SystemExit(2)
