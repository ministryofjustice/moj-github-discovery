import argparse
import atexit
import os
import sys
import time
from pathlib import Path

from core.config import AuditConfig, load_audit_config

from scripts import (
    alert_metrics,
    archive_repos,
    github_workflow,
    list_repos,
    lfs_script,
    org_security_posture,
)

# Constants

section_break = "\n" + ("=" * 80) + "\n"
sub_section_break = "\n" + ("-" * 80) + "\n"

# Script registry - maps script names to their modules (each exposing a `run()` function)
SCRIPTS = {
    "alert_metrics": alert_metrics,
    "archive_repos": archive_repos,
    "github_workflow": github_workflow,
    "list_repos": list_repos,
    "lfs_script": lfs_script,
    "org_security_posture": org_security_posture,
}

__start_time: float | None = None


# Setup Base Directories for Script Outputs
def base_directory_setup(config: AuditConfig) -> tuple[str, str]:
    """Configure base directories for outputs and internal files.

    Directories are fixed to 'outputs' and 'internal' relative to project root.
    """

    # Fixed directory names - do not override
    base_output_dir = "outputs"
    base_internal_dir = "internal"

    # Ensure base output directories exist
    for directory in (base_output_dir, base_internal_dir):
        os.makedirs(directory, exist_ok=True)

    return base_output_dir, base_internal_dir


def _report_elapsed() -> None:
    """Report elapsed time since script start on exit."""
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)


atexit.register(_report_elapsed)


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Unified entrypoint for running one or more GitHub audit scripts using the shared YAML config."
        )
    )
    parser.add_argument(
        "--scripts",
        nargs="+",
        choices=list(SCRIPTS.keys()),
        metavar="SCRIPT",
        help=f"One or more scripts to run. Choices: {', '.join(SCRIPTS.keys())}.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all scripts sequentially. Overrides --scripts if both provided.",
    )
    parser.add_argument(
        "--config-file",
        default=None,
        type=Path,
        help="Path to audit config YAML. Defaults to config/audit_config.yaml.",
    )
    parser.add_argument(
        "--auth",
        choices=["pat", "app", "cli"],
        default=None,
        help="Select GitHub authentication method explicitly",
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="Optionally specify a single repository to target in the format owner/repo. This only applies to the alert_metrics.py script for now.",
    )
    parser.add_argument(
        "--repos",
        nargs="+",
        help="Specific repos to scan, e.g. owner/repo owner/repo. Only applies to github_workflow.py for now.",
    )
    return parser.parse_args(argv)


def main(argv=None) -> None:

    global __start_time
    __start_time = time.monotonic()

    args = _parse_args(argv)

    # Global Script Argument Validation
    if not args.scripts and not args.all:
        print(
            "Please specify a script to run with --scripts <name> [name ...] or use --all to run all scripts.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Script-Specific Argument Validation
    if args.repo and "org_security_posture" in (args.scripts or []) and not args.all:
        print(
            "The --repo argument does not apply to org_security_posture. "
            "This script operates at org level and does not support single repo targeting.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.repos and "org_security_posture" in (args.scripts or []) and not args.all:
        print(
            "The --repos argument does not apply to org_security_posture. ",
            "This script operates at org level and does not support multiple repo targeting.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Load Config File - Defaults to config/audit_config.yaml if not specified
    config: AuditConfig = load_audit_config(args.config_file)

    scripts_to_run = (
        SCRIPTS if args.all else {name: SCRIPTS[name] for name in args.scripts}
    )

    print(
        f"{section_break}\nScripts selected for execution: \n{', '.join(scripts_to_run.keys())}{section_break}",
        file=sys.stderr,
    )

    script_results = {}

    base_output_dir, base_internal_dir = base_directory_setup(config)

    print(f"Base output directory: {base_output_dir}", file=sys.stderr)
    print(f"Base internal directory: {base_internal_dir}", file=sys.stderr)

    # Iterate through selected scripts and execute them sequentially,
    # passing the global config and any relevant CLI args

    for name, script in scripts_to_run.items():
        print(
            f"{section_break}\nStarting script: {name}\n{section_break}",
            file=sys.stderr,
        )
        try:
            # Prepare kwargs for scripts that require specific CLI args
            kwargs = {}
            if args.repo and name != "org_security_posture":
                kwargs["repo"] = args.repo
            if args.repos and name != "org_security_posture":
                kwargs["repos"] = args.repos
            # Pass the global config, auth method, base directories, and any script-specific kwargs
            # to the script's run function
            script.run(
                config,
                args.auth,
                base_output_dir=base_output_dir,
                base_internal_dir=base_internal_dir,
                **kwargs,
            )
            script_results[name] = "Success"
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
            print(f"Script {name} exited with code {code}", file=sys.stderr)
            script_results[name] = f"Failed (exit {code})"
        except Exception as exc:
            print(
                f"Script {name} failed with an unhandled exception: {exc!r}",
                file=sys.stderr,
            )
            script_results[name] = "Failed (exception)"

    # Summary of script results
    print(
        f"{section_break}\nScript execution summary:\n{section_break}", file=sys.stderr
    )
    for name, result in script_results.items():
        print(f"{name}: {result}", file=sys.stderr)

    print(f"{section_break}\nAll scripts completed.\n{section_break}", file=sys.stderr)

    if not all(result == "Success" for result in script_results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
