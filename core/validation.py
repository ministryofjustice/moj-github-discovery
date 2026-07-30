"""Validation helpers shared across audit scripts."""

from __future__ import annotations

import sys
from pathlib import Path


def direct_invocation_guard(script_path: str) -> None:
    """Exit with guidance when an audit script is executed directly.

    Audit scripts are library modules dispatched by ``main.py``. Executing one
    directly never calls ``run()``, so the process would otherwise exit silently
    with no output. Call from an ``if __name__ == "__main__"`` block.
    """
    script_name = Path(script_path).stem
    print(
        "Error: Scripts must be run via audit-cli or main.py.\n"
        f"Run: uv run audit-cli --scripts {script_name} --auth app",
        file=sys.stderr,
    )
    sys.exit(1)
