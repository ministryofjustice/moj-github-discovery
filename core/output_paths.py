"""Path resolver for audit script outputs and internal caches.

All path values originate from AuditConfig loaded from audit_config.yaml.
This module contains no hardcoded paths.
"""

from pathlib import Path

from core.config import AuditConfig


class OutputPathResolver:
    """Construct and create output/internal paths from config-driven values."""

    def __init__(
        self, config: AuditConfig, base_output_dir: str, base_internal_dir: str
    ):
        # Roots come from main.py, derived from config values.
        self.outputs_root = Path(base_output_dir)
        self.internal_root = Path(base_internal_dir)

    def script_output_dir(self, output_subdir: str) -> Path:
        """Return and create outputs/<output_subdir>/."""
        path = self.outputs_root / output_subdir
        path.mkdir(parents=True, exist_ok=True)
        return path

    def script_output_file(self, output_subdir: str, filename: str) -> Path:
        """Return outputs/<output_subdir>/<filename>, creating dir if needed."""
        return self.script_output_dir(output_subdir) / filename

    def database_path(self, db_path: str) -> Path:
        """Return resolved path for a database file.

        If db_path is already relative to internal_root (for example
        internal/audit.db), strip that prefix to avoid double-rooting.
        Absolute paths pass through unchanged.
        """
        path = Path(db_path)
        if path.is_absolute():
            return path

        relative = path
        internal_root_name = self.internal_root.name
        if path.parts and path.parts[0] == internal_root_name:
            relative = Path(*path.parts[1:])

        result = self.internal_root / relative
        result.parent.mkdir(parents=True, exist_ok=True)
        return result
