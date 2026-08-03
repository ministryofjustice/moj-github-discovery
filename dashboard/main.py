"""
Dash dashboard to display repo audit data from SQLite.

Usage:
    python dashboard/main.py
    python dashboard/main.py --db /path/to/repo_audit.db

Then open http://localhost:8050 in your browser.
"""

import os
import sys

# Add project root to path so `core.*` and `dashboard.*` are importable.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from core.config import AuditConfig, load_audit_config
from dashboard.app import create_app
from dashboard.utils.data import initialise_data


def run(config: AuditConfig) -> None:
    """Run the Dash dashboard."""
    # Load data from the database into the global _data dictionary
    initialise_data(config)

    # Create the Dash app
    app = create_app(config)

    # Start the Dash server
    print(f"\nStarting dashboard at http://localhost:{config.dashboard.port}")
    print("Press Ctrl+C to stop.\n")
    app.run(debug=config.dashboard.debug, port=config.dashboard.port)


if __name__ == "__main__":
    # Load the audit configuration
    config = load_audit_config()

    # Run the dashboard with the loaded configuration
    run(config)
