"""
Dash dashboard to display repo audit data from SQLite.

Requires at least one script to have been run to generate data in the database. See the `scripts/` directory for available scripts.

Usage:
    uv run audit-cli --dashboard
    uv run python dashboard/main.py

Then open http://localhost:8050 in your browser.
"""

from core.config import AuditConfig, load_audit_config
from core.dashboard_service import DashboardDataService
from dashboard.app import create_app


def run(config: AuditConfig) -> None:
    """Run the Dash dashboard."""
    dashboard_service = DashboardDataService(config)
    dashboard_service.initialise_data()

    # Create the Dash app
    app = create_app(config, dashboard_service)

    # Start the Dash server
    print(f"\nStarting dashboard at http://localhost:{config.dashboard.port}")
    print("Press Ctrl+C to stop.\n")
    # Run the app with the specified host, debug mode, and port from the configuration
    app.run(host="0.0.0.0", debug=config.dashboard.debug, port=config.dashboard.port)


if __name__ == "__main__":
    # Load the audit configuration
    config = load_audit_config()

    # Run the dashboard with the loaded configuration
    run(config)
