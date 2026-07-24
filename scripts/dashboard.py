"""
Dash dashboard to display repo audit data from SQLite.

Usage:
  python scripts/dashboard.py
  python scripts/dashboard.py --db /path/to/repo_audit.db

Then open http://localhost:8050 in your browser.
"""

import os
import sys

import dash

# Add project root to path so `core.*` and dashboard sub-packages are importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dashboard_utils.data as data_module
from dashboard_utils.data import load_data
from layouts.list_repos import generate_layout

app = dash.Dash(__name__, suppress_callback_exceptions=True)

# Importing the callbacks module registers all @callback decorators against the
# Dash app created above. The import must come after `app` is constructed.


def _parse_args() -> str:
    """Parse CLI arguments and return the resolved database path."""
    db_path = "internal/repo_audit.db"
    if "--db" in sys.argv:
        idx = sys.argv.index("--db")
        if idx + 1 >= len(sys.argv):
            print("Error: --db requires a path argument")
            sys.exit(2)
        db_path = sys.argv[idx + 1]

    # Fall back to a db alongside this script.
    if not os.path.exists(db_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(script_dir, "repo_audit.db")

    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}")
        sys.exit(1)

    print(f"Loading data from {db_path}")
    return db_path


if __name__ == "__main__":
    data_module.db_path = _parse_args()
    df = load_data()
    app.layout = generate_layout(df)
    print("\nStarting dashboard at http://localhost:8050")
    print("Press Ctrl+C to stop.\n")
    app.run(debug=True, port=8050)
