"""
Dash dashboard to display repo audit data from SQLite.

Usage:
    python dashboard/main.py
    python dashboard/main.py --db /path/to/repo_audit.db

Then open http://localhost:8050 in your browser.
"""

import os
import sys

import dash

# Add project root to path so `core.*` and `dashboard.*` are importable.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import dashboard.utils.data as data_module
from dashboard.layouts.list_repos import generate_layout
from dashboard.utils.data import load_data

app = dash.Dash(__name__, suppress_callback_exceptions=True)

# Importing the callbacks module registers all @callback decorators against the
# Dash app created above. The import must come after `app` is constructed.
from dashboard.callbacks import list_repos as _list_repos_callbacks  # noqa: F401


def _parse_args() -> str:
    """Parse CLI arguments and return the resolved database path."""
    db_path = os.path.join(PROJECT_ROOT, "internal", "repo_audit.db")
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
