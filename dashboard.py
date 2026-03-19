#!/usr/bin/env python3
"""
Minimal Dash dashboard to display repo audit data from SQLite.

Usage:
  python dashboard.py

Then open http://localhost:8050 in your browser.

To run with a custom database path:
  python dashboard.py --db /path/to/repo_audit.db
"""

import json
import os
import sqlite3
import subprocess
import sys

import dash
from dash import dcc, html, callback, Input, Output, State, ALL, callback_context
import pandas as pd

# Parse arguments
db_path = "repo_audit.db"
if "--db" in sys.argv:
    idx = sys.argv.index("--db")
    if idx + 1 < len(sys.argv):
        db_path = sys.argv[idx + 1]

# Use default location next to this script if not specified
if not os.path.exists(db_path):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(script_dir, "repo_audit.db")

if not os.path.exists(db_path):
    print(f"Error: Database not found at {db_path}")
    sys.exit(1)

print(f"Loading data from {db_path}")


def load_data():
    """Load repo audit data from SQLite."""
    conn = sqlite3.connect(db_path)
    query = "SELECT full_name, audit_json FROM repo_rows"
    df = pd.read_sql_query(query, conn)
    conn.close()

    # Parse JSON - repo_rows has flat structure (not nested)
    rows = []
    for _, row in df.iterrows():
        try:
            data = json.loads(row["audit_json"])

            rows.append(
                {
                    "repo": data.get("full_name", row["full_name"]),
                    "private": data.get("private"),
                    "archived": data.get("archived"),
                    "fork": data.get("fork"),
                    "language": data.get("language"),
                    "stars": data.get("stargazers", 0),
                    "open_issues": data.get("open_issues", 0),
                    "dependabot_alerts": data.get("dependabot_alerts"),
                    "secret_alerts": data.get("secret_scanning_alerts"),
                    "code_scanning_alerts": data.get("code_scanning_alerts"),
                    "branch_protected": data.get("default_branch_protected"),
                    "codeowners": data.get("codeowners"),
                    "flags": data.get("flags", ""),
                    "pushed_at": data.get("pushed_at", ""),
                }
            )
        except Exception as e:
            print(f"Error parsing {row['full_name']}: {e}")
            continue

    return pd.DataFrame(rows)


def load_audit_data(full_name: str) -> dict:
    """Load detailed audit data from the audits table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT audit_json FROM audits WHERE full_name = ?", (full_name,))
    row = cursor.fetchone()
    conn.close()

    if row:
        try:
            return json.loads(row[0])
        except Exception as e:
            print(f"There was a problem loading audit data: {e}")
            return None
    return None


def run_audit(full_name: str) -> dict:
    """Run audit_repo.py for the given repository."""
    try:
        script_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "audit_repo.py"
        )
        result = subprocess.run(
            [sys.executable, script_path, full_name, "--db", db_path],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode == 0:
            # Extract JSON from stdout (last line should be the JSON)
            lines = result.stdout.strip().split("\n")
            for line in reversed(lines):
                if line.strip().startswith("{"):
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError as e:
                        return {"error": f"Invalid JSON from audit: {str(e)}"}
            return {"error": "No JSON output found from audit script"}
        else:
            stderr_msg = result.stderr.strip() if result.stderr else "Unknown error"
            return {"error": f"Audit script failed: {stderr_msg}"}
    except subprocess.TimeoutExpired:
        return {"error": "Audit timed out (exceeded 120 seconds)"}
    except Exception as e:
        return {"error": f"Failed to run audit: {str(e)}"}


# Initialize app
app = dash.Dash(__name__, suppress_callback_exceptions=True)
df = load_data()


# Define color functions
def get_flag_color(flag_str):
    """Color badge based on flags."""
    if not flag_str:
        return {"backgroundColor": "#28a745", "color": "white"}
    else:
        return {"backgroundColor": "#dc3545", "color": "white"}


# Layout
app.layout = html.Div(
    [
        dcc.Store(
            id="data-store", data=df.to_json(orient="records", date_format="iso")
        ),
        dcc.Store(id="selected-repo-store", data=None),
        dcc.Store(id="audit-data-store", data=None),
        html.Div(
            [
                html.H1("Repository Audit Dashboard", style={"marginBottom": "20px"}),
                html.P(
                    f"Total repositories: {len(df)}",
                    style={"fontSize": "16px", "color": "#666"},
                ),
            ],
            style={
                "padding": "20px",
                "backgroundColor": "#f8f9fa",
                "borderRadius": "8px",
                "marginBottom": "20px",
            },
        ),
        # Filter section
        html.Div(
            [
                html.Div(
                    [
                        html.Label("Search repo name:", style={"fontWeight": "bold"}),
                        dcc.Input(
                            id="repo-filter",
                            type="text",
                            placeholder="Filter by repo name...",
                            style={
                                "width": "100%",
                                "padding": "8px",
                                "marginTop": "5px",
                                "border": "1px solid #ddd",
                                "borderRadius": "4px",
                            },
                        ),
                    ],
                    style={"marginBottom": "15px"},
                ),
                html.Div(
                    [
                        html.Label(
                            "Show only repos with flags:", style={"fontWeight": "bold"}
                        ),
                        dcc.Checklist(
                            id="flag-filter",
                            options=[
                                {
                                    "label": " Yes (show only flagged)",
                                    "value": "flagged",
                                }
                            ],
                            value=[],
                            style={"marginTop": "5px"},
                        ),
                    ],
                    style={"marginBottom": "15px"},
                ),
            ],
            style={
                "padding": "15px",
                "backgroundColor": "#fff",
                "border": "1px solid #ddd",
                "borderRadius": "4px",
                "marginBottom": "20px",
            },
        ),
        # Main content with table and side panel
        html.Div(
            [
                html.Div(
                    [
                        dcc.Loading(
                            id="loading",
                            type="default",
                            children=html.Div(id="table-container"),
                        )
                    ],
                    style={"flex": "1", "marginRight": "20px", "overflowX": "auto"},
                ),
                # Side panel for details
                html.Div(
                    id="detail-panel",
                    style={
                        "width": "350px",
                        "backgroundColor": "#f8f9fa",
                        "border": "1px solid #ddd",
                        "borderRadius": "4px",
                        "padding": "15px",
                        "overflowY": "auto",
                        "maxHeight": "700px",
                        "display": "none",
                    },
                ),
            ],
            style={"display": "flex", "gap": "20px"},
        ),
    ],
    style={
        "maxWidth": "1600px",
        "margin": "0 auto",
        "padding": "20px",
        "fontFamily": "Arial, sans-serif",
        "backgroundColor": "#ffffff",
    },
)


@callback(
    Output("table-container", "children"),
    Input("repo-filter", "value"),
    Input("flag-filter", "value"),
    Input("data-store", "data"),
)
def update_table(search, flag_filter, data):
    # Parse the JSON string from the store
    if isinstance(data, str):
        records = json.loads(data)
    else:
        records = data
    ddf = pd.DataFrame(records)

    # Apply filters
    if search:
        ddf = ddf[ddf["repo"].str.contains(search, case=False, na=False)]

    if "flagged" in flag_filter:
        ddf = ddf[ddf["flags"].notna() & (ddf["flags"] != "")]

    # Create table rows with click handlers
    table_rows = [
        html.Tr(
            [
                html.Th(
                    "Repository",
                    style={
                        "padding": "10px",
                        "textAlign": "left",
                        "backgroundColor": "#f8f9fa",
                    },
                ),
                html.Th(
                    "Status",
                    style={
                        "padding": "10px",
                        "textAlign": "center",
                        "backgroundColor": "#f8f9fa",
                    },
                ),
                html.Th(
                    "Language",
                    style={
                        "padding": "10px",
                        "textAlign": "left",
                        "backgroundColor": "#f8f9fa",
                    },
                ),
                html.Th(
                    "Stars",
                    style={
                        "padding": "10px",
                        "textAlign": "center",
                        "backgroundColor": "#f8f9fa",
                    },
                ),
                html.Th(
                    "Open Issues",
                    style={
                        "padding": "10px",
                        "textAlign": "center",
                        "backgroundColor": "#f8f9fa",
                    },
                ),
                html.Th(
                    "Dependabot",
                    style={
                        "padding": "10px",
                        "textAlign": "center",
                        "backgroundColor": "#f8f9fa",
                    },
                ),
                html.Th(
                    "Branch Protected",
                    style={
                        "padding": "10px",
                        "textAlign": "center",
                        "backgroundColor": "#f8f9fa",
                    },
                ),
                html.Th(
                    "Flags",
                    style={
                        "padding": "10px",
                        "textAlign": "left",
                        "backgroundColor": "#f8f9fa",
                        "maxWidth": "300px",
                    },
                ),
            ],
            style={"borderBottom": "2px solid #ddd"},
        )
    ]

    for _, row in ddf.iterrows():
        flags_display = row["flags"] if row["flags"] else "✓ OK"
        flag_color = get_flag_color(row["flags"])

        table_rows.append(
            html.Tr(
                [
                    html.Td(
                        row["repo"], style={"padding": "10px", "fontWeight": "bold"}
                    ),
                    html.Td(
                        "Private" if row["private"] else "Public",
                        style={
                            "padding": "10px",
                            "textAlign": "center",
                            "color": "#666",
                        },
                    ),
                    html.Td(row["language"] or "—", style={"padding": "10px"}),
                    html.Td(
                        str(row["stars"]),
                        style={"padding": "10px", "textAlign": "center"},
                    ),
                    html.Td(
                        str(row["open_issues"]),
                        style={"padding": "10px", "textAlign": "center"},
                    ),
                    html.Td(
                        (
                            str(row["dependabot_alerts"])
                            if pd.notna(row["dependabot_alerts"])
                            else "—"
                        ),
                        style={
                            "padding": "10px",
                            "textAlign": "center",
                            "color": (
                                "red"
                                if (
                                    pd.notna(row["dependabot_alerts"])
                                    and row["dependabot_alerts"] > 0
                                )
                                else "green"
                            ),
                        },
                    ),
                    html.Td(
                        "✓" if row["branch_protected"] else "✗",
                        style={
                            "padding": "10px",
                            "textAlign": "center",
                            "color": "green" if row["branch_protected"] else "red",
                            "fontWeight": "bold",
                        },
                    ),
                    html.Td(
                        html.Span(
                            flags_display,
                            style={
                                **flag_color,
                                "padding": "4px 8px",
                                "borderRadius": "4px",
                                "fontSize": "12px",
                                "display": "inline-block",
                                "wordWrap": "break-word",
                            },
                        ),
                        style={
                            "padding": "10px",
                            "maxWidth": "300px",
                            "wordBreak": "break-word",
                        },
                    ),
                ],
                id={"type": "repo-row", "index": row["repo"]},
                style={
                    "borderBottom": "1px solid #eee",
                    "backgroundColor": "#fafafa",
                    "cursor": "pointer",
                },
                n_clicks=0,
            )
        )

    return html.Table(
        table_rows,
        style={
            "width": "100%",
            "borderCollapse": "collapse",
            "border": "1px solid #ddd",
            "borderRadius": "4px",
            "overflow": "hidden",
        },
    )


def format_audit_detail(audit_data: dict) -> html.Div:
    """Format audit data for display in detail panel."""
    if not audit_data or "error" in audit_data:
        return html.Div(
            [
                html.H4("Error", style={"color": "red"}),
                html.P(
                    audit_data.get("error", "Unknown error")
                    if audit_data
                    else "No data"
                ),
            ]
        )

    repo = audit_data.get("repo", {})
    alerts = audit_data.get("alerts", {})
    community = audit_data.get("community", {})
    workflows = audit_data.get("workflows", {})
    workflow_analysis = audit_data.get("workflow_analysis", {})
    flags = audit_data.get("flags", [])

    community_files = community.get("files", {})

    sections = [
        html.H3(
            repo.get("name", "Unknown"),
            style={
                "marginBottom": "15px",
                "borderBottom": "2px solid #ddd",
                "paddingBottom": "10px",
            },
        ),
    ]

    # General info
    sections.append(
        html.Div(
            [
                html.H4(
                    "Repository Info",
                    style={
                        "marginTop": "15px",
                        "marginBottom": "10px",
                        "color": "#333",
                    },
                ),
                html.Div(
                    [
                        html.P(
                            f"Name: {repo.get('full_name', 'N/A')}",
                            style={"margin": "5px 0"},
                        ),
                        html.P(
                            f"URL: {repo.get('html_url', 'N/A')}",
                            style={"margin": "5px 0"},
                        ),
                        html.P(
                            f"Private: {'Yes' if repo.get('private') else 'No'}",
                            style={"margin": "5px 0"},
                        ),
                        html.P(
                            f"Fork: {'Yes' if repo.get('fork') else 'No'}",
                            style={"margin": "5px 0"},
                        ),
                        html.P(
                            f"License: {repo.get('license') or 'None'}",
                            style={"margin": "5px 0"},
                        ),
                    ],
                    style={"fontSize": "13px", "color": "#666"},
                ),
            ]
        )
    )

    # Alerts
    sections.append(
        html.Div(
            [
                html.H4(
                    "Security Alerts",
                    style={
                        "marginTop": "15px",
                        "marginBottom": "10px",
                        "color": "#333",
                    },
                ),
                html.Div(
                    [
                        html.P(
                            f"Dependabot: {alerts.get('dependabot_alerts', 'N/A')}",
                            style={"margin": "5px 0"},
                        ),
                        html.P(
                            f"Secret Scanning: {alerts.get('secret_scanning_alerts', 'N/A')}",
                            style={"margin": "5px 0"},
                        ),
                        html.P(
                            f"Code Scanning: {alerts.get('code_scanning_alerts', 'N/A')}",
                            style={"margin": "5px 0"},
                        ),
                    ],
                    style={"fontSize": "13px", "color": "#666"},
                ),
            ]
        )
    )

    # Community
    sections.append(
        html.Div(
            [
                html.H4(
                    "Community Files",
                    style={
                        "marginTop": "15px",
                        "marginBottom": "10px",
                        "color": "#333",
                    },
                ),
                html.Div(
                    [
                        html.P(
                            f"Security Policy: {'✓' if community_files.get('security_policy') else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": (
                                    "green"
                                    if community_files.get("security_policy")
                                    else "red"
                                ),
                            },
                        ),
                        html.P(
                            f"Code of Conduct: {'✓' if community_files.get('code_of_conduct') else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": (
                                    "green"
                                    if community_files.get("code_of_conduct")
                                    else "red"
                                ),
                            },
                        ),
                        html.P(
                            f"Contributing: {'✓' if community_files.get('contributing') else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": (
                                    "green"
                                    if community_files.get("contributing")
                                    else "red"
                                ),
                            },
                        ),
                    ],
                    style={"fontSize": "13px", "color": "#666"},
                ),
            ]
        )
    )

    # Workflows
    if workflows.get("count", 0) > 0:
        sections.append(
            html.Div(
                [
                    html.H4(
                        "CI/CD",
                        style={
                            "marginTop": "15px",
                            "marginBottom": "10px",
                            "color": "#333",
                        },
                    ),
                    html.Div(
                        [
                            html.P(
                                f"Workflows: {workflows.get('count', 0)}",
                                style={"margin": "5px 0"},
                            ),
                            html.P(
                                f"Has Tests: {'✓' if workflow_analysis.get('has_tests') else '✗'}",
                                style={
                                    "margin": "5px 0",
                                    "color": (
                                        "green"
                                        if workflow_analysis.get("has_tests")
                                        else "red"
                                    ),
                                },
                            ),
                            html.P(
                                f"Has Linting: {'✓' if workflow_analysis.get('has_linting') else '✗'}",
                                style={
                                    "margin": "5px 0",
                                    "color": (
                                        "green"
                                        if workflow_analysis.get("has_linting")
                                        else "red"
                                    ),
                                },
                            ),
                        ],
                        style={"fontSize": "13px", "color": "#666"},
                    ),
                ]
            )
        )

    # Flags
    if flags:
        sections.append(
            html.Div(
                [
                    html.H4(
                        "Flags",
                        style={
                            "marginTop": "15px",
                            "marginBottom": "10px",
                            "color": "#d9534f",
                        },
                    ),
                    html.Div(
                        [
                            html.Div(
                                flag,
                                style={
                                    "backgroundColor": "#f5f5f5",
                                    "border": "1px solid #ddd",
                                    "padding": "5px 8px",
                                    "borderRadius": "3px",
                                    "fontSize": "12px",
                                    "marginBottom": "5px",
                                },
                            )
                            for flag in flags
                        ],
                        style={"fontSize": "13px"},
                    ),
                ]
            )
        )

    return html.Div(sections)


@callback(
    Output("detail-panel", "children"),
    Output("detail-panel", "style"),
    Input("selected-repo-store", "data"),
    Input("audit-data-store", "data"),
)
def update_detail_panel(selected_repo, audit_data):
    if not selected_repo:
        return None, {"display": "none"}

    panel_style = {
        "width": "350px",
        "backgroundColor": "#f8f9fa",
        "border": "1px solid #ddd",
        "borderRadius": "4px",
        "padding": "15px",
        "overflowY": "auto",
        "maxHeight": "700px",
        "display": "block",
    }

    # Try to get audit data from store first, then from database
    if audit_data:
        # audit_data comes from dcc.Store - it's already parsed as dict by Dash
        if isinstance(audit_data, str):
            try:
                audit_data = json.loads(audit_data)
            except Exception as e:
                print(f"There was an issue loading audit data: {e}", file=sys.stderr)
                audit_data = None

    if not audit_data:
        # Load audit data from database
        audit_data = load_audit_data(selected_repo)

    if audit_data:
        content = format_audit_detail(audit_data)
    else:
        # Show button to run audit
        content = html.Div(
            [
                html.H3(
                    selected_repo,
                    style={
                        "marginBottom": "15px",
                        "borderBottom": "2px solid #ddd",
                        "paddingBottom": "10px",
                    },
                ),
                html.P(
                    "No detailed audit data available for this repository.",
                    style={"color": "#666", "marginBottom": "15px"},
                ),
                html.Button(
                    "Run Audit",
                    id="run-audit-btn",
                    n_clicks=0,
                    style={
                        "width": "100%",
                        "padding": "10px",
                        "backgroundColor": "#007bff",
                        "color": "white",
                        "border": "none",
                        "borderRadius": "4px",
                        "cursor": "pointer",
                        "fontSize": "14px",
                        "fontWeight": "bold",
                    },
                ),
                html.Div(
                    id="audit-status", style={"marginTop": "15px", "fontSize": "13px"}
                ),
            ]
        )

    return content, panel_style


@callback(
    Output("selected-repo-store", "data"),
    Input({"type": "repo-row", "index": ALL}, "n_clicks"),
    State("selected-repo-store", "data"),
    prevent_initial_call=True,
)
def on_row_click(n_clicks, current_selected):
    if not n_clicks or not any(n_clicks):
        return current_selected

    # Find which row was clicked (the one with the highest n_clicks that's new)
    ctx = callback_context
    if not ctx.triggered:
        return current_selected

    triggered_id = ctx.triggered[0]["prop_id"].split(".")[0]
    if triggered_id:
        import json as json_lib

        trigger_dict = json_lib.loads(triggered_id)
        selected = trigger_dict.get("index")
        return selected

    return current_selected


@callback(
    Output("audit-data-store", "data"),
    Output("audit-status", "children"),
    Input("run-audit-btn", "n_clicks"),
    State("selected-repo-store", "data"),
    prevent_initial_call=True,
)
def on_audit_click(n_clicks, repo_name):
    if n_clicks == 0 or not repo_name:
        return None, ""

    status_div = html.Div(
        [dcc.Loading(type="default", children=html.Div("Running audit..."))]
    )

    audit_result = run_audit(repo_name)

    if "error" in audit_result:
        return audit_result, html.Div(
            [html.P(f"Error: {audit_result['error']}", style={"color": "red"})]
        )

    return audit_result, html.Div(
        [html.P("✓ Audit completed successfully!", style={"color": "green"})]
    )


if __name__ == "__main__":
    print("\nStarting dashboard at http://localhost:8050")
    print("Press Ctrl+C to stop.\n")
    app.run(debug=True, port=8050)
