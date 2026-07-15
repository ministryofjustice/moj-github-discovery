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
import sys

import math

import dash
from dash import dcc, html, callback, Input, Output, State, ALL, callback_context
import pandas as pd

# add project root to path for core imports
# TODO: Remove once pyproject.toml is build-system configured
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.presenters import (
    build_dashboard_dataframe,
    repo_data_to_audit_result,
)
from core.storage import SqliteRepoStorage

# Module-level storage for db_path and df (set in if __name__ == "__main__")
db_path = None
df = None
app = dash.Dash(__name__, suppress_callback_exceptions=True)


def _parse_args() -> str:
    """Parse CLI arguments and return the resolved database path."""
    db_path = "internal/repo_audit.db"
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
    return db_path


def _get_storage() -> SqliteRepoStorage:
    """Get a storage instance for the SQLite database."""
    storage = SqliteRepoStorage(db_path)
    storage.init()
    return storage


def load_data():
    """Load repo summary data from core storage."""
    storage = _get_storage()
    return build_dashboard_dataframe(storage)


def _load_repo_audit_result(full_name: str) -> dict | None:
    """Load a single repo's audit result from core storage."""
    storage = _get_storage()
    repo_data = storage.read(full_name)
    if repo_data is None:
        return None
    return repo_data_to_audit_result(repo_data)


# Define color functions
def get_flag_color(flag_str):
    """Color badge based on flags."""
    if not flag_str:
        return {"backgroundColor": "#28a745", "color": "white"}
    else:
        return {"backgroundColor": "#dc3545", "color": "white"}


FLAG_FILTER_OPTIONS = [
    {"label": " archived", "value": "archived"},
    {"label": " fork", "value": "fork"},
    {"label": " no_license", "value": "no_license"},
    {
        "label": " public_unprotected_default_branch",
        "value": "public_unprotected_default_branch",
    },
    {"label": " dependabot_alerts_present", "value": "dependabot_alerts_present"},
    {"label": " secret_alerts_present", "value": "secret_alerts_present"},
    {"label": " code_scanning_alerts_present", "value": "code_scanning_alerts_present"},
    {"label": " no_security_policy", "value": "no_security_policy"},
    {"label": " no_code_of_conduct", "value": "no_code_of_conduct"},
    {"label": " no_actions_workflows", "value": "no_actions_workflows"},
    {"label": " no_detected_tests", "value": "no_detected_tests"},
    {"label": " no_detected_linting", "value": "no_detected_linting"},
]

PAGE_SIZE_OPTIONS = [10, 20, 50]
DEFAULT_PAGE_SIZE = 20


def render_header() -> html.Div:
    """Render the dashboard header."""
    return html.Div(
        [html.H1("Repository Audit Dashboard", style={"marginBottom": "0px"})],
        style={
            "padding": "20px",
            "backgroundColor": "#f8f9fa",
            "borderRadius": "8px",
            "marginBottom": "10px",
        },
    )


def render_summary(data: pd.DataFrame) -> html.Div:
    """Render repository count summary stats."""
    total = len(data)
    no_flags = int((data["flags"].isna() | (data["flags"] == "")).sum())
    has_flags = total - no_flags

    stat_style = {
        "display": "inline-block",
        "padding": "10px 20px",
        "marginRight": "15px",
        "backgroundColor": "#fff",
        "border": "1px solid #ddd",
        "borderRadius": "6px",
        "textAlign": "center",
        "minWidth": "160px",
    }
    label_style = {"fontSize": "12px", "color": "#888", "marginBottom": "4px"}
    value_style = {"fontSize": "24px", "fontWeight": "bold"}

    return html.Div(
        [
            html.Div(
                [
                    html.Div("Total Repositories", style=label_style),
                    html.Div(str(total), style=value_style),
                ],
                style=stat_style,
            ),
            html.Div(
                [
                    html.Div("No Flags", style=label_style),
                    html.Div(str(no_flags), style={**value_style, "color": "#28a745"}),
                ],
                style=stat_style,
            ),
            html.Div(
                [
                    html.Div("Flagged", style=label_style),
                    html.Div(str(has_flags), style={**value_style, "color": "#dc3545"}),
                ],
                style=stat_style,
            ),
        ],
        style={"padding": "15px 0", "marginBottom": "10px"},
    )


def render_filters() -> html.Div:
    """Render the search and flag filter controls."""
    return html.Div(
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
                        "Repos per page:",
                        style={
                            "fontWeight": "bold",
                            "marginBottom": "4px",
                            "display": "inline-block",
                            "marginRight": "8px",
                        },
                    ),
                    dcc.Dropdown(
                        id="page-size-dropdown",
                        options=[
                            {"label": str(size), "value": size}
                            for size in PAGE_SIZE_OPTIONS
                        ],
                        value=DEFAULT_PAGE_SIZE,
                        clearable=False,
                        searchable=False,
                        style={"width": "80px", "display": "inline-block"},
                    ),
                ],
                style={"marginBottom": "15px"},
            ),
            html.Div(
                [
                    html.Label(
                        "Filter by flag (show repos with any selected flag):",
                        style={
                            "fontWeight": "bold",
                            "marginBottom": "8px",
                            "display": "block",
                        },
                    ),
                    dcc.Checklist(
                        id="flag-filter",
                        options=FLAG_FILTER_OPTIONS,
                        value=[],
                        labelStyle={
                            "display": "block",
                            "marginBottom": "4px",
                            "fontSize": "13px",
                        },
                        style={
                            "marginTop": "5px",
                            "columnCount": "2",
                            "columnGap": "20px",
                        },
                    ),
                ],
            ),
        ],
        style={
            "padding": "15px",
            "backgroundColor": "#fff",
            "border": "1px solid #ddd",
            "borderRadius": "4px",
            "marginBottom": "20px",
        },
    )


def render_main_content() -> html.Div:
    """Render the main content area: repo table with pagination controls."""
    btn_style = {
        "padding": "6px 16px",
        "border": "1px solid #ddd",
        "borderRadius": "4px",
        "backgroundColor": "#fff",
        "cursor": "pointer",
        "fontSize": "14px",
    }
    return html.Div(
        [
            dcc.Loading(
                id="loading",
                type="default",
                children=html.Div(id="table-container"),
            ),
            html.Div(
                [
                    html.Button(
                        "⟨⟨ First",
                        id="first-page-btn",
                        n_clicks=0,
                        disabled=True,
                        style=btn_style,
                    ),
                    html.Button(
                        "← Prev",
                        id="prev-page-btn",
                        n_clicks=0,
                        disabled=True,
                        style={**btn_style, "marginLeft": "4px"},
                    ),
                    html.Span(
                        id="page-info",
                        style={"fontSize": "14px", "color": "#555", "margin": "0 14px"},
                    ),
                    html.Button(
                        "Next →",
                        id="next-page-btn",
                        n_clicks=0,
                        disabled=False,
                        style={**btn_style, "marginRight": "4px"},
                    ),
                    html.Button(
                        "Last ⟩⟩",
                        id="last-page-btn",
                        n_clicks=0,
                        disabled=False,
                        style=btn_style,
                    ),
                ],
                style={
                    "display": "flex",
                    "alignItems": "center",
                    "justifyContent": "center",
                    "padding": "14px 0",
                    "marginTop": "8px",
                },
            ),
        ],
    )


def render_modal() -> html.Div:
    """Render the fixed-position modal overlay for repo detail."""
    return html.Div(
        id="modal-overlay",
        style={"display": "none"},
        children=[
            # Backdrop
            html.Div(
                style={
                    "position": "fixed",
                    "top": 0,
                    "left": 0,
                    "right": 0,
                    "bottom": 0,
                    "backgroundColor": "rgba(0,0,0,0.5)",
                    "zIndex": 1000,
                },
            ),
            # Dialog
            html.Div(
                style={
                    "position": "fixed",
                    "top": "5%",
                    "left": "50%",
                    "transform": "translateX(-50%)",
                    "width": "640px",
                    "maxWidth": "92vw",
                    "maxHeight": "85vh",
                    "overflowY": "auto",
                    "backgroundColor": "#fff",
                    "borderRadius": "8px",
                    "padding": "28px 24px 24px",
                    "zIndex": 1001,
                    "boxShadow": "0 8px 32px rgba(0,0,0,0.25)",
                },
                children=[
                    html.Button(
                        "✕",
                        id="modal-close-btn",
                        n_clicks=0,
                        style={
                            "position": "absolute",
                            "top": "12px",
                            "right": "16px",
                            "background": "none",
                            "border": "none",
                            "fontSize": "20px",
                            "cursor": "pointer",
                            "color": "#666",
                            "lineHeight": "1",
                            "padding": "0",
                        },
                    ),
                    html.Div(id="modal-body"),
                ],
            ),
        ],
    )


def generate_layout(data: pd.DataFrame) -> html.Div:
    """Compose the full dashboard layout."""
    return html.Div(
        [
            dcc.Store(
                id="data-store", data=data.to_json(orient="records", date_format="iso")
            ),
            dcc.Store(id="selected-repo-store", data=None),
            dcc.Store(id="audit-data-store", data=None),
            dcc.Store(id="page-store", data=1),
            dcc.Store(id="page-size-store", data=DEFAULT_PAGE_SIZE),
            render_modal(),
            render_header(),
            render_summary(data),
            render_filters(),
            render_main_content(),
        ],
        style={
            "maxWidth": "1600px",
            "margin": "0 auto",
            "padding": "20px",
            "fontFamily": "Arial, sans-serif",
            "backgroundColor": "#ffffff",
        },
    )


# Callbacks
@callback(
    Output("table-container", "children"),
    Output("page-info", "children"),
    Output("first-page-btn", "disabled"),
    Output("prev-page-btn", "disabled"),
    Output("next-page-btn", "disabled"),
    Output("last-page-btn", "disabled"),
    Input("repo-filter", "value"),
    Input("flag-filter", "value"),
    Input("page-store", "data"),
    Input("page-size-store", "data"),
    Input("data-store", "data"),
)
def update_table(search, flag_filter, page, page_size, data):
    """Update the table based on search, flag filters, page, and page size."""
    if isinstance(data, str):
        records = json.loads(data)
    else:
        records = data
    ddf = pd.DataFrame(records)

    # Apply filters
    if search:
        ddf = ddf[ddf["repo"].str.contains(search, case=False, na=False)]

    if flag_filter:
        mask = ddf["flags"].apply(
            lambda f: any(flag in f.split(", ") for flag in flag_filter) if f else False
        )
        ddf = ddf[mask]

    # Pagination
    page_size = page_size or DEFAULT_PAGE_SIZE
    total_repos = len(ddf)
    total_pages = max(1, math.ceil(total_repos / page_size))
    page = max(1, min(page or 1, total_pages))
    page_ddf = ddf.iloc[(page - 1) * page_size : page * page_size]
    page_info = f"Page {page} of {total_pages}  ({total_repos} repos)"

    # Build table header
    th_left = {"padding": "10px", "textAlign": "left", "backgroundColor": "#f8f9fa"}
    th_center = {"padding": "10px", "textAlign": "center", "backgroundColor": "#f8f9fa"}
    table_rows = [
        html.Tr(
            [
                html.Th("Repository", style=th_left),
                html.Th("Status", style=th_center),
                html.Th("Language", style=th_left),
                html.Th("Stars", style=th_center),
                html.Th("Open Issues", style=th_center),
                html.Th("Dependabot", style=th_center),
                html.Th("Branch Protected", style=th_center),
                html.Th("Flags", style={**th_left, "maxWidth": "300px"}),
            ],
            style={"borderBottom": "2px solid #ddd"},
        )
    ]

    for _, row in page_ddf.iterrows():
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

    table = html.Table(
        table_rows,
        style={
            "width": "100%",
            "borderCollapse": "collapse",
            "border": "1px solid #ddd",
            "borderRadius": "4px",
            "overflow": "hidden",
        },
    )
    at_first = page <= 1
    at_last = page >= total_pages
    return table, page_info, at_first, at_first, at_last, at_last


@callback(
    Output("page-store", "data"),
    Input("first-page-btn", "n_clicks"),
    Input("prev-page-btn", "n_clicks"),
    Input("next-page-btn", "n_clicks"),
    Input("last-page-btn", "n_clicks"),
    Input("repo-filter", "value"),
    Input("flag-filter", "value"),
    Input("page-size-dropdown", "value"),
    State("page-store", "data"),
    State("page-size-store", "data"),
    State("data-store", "data"),
    prevent_initial_call=True,
)
def update_page(
    first_clicks,
    prev_clicks,
    next_clicks,
    last_clicks,
    search,
    flag_filter,
    page_size_input,
    current_page,
    page_size_store,
    data,
):
    """Navigate pages or reset to page 1 when filters change."""
    # First, update page-size-store if page size changed
    ctx = callback_context
    if not ctx.triggered:
        return current_page or 1

    trigger = ctx.triggered[0]["prop_id"]
    current_page = current_page or 1

    # Handle page navigation
    if "first-page-btn" in trigger:
        return 1
    if "prev-page-btn" in trigger:
        return max(1, current_page - 1)
    if "next-page-btn" in trigger:
        # Calculate total pages to check if we can go forward
        if isinstance(data, str):
            records = json.loads(data)
        else:
            records = data
        ddf = pd.DataFrame(records)
        page_size = page_size_input or DEFAULT_PAGE_SIZE
        total_pages = max(1, math.ceil(len(ddf) / page_size))
        return min(current_page + 1, total_pages)
    if "last-page-btn" in trigger:
        # Calculate total pages
        if isinstance(data, str):
            records = json.loads(data)
        else:
            records = data
        ddf = pd.DataFrame(records)
        page_size = page_size_input or DEFAULT_PAGE_SIZE
        total_pages = max(1, math.ceil(len(ddf) / page_size))
        return total_pages
    # Filter changed — reset to page 1
    return 1


@callback(
    Output("page-size-store", "data"),
    Input("page-size-dropdown", "value"),
    prevent_initial_call=False,
)
def update_page_size(page_size_value):
    """Update the page size store when the dropdown changes."""
    return page_size_value or DEFAULT_PAGE_SIZE


def format_audit_detail(audit_data: dict, repo_name: str = "Unknown") -> html.Div:
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

    repo = audit_data.get("repo") or {}
    alerts = audit_data.get("alerts") or {}
    community = audit_data.get("community") or {}
    workflows = audit_data.get("workflows") or {}
    workflow_analysis = audit_data.get("workflow_analysis") or {}
    branch_protection = audit_data.get("branch_protection") or {}
    repo_rulesets = audit_data.get("repo_rulesets") or {}
    codeowners = audit_data.get("codeowners") or {}
    flags = audit_data.get("flags", [])

    community_files = community.get("files") or {}

    sections = [
        html.H3(
            repo_name,
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
                            f"Name: {repo_name}",
                            style={"margin": "5px 0"},
                        ),
                        # html.P(
                        #     f"URL: {repo.get('html_url', 'N/A')}",
                        #     style={"margin": "5px 0"},
                        # ),
                        html.P(
                            f"Private: {'Yes' if repo.get('private') else 'No'}",
                            style={"margin": "5px 0"},
                        ),
                        html.P(
                            f"Fork: {'Yes' if repo.get('fork') else 'No'}",
                            style={"margin": "5px 0"},
                        ),
                        html.P(
                            f"License: {(repo.get('license') or {}).get('name', 'None')}",
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
                        html.P(
                            f"CODEOWNERS: {'✓' if codeowners.get('present') else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": (
                                    "green" if codeowners.get("present") else "red"
                                ),
                            },
                        ),
                    ],
                    style={"fontSize": "13px", "color": "#666"},
                ),
            ]
        )
    )

    # Default Branch Protection
    # Determine which protection data to use based on compliance method
    compliance_method = "none"
    protection_data = {}
    if branch_protection.get("branch_protection_enabled"):
        compliance_method = "branch_protection"
        protection_data = branch_protection
    elif repo_rulesets.get("has_active_rulesets"):
        compliance_method = "rulesets"
        protection_data = repo_rulesets

    # Extract fields from whichever protection method is active
    default_branch_protected = (
        protection_data.get("default_branch_protected")
        if compliance_method == "branch_protection"
        else repo_rulesets.get("has_active_rulesets")
    )
    enforce_admins = (
        protection_data.get("enforce_admins_enabled")
        if compliance_method == "branch_protection"
        else protection_data.get("enforce_admins")
    )
    dismiss_stale = protection_data.get("dismiss_stale_reviews", False)
    require_codeowner = protection_data.get("require_code_owner_reviews", False)
    review_count = protection_data.get("required_approving_review_count", 0)
    require_signatures = (
        protection_data.get("required_signatures_enabled")
        if compliance_method == "branch_protection"
        else protection_data.get("required_signatures")
    )

    sections.append(
        html.Div(
            [
                html.H4(
                    "Default Branch Protection",
                    style={
                        "marginTop": "15px",
                        "marginBottom": "10px",
                        "color": "#333",
                    },
                ),
                html.Div(
                    [
                        html.P(
                            f"Branch Protected: {'✓' if default_branch_protected else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": (
                                    "green" if default_branch_protected else "red"
                                ),
                            },
                        ),
                        html.P(
                            f"Compliance Method: {compliance_method}",
                            style={"margin": "5px 0"},
                        ),
                        html.P(
                            f"Enforce Admin Protection: {'✓' if enforce_admins else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": ("green" if enforce_admins else "red"),
                            },
                        ),
                        html.P(
                            f"Dismiss Stale Reviews: {'✓' if dismiss_stale else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": ("green" if dismiss_stale else "red"),
                            },
                        ),
                        html.P(
                            f"Require Code Owner Reviews: {'✓' if require_codeowner else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": ("green" if require_codeowner else "red"),
                            },
                        ),
                        html.P(
                            f"Required Approving Review Count: {review_count}",
                            style={
                                "margin": "5px 0",
                                "color": ("green" if review_count > 0 else "red"),
                            },
                        ),
                        html.P(
                            f"Required Signatures: {'✓' if require_signatures else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": ("green" if require_signatures else "red"),
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
    Output("modal-overlay", "style"),
    Output("modal-body", "children"),
    Input("selected-repo-store", "data"),
    Input("audit-data-store", "data"),
)
def update_modal(selected_repo, audit_data):
    """Show or hide the detail modal based on the selected repo."""
    hidden = {"display": "none"}
    visible = {"display": "block"}

    if not selected_repo:
        return hidden, None

    if audit_data:
        if isinstance(audit_data, str):
            try:
                audit_data = json.loads(audit_data)
            except Exception as e:
                print(f"There was an issue loading audit data: {e}", file=sys.stderr)
                audit_data = None

    if not audit_data:
        audit_data = _load_repo_audit_result(selected_repo)

    if audit_data:
        content = format_audit_detail(audit_data, selected_repo)
    else:
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

    return visible, content


@callback(
    Output("selected-repo-store", "data", allow_duplicate=True),
    Input("modal-close-btn", "n_clicks"),
    prevent_initial_call=True,
)
def close_modal(n_clicks):
    """Close the detail modal by clearing the selected repo."""
    return None


@callback(
    Output("selected-repo-store", "data"),
    Input({"type": "repo-row", "index": ALL}, "n_clicks"),
    State("selected-repo-store", "data"),
    prevent_initial_call=True,
)
def on_row_click(n_clicks, current_selected):
    """Determine which repo row was clicked and update the selected repo store."""
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


if __name__ == "__main__":
    """Run the Dash app."""
    db_path = _parse_args()
    df = load_data()
    app.layout = generate_layout(df)
    print("\nStarting dashboard at http://localhost:8050")
    print("Press Ctrl+C to stop.\n")
    app.run(debug=True, port=8050)
