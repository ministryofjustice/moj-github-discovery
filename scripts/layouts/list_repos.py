"""Layout components for the repository-list dashboard view."""

from __future__ import annotations

import pandas as pd
from dash import dcc, html

from dashboard_utils.constants import (
    DEFAULT_PAGE_SIZE,
    FLAG_FILTER_OPTIONS,
    PAGE_SIZE_OPTIONS,
)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


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
                id="data-store",
                data=data.to_json(orient="records", date_format="iso"),
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


# ---------------------------------------------------------------------------
# Detail panel
# ---------------------------------------------------------------------------


def format_audit_detail(audit_data: dict, repo_name: str = "Unknown") -> html.Div:
    """Format audit data for display in the repo detail modal."""
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

    # Repository Info
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
                        html.P(f"Name: {repo_name}", style={"margin": "5px 0"}),
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

    # Security Alerts
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

    # Community Files
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
                                "color": "green"
                                if community_files.get("security_policy")
                                else "red",
                            },
                        ),
                        html.P(
                            f"Code of Conduct: {'✓' if community_files.get('code_of_conduct') else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": "green"
                                if community_files.get("code_of_conduct")
                                else "red",
                            },
                        ),
                        html.P(
                            f"Contributing: {'✓' if community_files.get('contributing') else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": "green"
                                if community_files.get("contributing")
                                else "red",
                            },
                        ),
                        html.P(
                            f"CODEOWNERS: {'✓' if codeowners.get('present') else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": "green"
                                if codeowners.get("present")
                                else "red",
                            },
                        ),
                    ],
                    style={"fontSize": "13px", "color": "#666"},
                ),
            ]
        )
    )

    # Default Branch Protection
    compliance_method = "none"
    protection_data: dict = {}
    if branch_protection.get("branch_protection_enabled"):
        compliance_method = "branch_protection"
        protection_data = branch_protection
    elif repo_rulesets.get("has_active_rulesets"):
        compliance_method = "rulesets"
        protection_data = repo_rulesets

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
                                "color": "green" if default_branch_protected else "red",
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
                                "color": "green" if enforce_admins else "red",
                            },
                        ),
                        html.P(
                            f"Dismiss Stale Reviews: {'✓' if dismiss_stale else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": "green" if dismiss_stale else "red",
                            },
                        ),
                        html.P(
                            f"Require Code Owner Reviews: {'✓' if require_codeowner else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": "green" if require_codeowner else "red",
                            },
                        ),
                        html.P(
                            f"Required Approving Review Count: {review_count}",
                            style={
                                "margin": "5px 0",
                                "color": "green" if review_count > 0 else "red",
                            },
                        ),
                        html.P(
                            f"Required Signatures: {'✓' if require_signatures else '✗'}",
                            style={
                                "margin": "5px 0",
                                "color": "green" if require_signatures else "red",
                            },
                        ),
                    ],
                    style={"fontSize": "13px", "color": "#666"},
                ),
            ]
        )
    )

    # CI/CD
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
                                    "color": "green"
                                    if workflow_analysis.get("has_tests")
                                    else "red",
                                },
                            ),
                            html.P(
                                f"Has Linting: {'✓' if workflow_analysis.get('has_linting') else '✗'}",
                                style={
                                    "margin": "5px 0",
                                    "color": "green"
                                    if workflow_analysis.get("has_linting")
                                    else "red",
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
