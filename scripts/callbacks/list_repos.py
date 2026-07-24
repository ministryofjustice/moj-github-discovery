"""Dash callbacks for the repository-list dashboard view."""

from __future__ import annotations

import json
import math
import sys

import pandas as pd
from dash import ALL, Input, Output, State, callback, callback_context, html
from dashboard_utils.constants import DEFAULT_PAGE_SIZE, get_flag_color
from dashboard_utils.data import _load_repo_audit_result
from layouts.list_repos import format_audit_detail

# ---------------------------------------------------------------------------
# Table + pagination
# ---------------------------------------------------------------------------


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
    records = json.loads(data) if isinstance(data, str) else data
    ddf = pd.DataFrame(records)

    if search:
        ddf = ddf[ddf["repo"].str.contains(search, case=False, na=False)]

    if flag_filter:
        mask = ddf["flags"].apply(
            lambda f: any(flag in f.split(", ") for flag in flag_filter) if f else False
        )
        ddf = ddf[mask]

    page_size = page_size or DEFAULT_PAGE_SIZE
    total_repos = len(ddf)
    total_pages = max(1, math.ceil(total_repos / page_size))
    page = max(1, min(page or 1, total_pages))
    page_ddf = ddf.iloc[(page - 1) * page_size : page * page_size]
    page_info = f"Page {page} of {total_pages}  ({total_repos} repos)"

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
                                if pd.notna(row["dependabot_alerts"])
                                and row["dependabot_alerts"] > 0
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
    ctx = callback_context
    if not ctx.triggered:
        return current_page or 1

    trigger = ctx.triggered[0]["prop_id"]
    current_page = current_page or 1

    if "first-page-btn" in trigger:
        return 1
    if "prev-page-btn" in trigger:
        return max(1, current_page - 1)
    if "next-page-btn" in trigger or "last-page-btn" in trigger:
        records = json.loads(data) if isinstance(data, str) else data
        ddf = pd.DataFrame(records)

        if search:
            ddf = ddf[ddf["repo"].str.contains(search, case=False, na=False)]
        if flag_filter:
            mask = ddf["flags"].apply(
                lambda f: (
                    any(flag in f.split(", ") for flag in flag_filter) if f else False
                )
            )
            ddf = ddf[mask]
        page_size = page_size_input or DEFAULT_PAGE_SIZE
        total_pages = max(1, math.ceil(len(ddf) / page_size))
        return (
            min(current_page + 1, total_pages)
            if "next-page-btn" in trigger
            else total_pages
        )
    # Filter or page-size changed — reset to page 1
    return 1


@callback(
    Output("page-size-store", "data"),
    Input("page-size-dropdown", "value"),
    prevent_initial_call=False,
)
def update_page_size(page_size_value):
    """Update the page size store when the dropdown changes."""
    return page_size_value or DEFAULT_PAGE_SIZE


# ---------------------------------------------------------------------------
# Modal
# ---------------------------------------------------------------------------


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

    if audit_data and isinstance(audit_data, str):
        try:
            audit_data = json.loads(audit_data)
        except Exception as exc:
            print(f"There was an issue loading audit data: {exc}", file=sys.stderr)
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
    return


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

    ctx = callback_context
    if not ctx.triggered:
        return current_selected

    triggered_id = ctx.triggered[0]["prop_id"].split(".")[0]
    if triggered_id:
        trigger_dict = json.loads(triggered_id)
        return trigger_dict.get("index")

    return current_selected
