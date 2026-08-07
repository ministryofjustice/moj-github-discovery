import dash
from dash import ALL, Input, Output, dcc, html

from core.config import AuditConfig
from core.dashboard_service import DashboardDataService


def create_app(
    config: AuditConfig, dashboard_service: DashboardDataService
) -> dash.Dash:
    """Create and Configure the Dash App Instance"""
    app = dash.Dash(
        __name__,
        use_pages=True,
        pages_folder="",
        suppress_callback_exceptions=True,
    )
    app.server.config["dashboard_service"] = dashboard_service

    # Import Layouts After App instantiation to ensure page registration works correctly
    from dashboard.callbacks import list_repos as _list_repos_callbacks  # noqa: F401
    from dashboard.layouts import list_repos  # noqa: F401

    sources = dashboard_service.get_available_sources()

    # Empty Nav List - Add Links for Available Sources
    nav_items = []
    nav_paths = []
    link_style = {
        "display": "block",
        "padding": "10px 14px",
        "textAlign": "center",
        "textDecoration": "none",
        "color": "#1f3b57",
        "fontWeight": "600",
        "border": "1px solid #d5dce3",
        "borderRadius": "8px",
        "backgroundColor": "#ffffff",
    }
    active_link_style = {
        **link_style,
        "backgroundColor": "#1f3b57",
        "color": "#ffffff",
        "border": "1px solid #1f3b57",
        "boxShadow": "0 4px 12px rgba(31, 59, 87, 0.25)",
    }

    def add_nav_item(enabled: bool, label: str, path: str) -> None:
        if not enabled:
            return
        nav_paths.append(path)
        nav_items.append(
            dcc.Link(
                label,
                href=path,
                id={"type": "nav-link", "index": path},
                style=link_style,
            )
        )

    # Iterate through Sources and Add Links to Nav Items if Available
    add_nav_item(sources.get("list_repos"), "Repository Compliance", "/")
    add_nav_item(sources.get("archive_repos"), "Archival Candidacy", "/archive_repos")
    add_nav_item(sources.get("alert_metrics"), "Alert Metrics", "/alert_metrics")
    add_nav_item(sources.get("lfs"), "LFS Usage", "/lfs")
    add_nav_item(
        sources.get("org_security_posture"),
        "Org Security Posture",
        "/org_security_posture",
    )
    add_nav_item(sources.get("github_workflow"), "GitHub Workflow", "/github_workflow")

    nav_column_count = max(1, len(nav_items))

    # Construct the app layout with a navigation bar and page container for dynamic content
    app.layout = html.Div(
        [
            dcc.Location(id="nav-url", refresh=False),
            html.Nav(
                nav_items,
                style={
                    "maxWidth": "1600px",
                    "margin": "10px auto 0",
                    "padding": "0 20px",
                    "display": "grid",
                    "gridTemplateColumns": f"repeat({nav_column_count}, minmax(0, 1fr))",
                    "gap": "10px",
                    "boxSizing": "border-box",
                },
            ),
            dash.page_container,
        ]
    )

    @app.callback(
        Output({"type": "nav-link", "index": ALL}, "style"),
        Input("nav-url", "pathname"),
    )
    def style_active_nav(pathname: str):
        current_path = pathname or "/"
        return [
            active_link_style if current_path == nav_path else link_style
            for nav_path in nav_paths
        ]

    return app
