import dash
from dash import dcc, html

from core.config import AuditConfig
from dashboard.utils.data import get_available_sources


def create_app(config: AuditConfig) -> dash.Dash:
    """Create and Configure the Dash App Instance"""
    app = dash.Dash(
        __name__,
        use_pages=True,
        pages_folder="",
        suppress_callback_exceptions=True,
    )

    # Import Layouts After App instantiation to ensure page registration works correctly
    from dashboard.callbacks import list_repos as _list_repos_callbacks  # noqa: F401
    from dashboard.layouts import list_repos  # noqa: F401

    sources = get_available_sources(config)

    # Empty Nav List - Add Links for Available Sources
    nav_items = []
    # Iterate through Sources and Add Links to Nav Items if Available
    if sources.get("list_repos"):
        nav_items.append(dcc.Link("Repository Compliance", href="/"))
    if sources.get("archive_repos"):
        nav_items.append(dcc.Link("Archival Candidacy", href="/archive_repos"))
    if sources.get("alert_metrics"):
        nav_items.append(dcc.Link("Alert Metrics", href="/alert_metrics"))
    if sources.get("lfs"):
        nav_items.append(dcc.Link("LFS Usage", href="/lfs"))
    if sources.get("org_security_posture"):
        nav_items.append(dcc.Link("Org Security Posture", href="/org_security_posture"))
    if sources.get("github_workflow"):
        nav_items.append(dcc.Link("GitHub Workflow", href="/github_workflow"))

    # Construct the app layout with a navigation bar and page container for dynamic content
    app.layout = html.Div([html.Nav(nav_items), dash.page_container])

    return app
