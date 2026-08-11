"""Shared constants and small utilities for the dashboard."""

FLAG_FILTER_OPTIONS = [
    {"label": " Archived", "value": "archived"},
    {"label": " Empty Repo: No Push Activity", "value": "empty_repo_no_push_activity"},
    {"label": " Forked Repository", "value": "fork"},
    {"label": " No License", "value": "no_license"},
    {
        "label": " Public Unprotected Default Branch",
        "value": "public_unprotected_default_branch",
    },
    {
        "label": " Branch Protection Not Enforced",
        "value": "branch_protection_not_enforced",
    },
    {"label": " No Actions Workflows", "value": "no_actions_workflows"},
    {"label": " No Detected Tests", "value": "no_detected_tests"},
    {"label": " No Detected Linting", "value": "no_detected_linting"},
]


def get_flag_color(flag_str: str) -> dict:
    """Return a CSS colour dict for a flag badge based on whether flags are present."""
    if not flag_str:
        return {"backgroundColor": "#28a745", "color": "white"}
    return {"backgroundColor": "#dc3545", "color": "white"}


def safe_component_id(component_id: str) -> str:
    """Return a safe component ID by replacing dots with underscores and slashes with hyphens."""
    return component_id.replace(".", "_").replace("/", "-")
