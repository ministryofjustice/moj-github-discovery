"""Shared constants and small utilities for the dashboard."""

FLAG_FILTER_OPTIONS = [
    {"label": " archived", "value": "archived"},
    {"label": " empty_repo_no_push_activity", "value": "empty_repo_no_push_activity"},
    {"label": " fork", "value": "fork"},
    {"label": " no_license", "value": "no_license"},
    {
        "label": " public_unprotected_default_branch",
        "value": "public_unprotected_default_branch",
    },
    {
        "label": " branch_protection_not_enforced",
        "value": "branch_protection_not_enforced",
    },
    {"label": " no_actions_workflows", "value": "no_actions_workflows"},
    {"label": " no_detected_tests", "value": "no_detected_tests"},
    {"label": " no_detected_linting", "value": "no_detected_linting"},
]


def get_flag_color(flag_str: str) -> dict:
    """Return a CSS colour dict for a flag badge based on whether flags are present."""
    if not flag_str:
        return {"backgroundColor": "#28a745", "color": "white"}
    return {"backgroundColor": "#dc3545", "color": "white"}
