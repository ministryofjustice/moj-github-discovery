"""Shared constants and small utilities for the dashboard."""

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


def get_flag_color(flag_str: str) -> dict:
    """Return a CSS colour dict for a flag badge based on whether flags are present."""
    if not flag_str:
        return {"backgroundColor": "#28a745", "color": "white"}
    return {"backgroundColor": "#dc3545", "color": "white"}
