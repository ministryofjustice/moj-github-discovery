#!/usr/bin/env python3
"""Pandas-based viewer for repo audit data backed by core storage."""

import argparse
import os
import sys

import pandas as pd

from core.presenters import build_dashboard_dataframe
from core.storage import SqliteRepoStorage


def load_data(db_path: str) -> pd.DataFrame:
    """Load repo audit data from core storage and map it for CLI viewing."""
    storage = SqliteRepoStorage(db_path)
    storage.init()
    df = build_dashboard_dataframe(storage)
    if df.empty:
        return df
    return df.rename(
        columns={
            "secret_alerts": "secrets",
            "code_scanning_alerts": "code_scan",
            "dependabot_alerts": "dependabot",
            "branch_protected": "branch_protected",
        }
    )


def parse_filter(filter_str: str) -> tuple:
    """Parse filter string like 'column:value' into (column, value)."""
    if ":" not in filter_str:
        print(
            f"Invalid filter format: {filter_str}. Use 'column:value'", file=sys.stderr
        )
        sys.exit(1)
    column, value = filter_str.split(":", 1)
    return column.strip(), value.strip()


def apply_filters(df: pd.DataFrame, filters: list) -> pd.DataFrame:
    """Apply filters to dataframe."""
    for column, value in filters:
        if column not in df.columns:
            print(f"Column not found: {column}", file=sys.stderr)
            continue

        # Handle boolean values
        if value.lower() in ("true", "yes"):
            df = df[df[column].fillna(False)]
        elif value.lower() in ("false", "no"):
            df = df[~df[column].fillna(False)]
        else:
            # Try numeric comparison
            try:
                num_val = float(value)
                df = df[df[column] == num_val]
            except ValueError:
                # String match (case-insensitive)
                df = df[
                    df[column].astype(str).str.contains(value, case=False, na=False)
                ]

    return df


def main():
    parser = argparse.ArgumentParser(
        description="View repo audit data from core storage."
    )
    parser.add_argument("--db", default="repo_audit.db", help="SQLite database path.")
    parser.add_argument(
        "--filter",
        action="append",
        default=[],
        help="Filter in the form column:value. May be passed multiple times.",
    )
    parser.add_argument("--sort", help="Column to sort by descending.")
    parser.add_argument("--html", help="Optional HTML output path.")
    args = parser.parse_args()

    db_path = args.db
    filters = [parse_filter(raw) for raw in args.filter]
    sort_column = args.sort
    html_output = args.html

    # Use default location if not specified
    if not os.path.exists(db_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(script_dir, "repo_audit.db")

    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading data from {db_path}", file=sys.stderr)

    # Load and process data
    df = load_data(db_path)

    if df.empty:
        print("No data found in database", file=sys.stderr)
        sys.exit(1)

    # Apply filters
    if filters:
        df = apply_filters(df, filters)

    # Sort if requested
    if sort_column:
        if sort_column not in df.columns:
            print(f"Column not found for sorting: {sort_column}", file=sys.stderr)
            sys.exit(1)
        df = df.sort_values(by=sort_column, ascending=False, na_position="last")

    # Display summary
    print(f"\nTotal repositories: {len(df)}", file=sys.stderr)
    print(f"Public: {(~df['private'].fillna(False)).sum()}", file=sys.stderr)
    print(f"Private: {(df['private']).sum()}", file=sys.stderr)
    print(f"Archived: {df['archived'].fillna(False).sum()}", file=sys.stderr)
    print(
        f"With flagged issues: {((df['flags'] != '') & (df['flags'].notna())).sum()}\n",
        file=sys.stderr,
    )

    # Format display columns
    display_df = df[
        [
            "repo",
            "private",
            "language",
            "stars",
            "open_issues",
            "dependabot",
            "secrets",
            "code_scan",
            "branch_protected",
            "flags",
        ]
    ].copy()

    # Replace NaN with dash
    display_df = display_df.fillna("—")

    # Format boolean columns
    display_df["private"] = display_df["private"].apply(
        lambda x: "Private" if x is True else ("Public" if x is False else "—")
    )
    display_df["branch_protected"] = display_df["branch_protected"].apply(
        lambda x: "✓" if x is True else ("✗" if x is False else "?")
    )

    # Rename columns for display
    display_df = display_df.rename(
        columns={
            "dependabot": "Dependabot",
            "secrets": "Secrets",
            "code_scan": "Code Scan",
            "branch_protected": "Protected",
        }
    )

    # Set pandas display options
    pd.set_option("display.max_columns", None)
    pd.set_option("display.max_colwidth", None)
    pd.set_option("display.width", None)
    cols_to_shorten = ["flags", "language"]
    for col in cols_to_shorten:
        if col in display_df.columns:
            display_df[col] = display_df[col].astype(str).str[:50]

    # Print table to terminal
    print(display_df.to_string(index=False))

    # Export to HTML if requested
    if html_output:
        html_content = display_df.to_html(index=False, escape=False)

        # Wrap with styling
        full_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Repository Audit</title>
    <style>
        body {{ fontFamily: Arial, sans-serif; margin: 20px; backgroundColor: #f8f9fa; }}
        h1 {{ color: #333; }}
        .summary {{ marginBottom: 20px; padding: 15px; backgroundColor: #e7f3ff; borderRadius: 5px; }}
        table {{ borderCollapse: collapse; width: 100%; backgroundColor: white; boxShadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ backgroundColor: #f8f9fa; borderBottom: 2px solid #ddd; padding: 10px; textAlign: left; fontWeight: bold; }}
        td {{ borderBottom: 1px solid #eee; padding: 8px; }}
        tr:hover {{ backgroundColor: #f5f5f5; }}
        .flag {{ color: #d9534f; fontWeight: bold; }}
        .ok {{ color: #28a745; }}
    </style>
</head>
<body>
    <h1>Repository Audit Dashboard</h1>
    <div class="summary">
        <p><strong>Total repositories:</strong> {len(df)}</p>
        <p><strong>Public:</strong> {(~df["private"].fillna(False)).sum()} | <strong>Private:</strong> {(df["private"].fillna(False)).sum()} | <strong>Archived:</strong> {df["archived"].fillna(False).sum()}</p>
    </div>
    {html_content}
</body>
</html>"""

        with open(html_output, "w") as f:
            f.write(full_html)
        print(f"\nHTML exported to {html_output}", file=sys.stderr)


if __name__ == "__main__":
    main()
