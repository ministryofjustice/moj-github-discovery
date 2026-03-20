#!/usr/bin/env python3

import argparse
import csv
import datetime as dt
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import requests

# Service Catalogue client

def _catalogue_session(token: str) -> requests.Session:
    """Return a requests.Session pre-configured with auth headers."""
    sess = requests.Session()
    sess.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    return sess

def fetch_catalogue_components(
    base_url: str,
    token: str,
    per_page: int = 100,
)->  List[Dict[str, Any]]:
    """
    Fetch ALL components from the Service Catalogue, paginating automatically.
    Uses the /v1/components endpoint.
    """
    sess = _catalogue_session(token)
    components: List[Dict[str, Any]] = []
    page = 1

    while True:
        url = f"{base_url}/v1/components?page={page}&per_page={per_page}"
        try:
            resp = sess.get(url, timeout=30)
            resp.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            code = exc.response.status if exc.response is not None else None
            print(
                f"ERROR: Catalogue API returned HTTP {code} on page {page}",
                file=sys.stderr,
            )
            if code in (401, 403):
                print(
                    "Check that SERVICE_CATALOGUE_TOKEN is set and valid.",
                    file=sys.stderr,
                )
            break
        except requests.exceptions.RequestException as exc:
            print(f"ERROR: Catalogue request failed: {exc}", file=sys.stderr)
            break

        body = resp.json()

        # Strapi v4 wraps results in {"data": [...], "meta": {...}}
        data = body.get("data", body)
        if isinstance(data, list):
            if not data:
                break
            components.extend(data)
        else:
            # single object or unexpected shape - stop
            break

        # Check pagination metadata
        meta = body.get("meta", {})
        pagination = meta.get("pagination", {})
        total_pages = pagination.get("pageCount", 1)

        if page > total_pages:
            break
        page += 1
    
    print(
        f"Fetched {len(components)} components from the Service Catalogue.",
        file=sys.stderr,
    )
    return components

# ----------------------------------------------------------------------------------------------------------------------
# CSV reader
# ----------------------------------------------------------------------------------------------------------------------

def load_repo_summary(path: str) -> List[Dict[str, str]]:
    """Load the repo summary CSV produced by alerts_metrics.py."""
    if not os.path.isfile(path):
        raise SystemExit(f"Repo summary file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader)

# ----------------------------------------------------------------------------------------------------------------------
# Matching logic
# ----------------------------------------------------------------------------------------------------------------------

def _normalise_repo_name(name: str) -> str:
    """
    Strip owner prefix and lowercase for matching.
    'ministryofjustice/hmpps-tier' -> 'hmpps-tier'
    """
    if "/" in name:
        return name.split("/", 1)[1].strip().lower()
    return name.strip().lower()

def cross_reference(
    fetch_catalogue_components: List[Dict[str, Any]],
    audit_rows: List[Dict[str, str]],
)->  Dict[str, List[Dict[str, Any]]]:
    """
    Match catalogue components to audit rows by repo name.
    Return dict with keys: 'matched', 'audit_only', 'catalogue_only'.
    """

    #  Build lookup from catalogue:  normalised github_repo -> component
    cat_by_repo: Dict[str, Dict[str, Any]] = {}
    for comp in catalogue_components:
        github_repo = (comp.get("github_repo") or "").strip()
        if github_repo:
            cat_by_repo[github_repo.lower()] = comp

    # Build lookup from audit: normalised repo_name -> row
    audit_by_repo: Dict[str, Dict[str, str]] = {}
    for row in audit_rows:
        repo_name = _normalise_repo_name(row.get("repo", "") or row.get("repo_name", ""))
        if repo_name:
            audit_by_repo[repo_name] = row

    cat_keys = set(cat_by_repo.keys())
    audit_keys = set(audit_by_repo.keys())

    matched_keys = cat_keys & audit_keys
    audit_only_keys = audit_keys - cat_keys
    catalogue_only_keys = catkeys - audit_keys

    # Build matched rows - combined audit + catalogue fields
    matched = []
    for key in sorted(matched_keys):
        audit_row = audit_by_repo[key]
        cat_comp = cat_by_repo[key]
        merged = {
            "repo_name": key,
            "full_name": audit_row.get("repo", ""),
            # Audit fields
            "visibility": audit_row.get("visibility", ""),
            "archived": audit_row.get("archived", ""),
            "default_branch_protected": audit_row.get("default_branch_protected", ""),
            "codeowners_present": audit_row.get("codeowners_present", ""),
            "code_scanning_access": audit_row.get("code_scanning_access", ""),
            "code_scanning_alerts": audit_row.get("code_scanning_alerts", ""),
            "dependabot_access": audit_row.get("dependabot_access", ""),
            "dependabot_alerts": audit_row.get("dependabot_alerts", ""),
            "secret_scanning_access": audit_row.get("secret_scanning_access", ""),
            "secret_scanning_alerts": audit_row.get("secret_scanning_alerts", ""),
            "open_alerts_rows": audit_row.get("open_alert_rows", ""),
            "risk_score": audit_row.get("risk_score", ""),
            # Catalogue fields
            "catalogue_id": cat_comp.get("id", ""),
            "catalogue_name": cat_comp.get("name", ""),
            "catalogue_description": (cat_comp.get("description") or  "")[:120],
            "catalogue_frontend": cat_comp.get("frontend", ""),
            "catalogue_api": cat_comp.get("api", ""),
            "catalogue_part_of_monorepo": cat_comp.get("part_of_monorepo", ""),
            "catalogue_github_visibility": cat_comp.get("github_project_visibility", ""),
            # Catalogue security posture
            "cat_branch_protection_signed": cat_comp.get("branch_protection_signed", ""),
            "cat_dismiss_stale_reviews": cat_comp.get("pull_dismiss_stale_reviews", ""),
            "cat_secret_scanning_push_protection": cat_comp.get("secret_scanning_push_protection", ""),
            "cat_code_owner_review": cat_comp.get("branch_protection_code_owner_review", ""),
        }

        # Extract codescanning_summary counts if present
        cs_summary = cat_comp.get("codescanning_summary") or {}
        cs_counts = cs_summary.get("counts") or {}
        merged["cat_codescan_high"] = cs_count.get("HIGH", 0)
        merged["cat_codescan_medium"] = cs_counts.get("MEDIUM", 0)
        merged["cat_codescan_critical"] = cs_counts.get("CRITICAL", 0)

        matched.append(merged)

    # Audit-only rows
    audit_only = []
    for key in sorted(audit_only_keys):
        row = audit_by_repo[key]
        audit_only.append({
            "repo_name": key,
            "full_name": row.get("repo", ""),
            "visibility": row.get("visibility", ""),
            "archived": row.get("archived", ""),
            "open_alert_rows": row.get("archived", ""),
            "risk_score": row.get("risk_score", ""),
            "code_scanning_alerts": row.get("code_scanning_alerts", ""),
            "dependabot_alerts": row.get("dependabot_alerts", ""),
            "secret_scanning_alerts": row.get("secret_scanning_alerts", ""),
        })
    
    # Catalogue-only components
    catalogue_only = []
    for key in sorted(catalogue_only_keys):
        comp = cat_by_repo[key]
        cs_summary = comp.get("codescanning_summary") or {}
        cs_counts = cs_summary.get("counts") or {}
        catalogue_only.append({
            "repo_name": key,
            "catalogue_id": comp.get("id", ""),
            "catalogue_name": comp.get("name", ""),
            "catalogue_description": (comp.get("description") or "")[:120],
            "catalogue_language": comp.get("language", ""),
            "catalogue_github_visibility": comp.get("github_project_visibility", ""),
            "cat_codescan_high": cs_counts.get("HIGH", 0),
            "cat_codescan_medium": cs_counts.get("MEDIUM", 0),
            "archived": comp.get("archived", False),
        })
    
    return {
        "matched": matched,
        "audit_only": audit_only,
        "catalogue_only": catalogue_only,
    }

# ----------------------------------------------------------------------------------------------------------------------
# CSV writer
# ----------------------------------------------------------------------------------------------------------------------

def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    """Write a list of dicts to a CSV file."""
    if not rows:
        print(f"No rows to write for {path}")
        returned
    fieldnames = list(rows[0].key())
    with open(path, "W", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {path} ({lens(rows)} rows)")


# ----------------------------------------------------------------------------------------------------------------------
# Matching logic
# ----------------------------------------------------------------------------------------------------------------------

def write_summary(
    path: str,
    results: Dict[str, List[Dict[str, Any]]],
    total_catalogue: int,
    total_audit: int,
) -> None:
    """Write a human-readable gap analysis summary."""
    matched = results["matched"]
    audit_only = results["audit_only"]
    catalogue_only = results["catalogue_only"]

    now =  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "=" * 70,
        "SERVICE CATALOGUE x GITHUB AUDIT - GAP ANALYSIS",
        f"Generated: {now}",
        "=" * 70,
        "",
        "COVERAGE OVERVIEW",
        "_" * 40,
        f"  Catalogue components:       {total_catalogue}",
        f"  Audit repos scanned:        {total_audit}",
        f"  Matched (in both):          {len(matched)}",
        f"  Audit-only (not in cat):    {len(audit_only)}",
        f"  Catalogue-only (not scanned): {len(catalogue_only)}",
        "",
        f"  Catalogue coverage rate:    {len(matched)}/{total_audit} = "
        f"{len(matched) / max(total_audit, 1) * 100:.1f}%",
        "",
    ]

    # Highlight hight-risk repo not in catalogue
    high_risk_untracked = [
        r for r in audit_only
        if int(r.get("risk_score") or 0) > 0
    ]
    if high_risk_untracked:
        high_risk_untracked.sort(key=lambda x: -int(x.get("risk_score") or 0))
        lines.append("HIGH-RISK REPOS NOT IN SERVICE CATALOGUE")
        lines.append("-" * 40)
        lines.append(" (These have open alerts but are invisible to the catalogue)")
        lines.append("")
        for r in high_risk_untracked[:20]:
            lines.append(
                f" {r['full_name']:<55} risk_score={r,get('risk_score', '?'):>4} "
                f"open_alerts={r.get('open_alert_rows', '?')}"     
            )
        if len(high_risk_untracked) > 20:
            lines.append(f"  ... and {len(high_risk_untracked) - 20} more")
        lines.append("")

    # Highlight matched repos with open alerts
    matched_with_alerts = [
        r for r in matched
        if int(r.get("open_alert_rows") or 0) > 0     
    ]
    if matched_with_alerts:
        matched_with_alerts.sort(key=lambda x: -int(x.get("risk_score") or 0))
        lines.append("CATALOGUE COMPONENTS WITH OPEN ALERTS")
        lines.append("-" * 40)
        lines.append(" (Known service with unresolved security finsdings)")
        lines.append("")
        for r in matched_with_alerts[:20]:
            lines.append(
                f" {r['full_name']:<55} risk_score={r.get('risk_score', '?'):>4} "
                f"open={r.get('open_alerts_rows', '?')}"
            )
        if len(matched_with_alerts) > 20:
            lines.append(f" ... and {len(matched_with_alerts) - 20} more")
        lines.append("")
    
    # Achived repos still in catalogue
    archived_in_cat = [
        r for r in matched
        if str(r.get("archived", "")).lower() in ("true", "1", "yes")
    ]
    if archived_in_cat:
        lines.append("ARCHIVED REPOS STILL IN CATALOGUE")
        lines.append("-" * 40)
        lines.append(" (Consider removing ro marking inactive)")
        lines.append("")
        for r in archived_in_cat:
            lines.append(f" {r['full_name']}")
        lines.append("")

    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    repot = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"Wrote {path}")

    # Also print to stdout
    print()
    print(report)

# ----------------------------------------------------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------------------------------------------------

def main() -> None:
    parse = argparse.Argumentparser(
        description="Cross-reference Github audit data with the HMPPS Service Catalogue"
    )
    parser.add_argument(
        "--repo-summary",
        required=True,
        help="Path to the repo summary CSV from alerts_metrics.py "
            "(e.g. moj_full_repo_summary.csv)",
    )
    parser.add_argument(
        "--catalogue-url",
        default=os.getenv(
            "SERVICE_CATALOGUE_URL",
            "https://service-catalogue.hmpps.service.justice.gov.uk",
        ),
        help="Base URL of the Service catalogue "
            "(default: env SERVICE_CATALOGUE_URL or the HMPPS instance)",
    )
    parser.add_argument(
        "--out-prefix",
        default="catalogue_crossref",
        help="Prefix for output files (default: catalogue_crossref)"
    )
    args = parser.parse_args()

    if not args.catalogue_token:
        raise SystemExit(
            "No catalogue token provided. "
            "Set SERVICE_CATALOGUE_TOKEN env var or use -- catalogue-token."
        )
    
    # 1. Fetch catalogue components
    print("Fetching components from the Service Catalogue...", file=sys.stderr)
    components = fetch_catalogue_components(args,catalogue_url, args.catalogue_token)
    if not components:
        raise SystemExit("No components returned from the catalogue. Check token/URL.")
    
    # 2. Load audit repo summary
    print(f"Loading audit data from {args.repo_summary}...", file=sys.stderr)
    audit_rows = load_repo_summary(args.repo_summary)
    print(f"Loaded {len(audit_rows)} audit rows.", file=sys.stderr)

    # 3. Cross-reference
    print("Cross-referencing...", file=sys.stderr)
    results = cross_reference(components, audit_rows)

    # 4. write outputs
    prefix = args.out_prefix
    write_csv(f"{prefix}_matched.csv", results["matched"])
    write_csv(f"{prefix}_audit_only.csv", results["audit_only"])
    write_csv(f"{prefix}_catalogue_only.csv", results["catalogue_only"])
    write_summary(
        f"{prefix}_summary.txt", 
        results,
        total_catalogue=len(components),
        total_audit=len(audit_rows),
    )

    print("\nDone.", file=sys.stderr)

    if __name__ == "__main__":
        main()