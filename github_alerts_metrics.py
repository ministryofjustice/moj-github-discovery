import os
import csv
import time
import requests
import datetime
import json

TOKEN = os.getenv("GITHUB_TOKEN")
HEADERS = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}

ORG = "ministryofjustice"
BASE = "https://api.github.com"
MAX_ALERTS = 400  # limit total alerts collected


def paged_get(url, params=None):
    params = params or {}
    results = []

    while url:
        r = requests.get(url, headers=HEADERS, params=params)
        if r.status_code == 403:
            print(f"[403] Forbidden: {url}")
            return []
        if r.status_code == 404:
            print(f"[404] Not Found: {url}")
            return []
        r.raise_for_status()

        results.extend(r.json())

        if len(results) >= MAX_ALERTS:
            return results[:MAX_ALERTS]

        url = r.links.get("next", {}).get("url")
        params = None

    return results


def list_repos(org):
    return paged_get(f"{BASE}/orgs/{org}/repos", {"per_page": 100})


def fetch_code_scanning_alerts(owner, repo):
    return paged_get(
        f"{BASE}/repos/{owner}/{repo}/code-scanning/alerts", {"per_page": 100}
    )


def fetch_dependabot_alerts(owner, repo):
    return paged_get(
        f"{BASE}/repos/{owner}/{repo}/dependabot/alerts", {"per_page": 100}
    )


def fetch_secret_scanning_alerts(owner, repo):
    return paged_get(
        f"{BASE}/repos/{owner}/{repo}/secret-scanning/alerts", {"per_page": 100}
    )


def iso_to_dt(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def get_severity(a, kind):
    if kind == "dependabot":
        return a.get("security_advisory", {"severity": "not_found"}).get(
            "severity", "not_found"
        )
    elif kind == "code_scanning":
        return a.get("rule", {"security_severity_level": "not_found"}).get(
            "security_severity_level", "not_found"
        )
    elif kind == "secret_scanning":
        return "critical"
    else:
        raise ValueError(f"Unknown alert kind: {kind}")


def process_alerts(alerts, repo, kind):
    rows = []
    for a in alerts:
        created = iso_to_dt(a.get("created_at"))
        dismissed = iso_to_dt(a.get("dismissed_at"))
        fixed = iso_to_dt(a.get("fixed_at"))
        remediation_date = fixed or dismissed

        ttr = None
        if created and remediation_date:
            ttr = (remediation_date - created).days
        with open(f"data_{kind}.json", "w") as f:
            json.dump(a, f)
            BREAK_NOW = True

        rows.append(
            {
                "id": a.get("number") or a.get("id"),
                "type": kind,
                "repo": repo,
                "created_at": created.isoformat() if created else "",
                "remediated_at": remediation_date.isoformat()
                if remediation_date
                else "",
                "state": a.get("state"),
                "severity": get_severity(a, kind),
                "ttr_days": ttr,
            }
        )

        if len(rows) >= MAX_ALERTS:
            break

    return rows


def main():
    repos = list_repos(ORG)

    grouped = {}  # NEW: alerts grouped by repository
    total_count = 0

    for r in repos:
        if total_count >= MAX_ALERTS:
            break

        owner = r["owner"]["login"]
        name = r["name"]
        repo_full = f"{owner}/{name}"

        print(f"Scanning {repo_full}...")

        grouped.setdefault(repo_full, [])

        try:
            alerts = []
            alerts += process_alerts(
                fetch_code_scanning_alerts(owner, name), repo_full, "code_scanning"
            )
            alerts += process_alerts(
                fetch_dependabot_alerts(owner, name), repo_full, "dependabot"
            )
            alerts += process_alerts(
                fetch_secret_scanning_alerts(owner, name), repo_full, "secret_scanning"
            )

            # Trim if adding these would exceed MAX_ALERTS
            remaining = MAX_ALERTS - total_count
            alerts = alerts[:remaining]

            grouped[repo_full].extend(alerts)
            total_count += len(alerts)

        except Exception as e:
            print(f"Skipping {repo_full} due to error: {e}")

        time.sleep(0.3)

    # Flatten grouped structure for CSV output
    flat = []
    for repo, alerts in grouped.items():
        flat.extend(alerts)

    # Write CSV
    if flat:
        with open("github_alerts_limited.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(flat[0].keys()))
            writer.writeheader()
            writer.writerows(flat)

    print(f"\nDone! Wrote {len(flat)} alerts to github_alerts_limited.csv")
    print(f"Grouped by {len(grouped)} repositories.")


if __name__ == "__main__":
    main()
