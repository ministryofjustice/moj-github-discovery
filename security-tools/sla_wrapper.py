import csv
import sys
from datetime import UTC, datetime

# SLA thresholds in days
SLA = {
    "critical": 7,
    "high": 14,
    "medium": 30,
    "low": 90,
}

CSV_FILE = "github_alerts_limited.csv"


def parse_dt(value):
    return datetime.fromisoformat(value) if value else None


def main():
    breaches = []
    warnings = []

    with open(CSV_FILE) as f:
        reader = csv.DictReader(f)
        for row in reader:
            severity = row["severity"]
            created = parse_dt(row["created_at"])
            state = row["state"]

            if state != "open":
                continue

            if severity not in SLA:
                continue

            age_days = (datetime.now(UTC) - created).days

            if age_days > SLA[severity]:
                breaches.append((row["repo"], severity, age_days))
            else:
                warnings.append((row["repo"], severity, age_days))

    if breaches:
        print("::error:: SLA BREACHES DETECTED")
        for repo, sev, age in breaches:
            print(f"::error::{repo} — {sev} alert open for {age} days")
        sys.exit(1)

    if warnings:
        print("::warning:: Alerts found but within SLA")
        for repo, sev, age in warnings:
            print(f"::warning::{repo} — {sev} alert open for {age} days")

    print("No SLA breaches. Passing.")
    sys.exit(0)


if __name__ == "__main__":
    main()
