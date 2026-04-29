import pandas as pd

# Load the CSV file containing GitHub alert data
df = pd.read_csv("github_alerts_limited.csv")

# Normalise column names:
# - strip whitespace
# - convert to lowercase
# This prevents KeyErrors if the CSV has inconsistent formatting
df.columns = df.columns.str.strip().str.lower()

# Define which alert states count as "closed"
closed_states = ["resolved", "fixed"]

# --- High‑level counts ---
print("Total alerts:", len(df))
print("Open alerts:", len(df[df["state"] == "open"]))
print("Closed alerts:", len(df[df["state"].isin(closed_states)]))

# --- Severity breakdown ---
print("\nAlerts by severity:")
print(df["severity"].value_counts())

# --- Type breakdown ---
print("\nAlerts by type:")
print(df["type"].value_counts())

# --- Time‑to‑Remediate (TTR) statistics ---
# Assumes the CSV includes a numeric column `ttr_days`
print("\nAverage TTR:", df["ttr_days"].mean())
print("Max TTR:", df["ttr_days"].max())
print("Min TTR:", df["ttr_days"].min())

# --- Open alerts by severity ---
print("\nOpen alerts by severity:")
print(df[df["state"] == "open"]["severity"].value_counts())

# --- Combined grouping: severity + type ---
# This helps identify patterns, e.g. which severity/type combinations are most common
print("\nGrouped by severity + type:")
print(df.groupby(["severity", "type"]).size())
