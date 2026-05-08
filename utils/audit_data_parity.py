import os
import yaml
import pandas as pd


def load_script_file(file_path, file_type, sheet_name=None):
    """Load a script file (Excel, or CSV) and return its contents."""
    if file_type == "excel":
        result = pd.read_excel(file_path, sheet_name=sheet_name)
        if isinstance(result, dict):
            # If multiple sheets are returned, we can choose the first one or handle as needed
            return next(iter(result.values()))
        return result
    return pd.read_csv(file_path)


def normalize_df(df):
    """Normalize dataframe by replacing Nones with 'N/A'"""
    return df.fillna("N/A").replace({None: "N/A"})


def compare_audit_data(config_path="config/audit_parity_config.yaml"):
    """Compare data between app and PAT outputs for audit script parity."""

    # Load the configuration for comparisons
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    # Iterate through each comparison defined in the config
    for script_name, conf in config["comparisons"].items():
        comparison_level = conf.get(
            "comparison_level", config.get("comparison_level", "full")
        )
        comparison_path = "audit_parity_output"
        if not os.path.exists(comparison_path):
            os.makedirs(comparison_path)
        print(f"Comparing data for {script_name}.py ...")

        # Load PAT and App data files
        pat_df = load_script_file(
            conf["pat_file"], conf["file_type"], conf.get("sheet_name")
        )
        app_df = load_script_file(
            conf["app_file"], conf["file_type"], conf.get("sheet_name")
        )

        # Normalize both dataframes to ensure consistent comparison (e.g., handle None vs 'N/A')
        pat_df = normalize_df(pat_df)
        app_df = normalize_df(app_df)

        # Check if the id_column exists in both dataframes
        id_column = conf["id_column"]
        if id_column not in pat_df.columns or id_column not in app_df.columns:
            print(
                f"Error: '{id_column}' column not found in both files for {script_name}.py"
            )
            continue

        # Verify Consistent ID Column Values
        pat_repos = set(pat_df[id_column])
        app_repos = set(app_df[id_column])

        new_repos = app_repos - pat_repos

        with pd.ExcelWriter(
            f"{comparison_path}/new_repos_{script_name}.xlsx"
        ) as writer:
            # always write repo coverage summary
            repo_coverage_summary = (
                pd.DataFrame({"repo": sorted(new_repos)})
                if new_repos
                else pd.DataFrame({"repo": ["No coverage differences found"]})
            )
            repo_coverage_summary.to_excel(
                writer, sheet_name="Repo Coverage Summary", index=False
            )

        if comparison_level == "full":
            # Field Value Comparison
            common = pat_df.merge(app_df, on=id_column, suffixes=("_pat", "_app"))

            diff_found = False
            diff_summary = {}

            # make exclusion set based on composite key or id column
            exclude_cols = {id_column}

            for col in pat_df.columns:
                if col in exclude_cols:
                    continue
                pat_col = f"{col}_pat"
                app_col = f"{col}_app"
                if pat_col in common.columns:
                    diffs = common[common[pat_col] != common[app_col]]
                    if len(diffs) > 0:
                        if not diff_found:
                            print(
                                f"Field value differences found for {script_name}.py:"
                            )
                            diff_found = True
                        diff_summary[col] = diffs[[id_column, pat_col, app_col]]

            if diff_found:
                print(f"\nSummary of differences for {script_name}.py:")
                for col, diff_df in diff_summary.items():
                    print(
                        f"\n - {col}: differs across {len(diff_df)} {id_column} values"
                    )
                print(f"\nFull differences report written to diffs_{script_name}.xlsx")
                # Save the full differences report to an Excel file for detailed review
                with pd.ExcelWriter(
                    f"{comparison_path}/diffs_{script_name}.xlsx"
                ) as writer:
                    for col, diff_df in diff_summary.items():
                        diff_df.to_excel(writer, sheet_name=col, index=False)
            else:
                print(f"No field value differences found for {script_name}.py.")


if __name__ == "__main__":
    compare_audit_data()
