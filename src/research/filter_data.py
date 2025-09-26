import os
import argparse
import pandas as pd

from common.malwi_object import MalwiObject
from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)


def enrich_dataframe_with_triage(
    df: pd.DataFrame, triage_subfolder: str
) -> pd.DataFrame:
    rows = []

    # Load enrichment data from all triage files
    for filename in os.listdir(triage_subfolder):
        filepath = os.path.join(triage_subfolder, filename)
        try:
            objs = MalwiObject.from_file(filepath, language="python")
            success(f"Loaded {len(objs)} objects from {filepath}")
            for obj in objs:
                h = obj.to_string_hash()
                row = {
                    "hash": h,
                    "tokens": obj.to_token_string(),
                    "filepath": obj.file_path,
                    # Add any other relevant fields from obj here
                }
                rows.append(row)
        except Exception as e:
            warning(f"Failed to process triage file {filepath}: {e}")
            continue

    # Create a DataFrame from the enrichment rows
    enrichment_df = pd.DataFrame(rows)

    # Append the enrichment DataFrame to the original
    df_appended = pd.concat([df, enrichment_df], ignore_index=True)

    # Optionally, remove duplicates based on hash or other columns:
    df_appended = df_appended.drop_duplicates(subset=["hash"])

    return df_appended


def process_unified_csv(input_csv, output_csv, triage_dir=None):
    """
    Process a CSV file with categories:
    - Remove internal duplicates (by 'hash').
    - Remove cross-category duplicates (benign samples take priority).
    - If triage_dir given, enrich with MalwiObject data.
    """

    # Step 1: Load dataset
    progress("Step 1: Loading dataset from CSV file...")
    try:
        df = pd.read_csv(input_csv)
        info(f"Loaded {len(df)} samples from {input_csv}")

        # Show category distribution
        if "label" in df.columns:
            category_counts = df["label"].value_counts()
            info("Category distribution:")
            for category, count in category_counts.items():
                info(f"  - {category}: {count} samples")

    except Exception as e:
        error(f"Error reading file: {e}")
        return

    # Step 2: Enrich with triage data if provided
    if triage_dir and os.path.isdir(triage_dir):
        progress("Step 2: Enriching dataset with triage data...")

        # Check for category-specific subdirectories
        for category in ["benign", "malicious", "suspicious", "telemetry"]:
            triage_path = os.path.join(triage_dir, category)
            if os.path.isdir(triage_path):
                info(f"Enriching {category} samples with files from: {triage_path}")

                # Load triage files and add with correct label
                rows = []
                for filename in os.listdir(triage_path):
                    filepath = os.path.join(triage_path, filename)
                    try:
                        objs = MalwiObject.from_file(filepath, language="python")
                        success(f"Loaded {len(objs)} objects from {filepath}")
                        for obj in objs:
                            h = obj.to_string_hash()
                            row = {
                                "hash": h,
                                "tokens": obj.to_token_string(),
                                "filepath": obj.file_path,
                                "language": "python",
                                "label": category,
                            }
                            rows.append(row)
                    except Exception as e:
                        warning(f"Failed to process triage file {filepath}: {e}")
                        continue

                if rows:
                    enrichment_df = pd.DataFrame(rows)
                    df = pd.concat([df, enrichment_df], ignore_index=True)
                    info(f"  Added {len(rows)} {category} samples from triage")

    # Step 3: Remove internal duplicates
    progress("Step 3: Removing duplicate samples...")
    initial_count = len(df)
    df = df.drop_duplicates(subset=["hash"], keep="first")
    success(f"Removed {initial_count - len(df)} duplicate samples")

    # Step 4: Handle cross-category duplicates (benign samples take priority)
    if "label" in df.columns:
        progress("Step 4: Handling cross-category duplicates...")

        # Group by hash to find duplicates across categories
        hash_counts = df.groupby("hash")["label"].nunique()
        duplicate_hashes = hash_counts[hash_counts > 1].index

        if len(duplicate_hashes) > 0:
            info(
                f"Found {len(duplicate_hashes)} hashes appearing in multiple categories"
            )

            # For each duplicate hash, keep only the benign version if it exists
            # Otherwise keep the first occurrence
            for hash_val in duplicate_hashes:
                hash_df = df[df["hash"] == hash_val]
                if "benign" in hash_df["label"].values:
                    # Keep only the benign sample
                    df = df[~((df["hash"] == hash_val) & (df["label"] != "benign"))]
                else:
                    # Keep only the first occurrence
                    indices_to_drop = hash_df.index[1:]
                    df = df.drop(indices_to_drop)

            success(f"Resolved {len(duplicate_hashes)} cross-category duplicates")

    # Show final distribution
    if "label" in df.columns:
        info("Final category distribution:")
        category_counts = df["label"].value_counts()
        for category, count in category_counts.items():
            info(f"  - {category}: {count} samples")

    success(f"Final dataset shape: {df.shape}")

    # Step 5: Save processed dataset
    progress("Step 5: Saving processed dataset...")
    try:
        df.to_csv(output_csv, index=False)
        success(f"Saved processed dataset to: {output_csv}")
        success(f"Dataset processing completed: {len(df)} total samples")

    except Exception as e:
        error(f"Error saving processed CSV: {e}")


def process_csv_files(benign, malicious, triage_dir=None):
    """
    Process benign and malicious CSV files:
    - Remove internal duplicates (by 'hash') in each file.
    - Remove rows from malicious that have hashes common with benign.
    - If triage_dir given, enrich both DataFrames with MalwiObject data.
    """

    # Step 1: Load datasets
    progress("Step 1: Loading datasets from CSV files...")
    try:
        df_benign = pd.read_csv(benign)
        info(f"Loaded {len(df_benign)} benign samples from {benign}")

        df_malicious = pd.read_csv(malicious)
        info(f"Loaded {len(df_malicious)} malicious samples from {malicious}")

    except Exception as e:
        error(f"Error reading files: {e}")
        return

    # Step 2: Enrich with triage data if provided
    if triage_dir:
        progress("Step 2: Enriching datasets with triage data...")
        benign_triage_path = os.path.join(triage_dir, "benign")
        malicious_triage_path = os.path.join(triage_dir, "malicious")

        if os.path.isdir(benign_triage_path):
            info(f"Enriching benign dataset with files from: {benign_triage_path}")
            df_benign = enrich_dataframe_with_triage(df_benign, benign_triage_path)

        if os.path.isdir(malicious_triage_path):
            info(
                f"Enriching malicious dataset with files from: {malicious_triage_path}"
            )
            df_malicious = enrich_dataframe_with_triage(
                df_malicious, malicious_triage_path
            )

    # Step 3: Remove internal duplicates
    progress("Step 3: Removing duplicate samples within datasets...")
    initial_benign = len(df_benign)
    df_benign = df_benign.drop_duplicates(subset=["hash"], keep="first")
    success(
        f"Removed {initial_benign - len(df_benign)} duplicate samples from benign dataset"
    )

    initial_malicious = len(df_malicious)
    df_malicious = df_malicious.drop_duplicates(subset=["hash"], keep="first")
    success(
        f"Removed {initial_malicious - len(df_malicious)} duplicate samples from malicious dataset"
    )

    # Step 4: Remove cross-dataset duplicates
    progress("Step 4: Identifying and removing cross-dataset duplicates...")
    hashes_benign = set(df_benign["hash"])
    hashes_malicious = set(df_malicious["hash"])
    common_hashes = hashes_benign.intersection(hashes_malicious)
    info(f"Found {len(common_hashes)} common hashes between benign and malicious sets")

    # Remove common hashes ONLY from malicious set
    if common_hashes:
        df_malicious = df_malicious[~df_malicious["hash"].isin(common_hashes)]
        success(f"Removed {len(common_hashes)} common samples from malicious dataset")

    success(f"Final benign set shape: {df_benign.shape}")
    success(f"Final malicious set shape: {df_malicious.shape}")

    # Step 5: Save processed datasets
    progress("Step 5: Saving processed datasets...")
    base_benign, ext_benign = os.path.splitext(benign)
    output_benign = f"{base_benign}_processed{ext_benign}"

    base_malicious, ext_malicious = os.path.splitext(malicious)
    output_malicious = f"{base_malicious}_processed{ext_malicious}"

    try:
        df_benign.to_csv(output_benign, index=False)
        success(f"Saved processed benign dataset to: {output_benign}")

        df_malicious.to_csv(output_malicious, index=False)
        success(f"Saved processed malicious dataset to: {output_malicious}")

        # Summary
        success(
            f"Dataset processing completed: {len(df_benign)} benign, {len(df_malicious)} malicious samples"
        )

    except Exception as e:
        error(f"Error saving processed CSVs: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Process two CSV files (benign and malicious). Removes intra-file duplicates from both. "
            "Removes duplicates common with the benign file ONLY from the malicious file. "
            "Optionally enriches CSV data from a triaging folder containing 'benign' and/or 'malicious' subfolders."
        )
    )
    parser.add_argument(
        "--benign",
        "-b",
        metavar="BENIGN_CSV_PATH",
        type=str,
        help="Path to the benign CSV file. Duplicates common with the malicious file will be KEPT in this file.",
    )
    parser.add_argument(
        "--malicious",
        "-m",
        metavar="MALICIOUS_CSV_PATH",
        type=str,
        help="Path to the malicious CSV file. Duplicates common with the benign file will be REMOVED from this file.",
    )
    parser.add_argument(
        "--triaging",
        "-t",
        metavar="TRIAGING_FOLDER",
        type=str,
        help="Folder containing 'benign' and/or 'malicious' subfolders to enrich CSV data by parsing files.",
    )

    args = parser.parse_args()

    # Configure messaging system
    configure_messaging(quiet=False)

    if args.benign and args.malicious:
        process_csv_files(args.benign, args.malicious, triage_dir=args.triaging)
    else:
        error(
            "Both --benign and --malicious CSV file paths must be provided to process."
        )
