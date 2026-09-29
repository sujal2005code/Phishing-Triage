"""
Process the Kaggle Phishing and Legitimate URLs dataset
using the project's existing 33-feature URL extractor.

Kaggle labels:
    0 = phishing/suspicious
    1 = legitimate/genuine

Project labels:
    0 = legitimate
    1 = phishing

Therefore labels are inverted during processing.
"""

import os
import sys
import pandas as pd

# Project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RAW_FILE = os.path.join(
    PROJECT_ROOT,
    "data",
    "raw",
    "new_data_urls.csv"
)

OUTPUT_FILE = os.path.join(
    PROJECT_ROOT,
    "data",
    "processed",
    "kaggle_phishing_urls.csv"
)

# Import existing feature extractor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from url_features import extract_features, get_feature_names


def main():

    print("=" * 70)
    print("KAGGLE URL DATASET PROCESSING")
    print("=" * 70)

    print(f"\nInput:  {RAW_FILE}")
    print(f"Output: {OUTPUT_FILE}")

    if not os.path.exists(RAW_FILE):
        raise FileNotFoundError(
            f"Kaggle dataset not found: {RAW_FILE}"
        )

    # ---------------------------------------------------------
    # 1. Load raw dataset
    # ---------------------------------------------------------

    print("\n[1/6] Loading Kaggle dataset...")

    df = pd.read_csv(RAW_FILE)

    print(f"Rows loaded: {len(df):,}")
    print(f"Columns: {list(df.columns)}")

    # Keep only required columns
    df = df[["url", "status"]].copy()

    # ---------------------------------------------------------
    # 2. Clean URLs
    # ---------------------------------------------------------

    print("\n[2/6] Cleaning URLs...")

    df["url"] = df["url"].astype(str).str.strip()

    # Remove empty/null-looking URLs
    df = df[
        df["url"].notna()
        & (df["url"] != "")
        & (df["url"].str.lower() != "nan")
    ].copy()

    print(f"After removing empty URLs: {len(df):,}")

    # ---------------------------------------------------------
    # 3. Check labels
    # ---------------------------------------------------------

    print("\n[3/6] Checking labels...")

    print("Original Kaggle labels:")
    print(df["status"].value_counts().sort_index())

    # Make sure labels are numeric
    df["status"] = pd.to_numeric(df["status"], errors="coerce")

    df = df[df["status"].isin([0, 1])].copy()

    # ---------------------------------------------------------
    # 4. Remove duplicate/conflicting URLs
    # ---------------------------------------------------------

    print("\n[4/6] Removing duplicates...")

    before = len(df)

    # Find URLs that appear with BOTH labels
    label_counts = df.groupby("url")["status"].nunique()

    conflicting_urls = label_counts[label_counts > 1].index

    print(f"Conflicting URLs: {len(conflicting_urls):,}")

    # Remove conflicting URLs completely
    if len(conflicting_urls) > 0:
        df = df[~df["url"].isin(conflicting_urls)].copy()

    # Remove exact duplicate URL/label pairs
    df = df.drop_duplicates(subset=["url", "status"])

    print(f"Rows before deduplication: {before:,}")
    print(f"Rows after deduplication:  {len(df):,}")

    # ---------------------------------------------------------
    # 5. Convert Kaggle labels to project labels
    # ---------------------------------------------------------

    print("\n[5/6] Converting labels...")

    # Kaggle:
    #   0 = phishing
    #   1 = legitimate
    #
    # Project:
    #   0 = legitimate
    #   1 = phishing

    df["label"] = 1 - df["status"]

    print("Project labels:")
    print(
        df["label"]
        .value_counts()
        .sort_index()
        .rename(index={
            0: "legitimate",
            1: "phishing"
        })
    )

    # ---------------------------------------------------------
    # 6. Extract the project's 33 features
    # ---------------------------------------------------------

    print("\n[6/6] Extracting URL features...")
    print("This may take several minutes for ~800k URLs.")
    print()

    feature_names = get_feature_names()

    print(f"Expected features: {len(feature_names)}")

    records = []

    total = len(df)

    for i, url in enumerate(df["url"].tolist(), start=1):

        features = extract_features(url)

        # Make sure every expected feature exists
        record = {
            name: features.get(name, 0)
            for name in feature_names
        }

        record["label"] = int(df.iloc[i - 1]["label"])

        records.append(record)

        if i % 10000 == 0:
            print(
                f"Processed {i:,} / {total:,} "
                f"({i / total * 100:.1f}%)"
            )

    processed = pd.DataFrame(records)

    # Ensure consistent column order
    processed = processed[feature_names + ["label"]]

    # Create output directory
    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    processed.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\n" + "=" * 70)
    print("PROCESSING COMPLETE")
    print("=" * 70)

    print(f"\nProcessed dataset:")
    print(f"  Rows:     {len(processed):,}")
    print(f"  Features: {len(feature_names)}")

    print("\nClass distribution:")

    counts = processed["label"].value_counts().sort_index()

    print(f"  Legitimate (0): {counts.get(0, 0):,}")
    print(f"  Phishing   (1): {counts.get(1, 0):,}")

    print(f"\nSaved to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()