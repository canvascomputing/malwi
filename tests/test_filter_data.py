import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Skip all tests in this module if pandas is not available (training dependencies not installed)
pytest_plugins = []

try:
    import pandas as pd
    from research.filter_data import process_csv_files

    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    pd = None
    process_csv_files = None

pytestmark = pytest.mark.skipif(
    not PANDAS_AVAILABLE,
    reason="pandas not available (training dependencies not installed)",
)


def create_csv(tmp_path: Path, filename: str, data):
    """Helper function to create a CSV file in a temporary directory."""
    file_path = tmp_path / filename
    data.to_csv(file_path, index=False)
    return file_path


def read_processed_csv(tmp_path: Path, original_filename: str):
    """Helper function to read the processed CSV file."""
    base, ext = os.path.splitext(original_filename)
    processed_filename = f"{base}_processed{ext}"
    file_path = tmp_path / processed_filename
    if file_path.exists():
        return pd.read_csv(file_path)
    return (
        pd.DataFrame()
    )  # Return empty DataFrame if file doesn't exist (e.g., after error)


def assert_df_equal_ignore_order(df1, df2, sort_by_col="hash"):
    """
    Asserts two DataFrames are equal, ignoring row order.
    Sorts by 'hash' column if it exists, otherwise compares as is.
    Handles empty DataFrames correctly.
    """
    if df1.empty and df2.empty:
        assert True
        return
    if df1.empty or df2.empty:  # One is empty, the other is not
        assert False, (
            f"One DataFrame is empty, the other is not.\nDF1:\n{df1}\nDF2:\n{df2}"
        )

    # Ensure 'hash' column exists for sorting if specified and dfs are not empty
    if sort_by_col in df1.columns and sort_by_col in df2.columns:
        df1_sorted = df1.sort_values(by=sort_by_col).reset_index(drop=True)
        df2_sorted = df2.sort_values(by=sort_by_col).reset_index(drop=True)
    else:  # If no 'hash' column or not specified for sorting, compare as is
        df1_sorted = df1.reset_index(drop=True)
        df2_sorted = df2.reset_index(drop=True)

    pd.testing.assert_frame_equal(df1_sorted, df2_sorted, check_dtype=False)


# --- Test Cases ---


def test_no_common_hashes_no_intra_duplicates(tmp_path):
    benign_data = pd.DataFrame(
        {"hash": ["h_b1", "h_b2"], "feature": ["b_data1", "b_data2"]}
    )
    malicious_data = pd.DataFrame(
        {"hash": ["h_m1", "h_m2"], "feature": ["m_data1", "m_data2"]}
    )

    benign_file = create_csv(tmp_path, "benign.csv", benign_data)
    malicious_file = create_csv(tmp_path, "malicious.csv", malicious_data)

    process_csv_files(str(benign_file), str(malicious_file))

    processed_benign = read_processed_csv(tmp_path, "benign.csv")
    processed_malicious = read_processed_csv(tmp_path, "malicious.csv")

    assert_df_equal_ignore_order(processed_benign, benign_data)
    assert_df_equal_ignore_order(processed_malicious, malicious_data)


def test_common_hashes_no_intra_duplicates(tmp_path):
    benign_data = pd.DataFrame(
        {
            "hash": ["h_b1", "h_common1", "h_b2"],
            "feature": ["b_data1", "b_common_data", "b_data2"],
        }
    )
    malicious_data = pd.DataFrame(
        {
            "hash": ["h_m1", "h_common1", "h_m2"],
            "feature": ["m_data1", "m_common_data", "m_data2"],
        }
    )

    benign_file = create_csv(tmp_path, "benign_c.csv", benign_data)
    malicious_file = create_csv(tmp_path, "malicious_c.csv", malicious_data)

    process_csv_files(str(benign_file), str(malicious_file))

    processed_benign = read_processed_csv(tmp_path, "benign_c.csv")
    processed_malicious = read_processed_csv(tmp_path, "malicious_c.csv")

    expected_malicious = malicious_data[
        ~malicious_data["hash"].isin(["h_common1"])
    ].reset_index(drop=True)

    assert_df_equal_ignore_order(processed_benign, benign_data)  # Benign keeps common
    assert_df_equal_ignore_order(
        processed_malicious, expected_malicious
    )  # Malicious removes common


def test_intra_file_duplicates_no_common_hashes(tmp_path):
    benign_data = pd.DataFrame(
        {
            "hash": ["h_b1", "h_b1", "h_b2"],
            "feature": ["b_data1a", "b_data1b", "b_data2"],
        }
    )
    malicious_data = pd.DataFrame(
        {
            "hash": ["h_m1", "h_m2", "h_m2"],
            "feature": ["m_data1", "m_data2a", "m_data2b"],
        }
    )

    benign_file = create_csv(tmp_path, "benign_intra.csv", benign_data)
    malicious_file = create_csv(tmp_path, "malicious_intra.csv", malicious_data)

    process_csv_files(str(benign_file), str(malicious_file))

    processed_benign = read_processed_csv(tmp_path, "benign_intra.csv")
    processed_malicious = read_processed_csv(tmp_path, "malicious_intra.csv")

    expected_benign = benign_data.drop_duplicates(
        subset=["hash"], keep="first"
    ).reset_index(drop=True)
    expected_malicious = malicious_data.drop_duplicates(
        subset=["hash"], keep="first"
    ).reset_index(drop=True)

    assert_df_equal_ignore_order(processed_benign, expected_benign)
    assert_df_equal_ignore_order(processed_malicious, expected_malicious)


def test_common_hashes_and_intra_file_duplicates(tmp_path):
    benign_data = pd.DataFrame(
        {
            "hash": ["h_b1", "h_b1", "h_common1"],
            "feature": ["b_data1a", "b_data1b", "b_common_data"],
        }
    )
    malicious_data = pd.DataFrame(
        {
            "hash": ["h_m1", "h_common1", "h_common1", "h_m2"],
            "feature": ["m_data1", "m_common_data_a", "m_common_data_b", "m_data2"],
        }
    )

    benign_file = create_csv(tmp_path, "benign_both.csv", benign_data)
    malicious_file = create_csv(tmp_path, "malicious_both.csv", malicious_data)

    process_csv_files(str(benign_file), str(malicious_file))

    processed_benign = read_processed_csv(tmp_path, "benign_both.csv")
    processed_malicious = read_processed_csv(tmp_path, "malicious_both.csv")

    # Expected benign: intra-duplicates removed, common hash KEPT
    expected_benign = benign_data.drop_duplicates(
        subset=["hash"], keep="first"
    ).reset_index(drop=True)

    # Expected malicious:
    # 1. Intra-duplicates removed: h_m1, h_common1 (first), h_m2
    malicious_dedup_intra = malicious_data.drop_duplicates(
        subset=["hash"], keep="first"
    )
    # 2. Common hashes with (deduplicated) benign are removed from (deduplicated) malicious
    # Hashes in deduped benign: h_b1, h_common1
    # Common with deduped malicious: h_common1
    expected_malicious = malicious_dedup_intra[
        ~malicious_dedup_intra["hash"].isin(["h_common1"])
    ].reset_index(drop=True)

    assert_df_equal_ignore_order(processed_benign, expected_benign)
    assert_df_equal_ignore_order(processed_malicious, expected_malicious)


def test_empty_benign_file(tmp_path):
    benign_data = pd.DataFrame(columns=["hash", "feature"])  # Empty with headers
    malicious_data = pd.DataFrame(
        {
            "hash": ["h_m1", "h_m1", "h_m2"],
            "feature": ["m_data1a", "m_data1b", "m_data2"],
        }
    )

    benign_file = create_csv(tmp_path, "benign_empty.csv", benign_data)
    malicious_file = create_csv(tmp_path, "malicious_data.csv", malicious_data)

    process_csv_files(str(benign_file), str(malicious_file))

    processed_benign = read_processed_csv(tmp_path, "benign_empty.csv")
    processed_malicious = read_processed_csv(tmp_path, "malicious_data.csv")

    expected_benign = pd.DataFrame(columns=["hash", "feature"])
    expected_malicious = malicious_data.drop_duplicates(
        subset=["hash"], keep="first"
    ).reset_index(drop=True)

    assert_df_equal_ignore_order(processed_benign, expected_benign)
    assert_df_equal_ignore_order(processed_malicious, expected_malicious)


def test_empty_malicious_file(tmp_path):
    benign_data = pd.DataFrame(
        {
            "hash": ["h_b1", "h_b1", "h_b2"],
            "feature": ["b_data1a", "b_data1b", "b_data2"],
        }
    )
    malicious_data = pd.DataFrame(columns=["hash", "feature"])  # Empty with headers

    benign_file = create_csv(tmp_path, "benign_data.csv", benign_data)
    malicious_file = create_csv(tmp_path, "malicious_empty.csv", malicious_data)

    process_csv_files(str(benign_file), str(malicious_file))

    processed_benign = read_processed_csv(tmp_path, "benign_data.csv")
    processed_malicious = read_processed_csv(tmp_path, "malicious_empty.csv")

    expected_benign = benign_data.drop_duplicates(
        subset=["hash"], keep="first"
    ).reset_index(drop=True)
    expected_malicious = pd.DataFrame(columns=["hash", "feature"])

    assert_df_equal_ignore_order(processed_benign, expected_benign)
    assert_df_equal_ignore_order(processed_malicious, expected_malicious)


def test_both_files_empty(tmp_path):
    benign_data = pd.DataFrame(columns=["hash", "feature"])
    malicious_data = pd.DataFrame(columns=["hash", "feature"])

    benign_file = create_csv(tmp_path, "benign_both_empty.csv", benign_data)
    malicious_file = create_csv(tmp_path, "malicious_both_empty.csv", malicious_data)

    process_csv_files(str(benign_file), str(malicious_file))

    processed_benign = read_processed_csv(tmp_path, "benign_both_empty.csv")
    processed_malicious = read_processed_csv(tmp_path, "malicious_both_empty.csv")

    # Ensure columns are in the same order if they exist (or handle no columns)
    # The script should produce files with headers even if they are empty of data
    expected_df = pd.DataFrame(columns=["hash", "feature"])

    assert_df_equal_ignore_order(processed_benign, expected_df)
    assert_df_equal_ignore_order(processed_malicious, expected_df)


def test_all_malicious_hashes_are_common(tmp_path):
    benign_data = pd.DataFrame(
        {
            "hash": ["h1", "h2", "h3", "h_b_only"],
            "feature": ["b1", "b2", "b3", "b_only_data"],
        }
    )
    malicious_data = pd.DataFrame(
        {"hash": ["h1", "h2", "h3", "h3"], "feature": ["m1", "m2", "m3a", "m3b"]}
    )  # h3 is duplicated

    benign_file = create_csv(tmp_path, "benign_all_common.csv", benign_data)
    malicious_file = create_csv(tmp_path, "malicious_all_common.csv", malicious_data)

    process_csv_files(str(benign_file), str(malicious_file))

    processed_benign = read_processed_csv(tmp_path, "benign_all_common.csv")
    processed_malicious = read_processed_csv(tmp_path, "malicious_all_common.csv")

    # Expected benign: intra-duplicates removed (none here), common hashes KEPT
    expected_benign = benign_data.drop_duplicates(
        subset=["hash"], keep="first"
    ).reset_index(drop=True)

    # Expected malicious:
    # 1. Intra-duplicates removed: h1, h2, h3 (first)
    # 2. Common hashes (h1, h2, h3) removed.
    # Result: empty data, only headers.
    expected_malicious = pd.DataFrame(columns=["hash", "feature"])

    assert_df_equal_ignore_order(processed_benign, expected_benign)
    assert_df_equal_ignore_order(processed_malicious, expected_malicious)


def test_malicious_has_unique_and_common_benign_has_unique_and_common(tmp_path):
    benign_data = pd.DataFrame(
        {
            "hash": [
                "h_b_unique1",
                "h_common1",
                "h_b_unique2",
                "h_common2",
                "h_common1",
            ],  # h_common1 duplicated
            "feature": ["b_u1", "b_c1a", "b_u2", "b_c2", "b_c1b"],
        }
    )
    malicious_data = pd.DataFrame(
        {
            "hash": [
                "h_m_unique1",
                "h_common1",
                "h_m_unique2",
                "h_common2",
                "h_common2",
            ],  # h_common2 duplicated
            "feature": ["m_u1", "m_c1", "m_u2", "m_c2a", "m_c2b"],
        }
    )

    benign_file = create_csv(tmp_path, "benign_mixed.csv", benign_data)
    malicious_file = create_csv(tmp_path, "malicious_mixed.csv", malicious_data)

    process_csv_files(str(benign_file), str(malicious_file))

    processed_benign = read_processed_csv(tmp_path, "benign_mixed.csv")
    processed_malicious = read_processed_csv(tmp_path, "malicious_mixed.csv")

    # Expected benign: intra-duplicates removed, common hashes KEPT
    # h_b_unique1, h_common1 (first), h_b_unique2, h_common2
    expected_benign_data = [
        {"hash": "h_b_unique1", "feature": "b_u1"},
        {"hash": "h_common1", "feature": "b_c1a"},
        {"hash": "h_b_unique2", "feature": "b_u2"},
        {"hash": "h_common2", "feature": "b_c2"},
    ]
    expected_benign = pd.DataFrame(expected_benign_data)

    # Expected malicious:
    # 1. Intra-duplicates removed from malicious: h_m_unique1, h_common1, h_m_unique2, h_common2 (first)
    #    df: h_m_unique1 (m_u1), h_common1 (m_c1), h_m_unique2 (m_u2), h_common2 (m_c2a)
    # 2. Common hashes with (deduplicated) benign are {h_common1, h_common2}. These are removed.
    # Result: h_m_unique1, h_m_unique2
    expected_malicious_data = [
        {"hash": "h_m_unique1", "feature": "m_u1"},
        {"hash": "h_m_unique2", "feature": "m_u2"},
    ]
    expected_malicious = pd.DataFrame(expected_malicious_data)

    assert_df_equal_ignore_order(processed_benign, expected_benign)
    assert_df_equal_ignore_order(processed_malicious, expected_malicious)


def test_triaging_only_common_hashes_removed(tmp_path):
    # This test is for the old triaging mode where only common hashes
    # are removed from malicious, but duplicates are NOT removed.
    benign_data = pd.DataFrame(
        {
            "hash": ["h_b1", "h_common1", "h_b2"],
            "feature": ["b_data1", "b_common_data", "b_data2"],
        }
    )
    malicious_data = pd.DataFrame(
        {
            "hash": ["h_m1", "h_common1", "h_common1", "h_m2"],
            "feature": ["m_data1", "m_common_data_a", "m_common_data_b", "m_data2"],
        }
    )

    benign_file = create_csv(tmp_path, "benign_remove.csv", benign_data)
    malicious_file = create_csv(tmp_path, "malicious_remove.csv", malicious_data)

    # Process the CSV files
    # or is invoked differently. Replace accordingly.
    process_csv_files(str(benign_file), str(malicious_file))

    processed_benign = read_processed_csv(tmp_path, "benign_remove.csv")
    processed_malicious = read_processed_csv(tmp_path, "malicious_remove.csv")

    # benign should be unchanged
    assert_df_equal_ignore_order(processed_benign, benign_data)

    # malicious should only have common hashes removed, duplicates remain
    expected_malicious = malicious_data[
        ~malicious_data["hash"].isin(["h_common1"])
    ].reset_index(drop=True)

    assert_df_equal_ignore_order(processed_malicious, expected_malicious)


def test_triaging_only_duplicates_kept(tmp_path):
    benign_data = pd.DataFrame(
        {
            "hash": ["h_b1"],
            "feature": ["b_data1"],
        }
    )
    malicious_data = pd.DataFrame(
        {
            "hash": ["h_m1", "h_m1", "h_b1"],
            "feature": ["m_data1a", "m_data1b", "m_data_b1"],
        }
    )

    benign_file = create_csv(tmp_path, "benign_dup_remove.csv", benign_data)
    malicious_file = create_csv(tmp_path, "malicious_dup_remove.csv", malicious_data)

    process_csv_files(str(benign_file), str(malicious_file))

    processed_benign = read_processed_csv(tmp_path, "benign_dup_remove.csv")
    processed_malicious = read_processed_csv(tmp_path, "malicious_dup_remove.csv")

    # benign unchanged
    assert_df_equal_ignore_order(processed_benign, benign_data)

    # malicious should only have benign hashes removed, duplicates collapsed
    expected_malicious = pd.DataFrame(
        {
            "hash": ["h_m1"],
            "feature": ["m_data1a"],
        }
    )

    assert_df_equal_ignore_order(processed_malicious, expected_malicious)


@pytest.fixture
def sample_df():
    return pd.DataFrame(
        {
            "hash": ["hash1", "hash2"],
            "tokens": ["token1", "token2"],
            "filepath": ["path1.py", "path2.py"],
        }
    )
