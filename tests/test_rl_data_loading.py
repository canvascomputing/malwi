import pytest
import tempfile
import csv
import pandas as pd
from pathlib import Path

from research.train_rl import load_and_organize_data


class TestRLDataLoading:
    @pytest.fixture
    def sample_csv_with_packages(self):
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package"],
            [
                "LOAD_CONST foo",
                "hash1",
                "python",
                "/pkg1/file1.py",
                "malicious",
                "package_1",
            ],
            [
                "LOAD_CONST bar",
                "hash2",
                "python",
                "/pkg1/file2.py",
                "malicious",
                "package_1",
            ],
            [
                "LOAD_CONST baz",
                "hash3",
                "python",
                "/pkg2/file1.py",
                "malicious",
                "package_2",
            ],
            ["LOAD_CONST qux", "hash4", "python", "/benign1.py", "benign", ""],
            ["LOAD_CONST quux", "hash5", "python", "/benign2.py", "benign", ""],
            ["LOAD_CONST corge", "hash6", "python", "/benign3.py", "benign", ""],
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerows(csv_content)
            temp_file_path = f.name

        yield temp_file_path

        Path(temp_file_path).unlink()

    def test_load_and_organize_basic(self, sample_csv_with_packages):
        malicious_packages, benign_samples, benign_labels = load_and_organize_data(
            sample_csv_with_packages
        )

        assert len(malicious_packages) == 2
        assert len(benign_samples) == 3
        assert len(benign_labels) == 3

        assert all(label == 0 for label in benign_labels)

    def test_malicious_packages_grouped_correctly(self, sample_csv_with_packages):
        malicious_packages, _, _ = load_and_organize_data(sample_csv_with_packages)

        assert "package_1" in malicious_packages
        assert "package_2" in malicious_packages

        assert len(malicious_packages["package_1"]) == 2
        assert len(malicious_packages["package_2"]) == 1

        assert "LOAD_CONST foo" in malicious_packages["package_1"]
        assert "LOAD_CONST bar" in malicious_packages["package_1"]
        assert "LOAD_CONST baz" in malicious_packages["package_2"]

    def test_benign_samples_loaded_correctly(self, sample_csv_with_packages):
        _, benign_samples, benign_labels = load_and_organize_data(
            sample_csv_with_packages
        )

        assert len(benign_samples) == 3

        assert "LOAD_CONST qux" in benign_samples
        assert "LOAD_CONST quux" in benign_samples
        assert "LOAD_CONST corge" in benign_samples

        assert all(label == 0 for label in benign_labels)

    def test_empty_csv(self):
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package"],
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerows(csv_content)
            temp_file_path = f.name

        try:
            malicious_packages, benign_samples, benign_labels = load_and_organize_data(
                temp_file_path
            )

            assert len(malicious_packages) == 0
            assert len(benign_samples) == 0
            assert len(benign_labels) == 0

        finally:
            Path(temp_file_path).unlink()

    def test_only_malicious_data(self):
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package"],
            [
                "LOAD_CONST foo",
                "hash1",
                "python",
                "/pkg1/file1.py",
                "malicious",
                "package_1",
            ],
            [
                "LOAD_CONST bar",
                "hash2",
                "python",
                "/pkg1/file2.py",
                "malicious",
                "package_1",
            ],
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerows(csv_content)
            temp_file_path = f.name

        try:
            malicious_packages, benign_samples, benign_labels = load_and_organize_data(
                temp_file_path
            )

            assert len(malicious_packages) == 1
            assert len(benign_samples) == 0
            assert len(benign_labels) == 0

            assert "package_1" in malicious_packages
            assert len(malicious_packages["package_1"]) == 2

        finally:
            Path(temp_file_path).unlink()

    def test_only_benign_data(self):
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package"],
            ["LOAD_CONST foo", "hash1", "python", "/benign1.py", "benign", ""],
            ["LOAD_CONST bar", "hash2", "python", "/benign2.py", "benign", ""],
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerows(csv_content)
            temp_file_path = f.name

        try:
            malicious_packages, benign_samples, benign_labels = load_and_organize_data(
                temp_file_path
            )

            assert len(malicious_packages) == 0
            assert len(benign_samples) == 2
            assert len(benign_labels) == 2

        finally:
            Path(temp_file_path).unlink()

    def test_missing_package_column_fallback(self):
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label"],
            ["LOAD_CONST foo", "hash1", "python", "/pkg1/file1.py", "malicious"],
            ["LOAD_CONST bar", "hash2", "python", "/benign1.py", "benign"],
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerows(csv_content)
            temp_file_path = f.name

        try:
            malicious_packages, benign_samples, benign_labels = load_and_organize_data(
                temp_file_path
            )

            assert len(malicious_packages) >= 1
            assert len(benign_samples) == 1

        finally:
            Path(temp_file_path).unlink()

    def test_unknown_package_fallback(self):
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package"],
            ["LOAD_CONST foo", "hash1", "python", "/file1.py", "malicious", ""],
            ["LOAD_CONST bar", "hash2", "python", "/file2.py", "malicious", None],
        ]

        df = pd.DataFrame(csv_content[1:], columns=csv_content[0])

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            df.to_csv(f.name, index=False)
            temp_file_path = f.name

        try:
            malicious_packages, _, _ = load_and_organize_data(temp_file_path)

            assert "unknown" in malicious_packages
            assert len(malicious_packages["unknown"]) == 2

        finally:
            Path(temp_file_path).unlink()

    def test_skip_empty_or_invalid_tokens(self):
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package"],
            [
                "LOAD_CONST valid",
                "hash1",
                "python",
                "/file1.py",
                "malicious",
                "package_1",
            ],
            ["", "hash2", "python", "/file2.py", "malicious", "package_1"],
            [None, "hash3", "python", "/file3.py", "malicious", "package_1"],
            ["   ", "hash4", "python", "/file4.py", "malicious", "package_1"],
            [
                "LOAD_CONST another",
                "hash5",
                "python",
                "/file5.py",
                "malicious",
                "package_1",
            ],
        ]

        df = pd.DataFrame(csv_content[1:], columns=csv_content[0])

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            df.to_csv(f.name, index=False)
            temp_file_path = f.name

        try:
            malicious_packages, _, _ = load_and_organize_data(temp_file_path)

            assert "package_1" in malicious_packages
            assert len(malicious_packages["package_1"]) == 2

        finally:
            Path(temp_file_path).unlink()

    def test_multiple_packages_with_varying_sizes(self):
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package"],
            [
                "LOAD_CONST a",
                "hash1",
                "python",
                "/pkg1/file1.py",
                "malicious",
                "package_1",
            ],
            [
                "LOAD_CONST b",
                "hash2",
                "python",
                "/pkg2/file1.py",
                "malicious",
                "package_2",
            ],
            [
                "LOAD_CONST c",
                "hash3",
                "python",
                "/pkg2/file2.py",
                "malicious",
                "package_2",
            ],
            [
                "LOAD_CONST d",
                "hash4",
                "python",
                "/pkg2/file3.py",
                "malicious",
                "package_2",
            ],
            [
                "LOAD_CONST e",
                "hash5",
                "python",
                "/pkg3/file1.py",
                "malicious",
                "package_3",
            ],
            [
                "LOAD_CONST f",
                "hash6",
                "python",
                "/pkg3/file2.py",
                "malicious",
                "package_3",
            ],
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerows(csv_content)
            temp_file_path = f.name

        try:
            malicious_packages, _, _ = load_and_organize_data(temp_file_path)

            assert len(malicious_packages) == 3
            assert len(malicious_packages["package_1"]) == 1
            assert len(malicious_packages["package_2"]) == 3
            assert len(malicious_packages["package_3"]) == 2

        finally:
            Path(temp_file_path).unlink()
