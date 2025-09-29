import pytest
import tempfile
import csv
import numpy as np
import pandas as pd
from pathlib import Path

from research.train_rl import load_and_organize_embeddings


class TestRLEmbeddingLoading:
    @pytest.fixture
    def sample_embedding_csv(self):
        """Create a sample CSV with pre-computed embeddings."""
        # Create sample 4-dimensional embeddings for testing
        emb1 = np.array([0.1, 0.2, 0.3, 0.4], dtype=np.float32)
        emb2 = np.array([0.5, 0.6, 0.7, 0.8], dtype=np.float32)
        emb3 = np.array([0.9, 1.0, 1.1, 1.2], dtype=np.float32)
        emb4 = np.array([1.3, 1.4, 1.5, 1.6], dtype=np.float32)
        emb5 = np.array([1.7, 1.8, 1.9, 2.0], dtype=np.float32)
        emb6 = np.array([2.1, 2.2, 2.3, 2.4], dtype=np.float32)

        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package", "embedding"],
            [
                "LOAD_CONST foo",
                "hash1",
                "python",
                "/pkg1/file1.py",
                "malicious",
                "package_1",
                ",".join(map(str, emb1)),
            ],
            [
                "LOAD_CONST bar",
                "hash2",
                "python",
                "/pkg1/file2.py",
                "malicious",
                "package_1",
                ",".join(map(str, emb2)),
            ],
            [
                "LOAD_CONST baz",
                "hash3",
                "python",
                "/pkg2/file1.py",
                "malicious",
                "package_2",
                ",".join(map(str, emb3)),
            ],
            [
                "LOAD_CONST qux",
                "hash4",
                "python",
                "/benign1.py",
                "benign",
                "",
                ",".join(map(str, emb4)),
            ],
            [
                "LOAD_CONST quux",
                "hash5",
                "python",
                "/benign2.py",
                "benign",
                "",
                ",".join(map(str, emb5)),
            ],
            [
                "LOAD_CONST corge",
                "hash6",
                "python",
                "/benign3.py",
                "benign",
                "",
                ",".join(map(str, emb6)),
            ],
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerows(csv_content)
            temp_file_path = f.name

        yield temp_file_path

        Path(temp_file_path).unlink()

    def test_load_embeddings_basic(self, sample_embedding_csv):
        """Test basic loading of embeddings from CSV."""
        (
            malicious_packages,
            benign_embeddings,
            benign_labels,
            _,
            _,
            _,
        ) = load_and_organize_embeddings(sample_embedding_csv)

        assert len(malicious_packages) == 2
        assert len(benign_embeddings) == 3
        assert len(benign_labels) == 3

        assert all(label == 0 for label in benign_labels)

    def test_embeddings_are_numpy_arrays(self, sample_embedding_csv):
        """Test that embeddings are properly converted to numpy arrays."""
        (
            malicious_packages,
            benign_embeddings,
            _,
            _,
            _,
            _,
        ) = load_and_organize_embeddings(sample_embedding_csv)

        # Check malicious package embeddings
        for package_name, embeddings in malicious_packages.items():
            for emb in embeddings:
                assert isinstance(emb, np.ndarray)
                assert emb.dtype == np.float32
                assert emb.shape == (4,)  # 4-dimensional test embeddings

        # Check benign embeddings
        for emb in benign_embeddings:
            assert isinstance(emb, np.ndarray)
            assert emb.dtype == np.float32
            assert emb.shape == (4,)

    def test_malicious_packages_grouped_correctly(self, sample_embedding_csv):
        """Test that malicious embeddings are grouped by package."""
        (
            malicious_packages,
            _,
            _,
            _,
            _,
            _,
        ) = load_and_organize_embeddings(sample_embedding_csv)

        assert "package_1" in malicious_packages
        assert "package_2" in malicious_packages

        assert len(malicious_packages["package_1"]) == 2
        assert len(malicious_packages["package_2"]) == 1

        # Check first embedding from package_1
        emb = malicious_packages["package_1"][0]
        assert np.allclose(emb, [0.1, 0.2, 0.3, 0.4], atol=1e-6)

    def test_embedding_values_correct(self, sample_embedding_csv):
        """Test that embedding values are parsed correctly."""
        (
            _,
            benign_embeddings,
            _,
            _,
            _,
            _,
        ) = load_and_organize_embeddings(sample_embedding_csv)

        # Check first benign embedding
        assert np.allclose(benign_embeddings[0], [1.3, 1.4, 1.5, 1.6], atol=1e-6)
        assert np.allclose(benign_embeddings[1], [1.7, 1.8, 1.9, 2.0], atol=1e-6)
        assert np.allclose(benign_embeddings[2], [2.1, 2.2, 2.3, 2.4], atol=1e-6)

    def test_train_test_split(self, sample_embedding_csv):
        """Test train/test splitting with embeddings."""
        (
            train_mal,
            train_benign,
            train_benign_labels,
            test_mal,
            test_benign,
            test_benign_labels,
        ) = load_and_organize_embeddings(sample_embedding_csv, test_split=0.5)

        # Should split packages
        total_packages = len(train_mal) + len(test_mal)
        assert total_packages == 2

        # Should split benign samples
        total_benign = len(train_benign) + len(test_benign)
        assert total_benign == 3

        # All embeddings should be numpy arrays
        for pkg_embeddings in train_mal.values():
            for emb in pkg_embeddings:
                assert isinstance(emb, np.ndarray)

        for emb in train_benign:
            assert isinstance(emb, np.ndarray)

        for emb in test_benign:
            assert isinstance(emb, np.ndarray)

    def test_empty_embedding_csv(self):
        """Test loading empty CSV with embeddings."""
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package", "embedding"],
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerows(csv_content)
            temp_file_path = f.name

        try:
            (
                malicious_packages,
                benign_embeddings,
                benign_labels,
                _,
                _,
                _,
            ) = load_and_organize_embeddings(temp_file_path)

            assert len(malicious_packages) == 0
            assert len(benign_embeddings) == 0
            assert len(benign_labels) == 0

        finally:
            Path(temp_file_path).unlink()

    def test_skip_invalid_embeddings(self):
        """Test that invalid embedding strings are skipped."""
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package", "embedding"],
            [
                "LOAD_CONST valid1",
                "hash1",
                "python",
                "/file1.py",
                "malicious",
                "package_1",
                "0.1,0.2,0.3,0.4",
            ],
            [
                "LOAD_CONST invalid",
                "hash2",
                "python",
                "/file2.py",
                "malicious",
                "package_1",
                "",  # Empty embedding
            ],
            [
                "LOAD_CONST valid2",
                "hash3",
                "python",
                "/file3.py",
                "malicious",
                "package_1",
                "0.5,0.6,0.7,0.8",
            ],
        ]

        df = pd.DataFrame(csv_content[1:], columns=csv_content[0])

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            df.to_csv(f.name, index=False)
            temp_file_path = f.name

        try:
            (
                malicious_packages,
                _,
                _,
                _,
                _,
                _,
            ) = load_and_organize_embeddings(temp_file_path)

            # Should only have 2 valid embeddings
            assert "package_1" in malicious_packages
            assert len(malicious_packages["package_1"]) == 2

        finally:
            Path(temp_file_path).unlink()

    def test_missing_embedding_column(self):
        """Test error handling when embedding column is missing."""
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package"],
            [
                "LOAD_CONST foo",
                "hash1",
                "python",
                "/file1.py",
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
            with pytest.raises(ValueError, match="embedding"):
                load_and_organize_embeddings(temp_file_path)

        finally:
            Path(temp_file_path).unlink()

    def test_unknown_package_fallback_with_embeddings(self):
        """Test that embeddings without package names use 'unknown' fallback."""
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package", "embedding"],
            [
                "LOAD_CONST foo",
                "hash1",
                "python",
                "/file1.py",
                "malicious",
                "",
                "0.1,0.2",
            ],
            [
                "LOAD_CONST bar",
                "hash2",
                "python",
                "/file2.py",
                "malicious",
                None,
                "0.3,0.4",
            ],
        ]

        df = pd.DataFrame(csv_content[1:], columns=csv_content[0])

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            df.to_csv(f.name, index=False)
            temp_file_path = f.name

        try:
            (
                malicious_packages,
                _,
                _,
                _,
                _,
                _,
            ) = load_and_organize_embeddings(temp_file_path)

            assert "unknown" in malicious_packages
            assert len(malicious_packages["unknown"]) == 2

        finally:
            Path(temp_file_path).unlink()

    def test_high_dimensional_embeddings(self):
        """Test loading higher dimensional embeddings (256-dim like real DistilBERT)."""
        # Create a 256-dimensional embedding
        emb_256 = np.random.rand(256).astype(np.float32)

        csv_content = [
            ["tokens", "label", "package", "embedding"],
            ["LOAD_CONST test", "benign", "", ",".join(map(str, emb_256))],
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerows(csv_content)
            temp_file_path = f.name

        try:
            (
                _,
                benign_embeddings,
                _,
                _,
                _,
                _,
            ) = load_and_organize_embeddings(temp_file_path)

            assert len(benign_embeddings) == 1
            assert benign_embeddings[0].shape == (256,)
            assert np.allclose(benign_embeddings[0], emb_256, atol=1e-6)

        finally:
            Path(temp_file_path).unlink()
