#!/usr/bin/env python3
"""
Test cases for the training pipeline.
Validates that the CSV approach works correctly with categories.
"""

import pytest
import tempfile
import pandas as pd
from pathlib import Path
import os
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from research.filter_data import process_unified_csv
from research.train_tokenizer import train_tokenizer
from research.train_distilbert import run_training
from common.messaging import configure_messaging


class TestUnifiedTraining:
    """Test the training pipeline with categories."""

    @pytest.fixture
    def sample_training_csv(self):
        """Create a sample training CSV with all categories."""
        data = {
            "tokens": [
                "import os system subprocess",
                "print hello world",
                "os system rm rf",
                "requests get http url",
                "def add x y return x plus y",
                "eval input user_data",
                "socket connect host port",
                "len list items",
                "exec compile code",
                "open file read",
                "base64 decode data",
                "json loads data",
            ],
            "hash": [
                "abc123def456",
                "def456ghi789",
                "ghi789jkl012",
                "jkl012mno345",
                "mno345pqr678",
                "pqr678stu901",
                "stu901vwx234",
                "vwx234yzab567",
                "yzab567cdef890",
                "cdef890ghij123",
                "ghij123klmn456",
                "klmn456opqr789",
            ],
            "language": ["python"] * 12,
            "filepath": [
                "/test/malicious1.py",
                "/test/benign1.py",
                "/test/suspicious1.py",
                "/test/telemetry1.py",
                "/test/benign2.py",
                "/test/malicious2.py",
                "/test/telemetry2.py",
                "/test/benign3.py",
                "/test/malicious3.py",
                "/test/benign4.py",
                "/test/suspicious2.py",
                "/test/benign5.py",
            ],
            "label": [
                "malicious",
                "benign",
                "suspicious",
                "telemetry",
                "benign",
                "malicious",
                "telemetry",
                "benign",
                "malicious",
                "benign",
                "suspicious",
                "benign",
            ],
        }

        df = pd.DataFrame(data)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            df.to_csv(f.name, index=False)
            return f.name

    @pytest.fixture
    def processed_csv(self, sample_training_csv):
        """Create processed training CSV."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="_processed.csv", delete=False
        ) as f:
            processed_path = f.name

        # Configure messaging to be quiet during tests
        configure_messaging(quiet=True)

        # Process the sample CSV
        process_unified_csv(sample_training_csv, processed_path)

        return processed_path

    def test_csv_processing(self, sample_training_csv):
        """Test that CSV processing works correctly."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="_processed.csv", delete=False
        ) as f:
            processed_path = f.name

        configure_messaging(quiet=True)

        # Should not raise any exceptions
        process_unified_csv(sample_training_csv, processed_path)

        # Check that processed file exists and has correct structure
        assert Path(processed_path).exists()

        # Load and verify structure
        df = pd.read_csv(processed_path)

        # Should have all expected columns
        expected_columns = ["tokens", "hash", "language", "filepath", "label"]
        assert all(col in df.columns for col in expected_columns)

        # Should have all 4 categories
        labels = set(df["label"].values)
        expected_labels = {"benign", "malicious", "suspicious", "telemetry"}
        assert expected_labels.issubset(labels)

        # Clean up
        os.unlink(sample_training_csv)
        os.unlink(processed_path)

    def test_category_distribution(self, sample_training_csv):
        """Test that category distribution is preserved correctly."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="_processed.csv", delete=False
        ) as f:
            processed_path = f.name

        configure_messaging(quiet=True)
        process_unified_csv(sample_training_csv, processed_path)

        # Load both files and compare distributions
        original_df = pd.read_csv(sample_training_csv)
        processed_df = pd.read_csv(processed_path)

        original_counts = original_df["label"].value_counts().sort_index()
        processed_counts = processed_df["label"].value_counts().sort_index()

        # Should be identical (no samples should be lost or changed)
        pd.testing.assert_series_equal(original_counts, processed_counts)

        # Clean up
        os.unlink(sample_training_csv)
        os.unlink(processed_path)

    def test_tokenizer_training(self, processed_csv):
        """Test that tokenizer training works with CSV."""
        configure_messaging(quiet=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_tokenizer"

            # Create args object for tokenizer training
            class Args:
                def __init__(self):
                    self.training = processed_csv
                    self.output_path = output_path
                    self.top_n_tokens = 100  # Small for testing
                    self.force_retrain = True
                    self.save_computed_tokens = True
                    self.function_mapping_path = Path(
                        "src/common/syntax_mapping/function_mapping.json"
                    )
                    self.vocab_size = 1000  # Small for testing
                    self.max_length = 128
                    self.token_column = "tokens"

            args = Args()

            # Should not raise any exceptions
            train_tokenizer(args)

            # Check that tokenizer files were created
            assert (output_path / "tokenizer.json").exists()
            # Check for either vocab.json or tokenizer_config.json (modern tokenizers use different files)
            tokenizer_files = list(output_path.glob("*.json"))
            assert len(tokenizer_files) > 0, (
                f"No tokenizer files found in {output_path}"
            )

        # Clean up
        os.unlink(processed_csv)

    def test_distilbert_training_args(self, processed_csv):
        """Test that DistilBERT training can be configured with CSV."""
        configure_messaging(quiet=True)

        # Test that we can create proper args for training
        class Args:
            def __init__(self):
                self.training = processed_csv
                self.tokenizer_path = Path("malwi_models")
                self.model_output_path = Path("test_model")
                self.model_name = "distilbert-base-uncased"
                self.max_length = 128
                self.window_stride = 64
                self.epochs = 1
                self.batch_size = 2
                self.vocab_size = 1000
                self.save_steps = 0
                self.num_proc = 1
                self.hidden_size = 256
                self.token_column = "tokens"

        args = Args()

        # Verify we can access the training file
        df = pd.read_csv(args.training)
        assert "label" in df.columns
        assert len(df) > 0

        # Verify all categories are present
        labels = set(df["label"].values)
        expected_labels = {"benign", "malicious", "suspicious", "telemetry"}
        assert expected_labels.issubset(labels)

        # Clean up
        os.unlink(processed_csv)

    def test_load_asts_from_unified_csv(self, processed_csv):
        """Test that load_asts_from_csv works correctly with categories."""
        from research.train_distilbert import load_asts_from_csv

        configure_messaging(quiet=True)

        # Load data
        asts, labels = load_asts_from_csv(processed_csv, "tokens", "label")

        # Should have loaded data
        assert len(asts) > 0
        assert len(labels) > 0
        assert len(asts) == len(labels)

        # Should have all 4 categories
        unique_labels = set(labels)
        expected_labels = {"benign", "malicious", "suspicious", "telemetry"}
        assert expected_labels.issubset(unique_labels)

        # Clean up
        os.unlink(processed_csv)

    def test_benign_ratio_balancing(self):
        """Test that benign ratio balancing works correctly."""
        from research.train_distilbert import load_asts_from_csv
        from collections import Counter
        import numpy as np

        # Create test data with imbalanced benign samples
        data = {
            "tokens": [
                "import os",
                "print hello",
                "eval data",
                "def func",
                "len list",
                "os system",
            ],
            "hash": ["hash1", "hash2", "hash3", "hash4", "hash5", "hash6"],
            "language": ["python"] * 6,
            "filepath": [
                "/test/b1.py",
                "/test/b2.py",
                "/test/m1.py",
                "/test/b3.py",
                "/test/b4.py",
                "/test/m2.py",
            ],
            "label": [
                "benign",
                "benign",
                "malicious",
                "benign",
                "benign",
                "malicious",
            ],  # 4 benign, 2 others
        }

        df = pd.DataFrame(data)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            df.to_csv(f.name, index=False)
            test_csv = f.name

        configure_messaging(quiet=True)

        # Load data
        training_asts, training_labels = load_asts_from_csv(test_csv, "tokens", "label")

        # Original distribution
        original_counts = Counter(training_labels)
        assert original_counts["benign"] == 4
        assert original_counts["malicious"] == 2

        # Simulate balancing with ratio 1.0 (1:1 benign:others)
        benign_indices = [
            i for i, label in enumerate(training_labels) if label == "benign"
        ]
        non_benign_indices = [
            i for i, label in enumerate(training_labels) if label != "benign"
        ]

        benign_asts = [training_asts[i] for i in benign_indices]
        non_benign_asts = [training_asts[i] for i in non_benign_indices]

        benign_ratio = 1.0
        if len(benign_asts) > len(non_benign_asts) * benign_ratio:
            target_benign_count = int(len(non_benign_asts) * benign_ratio)
            rng = np.random.RandomState(42)
            selected_indices = rng.choice(
                len(benign_asts), size=target_benign_count, replace=False
            )
            balanced_benign = [benign_asts[i] for i in selected_indices]
        else:
            balanced_benign = benign_asts

        # Should downsample from 4 to 2 benign samples (1:1 ratio with 2 non-benign)
        assert len(balanced_benign) == 2
        assert len(non_benign_asts) == 2

        # Clean up
        os.unlink(test_csv)

    def teardown_method(self):
        """Clean up any remaining temporary files."""
        # Remove any test files that might be left behind
        test_files = ["test_training.csv", "test_training_processed.csv"]

        for file_path in test_files:
            if Path(file_path).exists():
                os.unlink(file_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
