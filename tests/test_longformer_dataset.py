"""
Tests for LongformerPackageDataset and related utilities.
"""

import pytest
import tempfile
import csv
import pandas as pd
from pathlib import Path

from research.longformer_dataset import (
    LongformerPackageDataset,
    create_longformer_dataloaders,
    longformer_collate_fn,
)


class TestLongformerPackageDataset:
    @pytest.fixture
    def sample_csv_data(self):
        """Create sample CSV data for testing."""
        return [
            {
                "tokens": "LOAD_CONST var1 STORE_GLOBAL var1 LOAD_CONST print CALL_FUNCTION",
                "label": "malicious",
                "package": "evil_package",
                "filepath": "/path/to/evil_package/file1.py",
                "hash": "hash1",
            },
            {
                "tokens": "LOAD_CONST var2 BINARY_ADD RETURN_VALUE",
                "label": "malicious",
                "package": "evil_package",
                "filepath": "/path/to/evil_package/file2.py",
                "hash": "hash2",
            },
            {
                "tokens": "LOAD_CONST num BINARY_MULTIPLY STORE_LOCAL result",
                "label": "benign",
                "package": "good_repo",
                "filepath": "/path/to/good_repo/utils.py",
                "hash": "hash3",
            },
            {
                "tokens": "LOAD_CONST msg LOAD_CONST print CALL_FUNCTION RETURN_VALUE",
                "label": "benign",
                "package": "good_repo",
                "filepath": "/path/to/good_repo/main.py",
                "hash": "hash4",
            },
            {
                "tokens": "LOAD_CONST data LOAD_METHOD json dumps CALL_METHOD",
                "label": "benign",
                "package": "another_repo",
                "filepath": "/path/to/another_repo/api.py",
                "hash": "hash5",
            },
        ]

    @pytest.fixture
    def csv_file(self, sample_csv_data):
        """Create temporary CSV file with sample data."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            csv_path = f.name
            fieldnames = ["tokens", "label", "package", "filepath", "hash"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(sample_csv_data)

        yield csv_path
        Path(csv_path).unlink()

    def test_dataset_loads_csv(self, csv_file):
        """Test that dataset successfully loads CSV data."""
        dataset = LongformerPackageDataset(
            csv_path=csv_file,
            tokenizer_path="distilbert-base-uncased",
            max_length=512,
            min_objects_per_package=1,
        )

        assert len(dataset) > 0, "Dataset should have at least one training sample"
        assert len(dataset.package_data) >= 1, "Should have at least one package"

    def test_dataset_groups_by_package(self, csv_file):
        """Test that dataset correctly groups code objects by package."""
        dataset = LongformerPackageDataset(
            csv_path=csv_file,
            tokenizer_path="distilbert-base-uncased",
            max_length=512,
            min_objects_per_package=1,
        )

        # evil_package should have 2 code objects
        assert "evil_package" in dataset.package_data
        assert len(dataset.package_data["evil_package"]) == 2

    def test_dataset_filters_by_min_objects(self, csv_file):
        """Test that dataset filters out packages with too few objects."""
        dataset = LongformerPackageDataset(
            csv_path=csv_file,
            tokenizer_path="distilbert-base-uncased",
            max_length=512,
            min_objects_per_package=3,  # Require at least 3 objects
        )

        # evil_package has only 2 objects, good_repo has 2, another_repo has 1
        # All should be filtered out
        assert len(dataset.package_data) == 0

    def test_dataset_getitem_returns_correct_format(self, csv_file):
        """Test that __getitem__ returns data in expected format."""
        dataset = LongformerPackageDataset(
            csv_path=csv_file,
            tokenizer_path="distilbert-base-uncased",
            max_length=512,
            min_objects_per_package=1,
        )

        # Get first sample
        sample = dataset[0]

        # Check expected keys
        assert "input_ids" in sample
        assert "attention_mask" in sample
        assert "global_attention_mask" in sample
        assert "labels" in sample

        # Check tensor shapes
        assert sample["input_ids"].shape[0] <= 512
        assert sample["attention_mask"].shape[0] <= 512
        assert sample["global_attention_mask"].shape[0] <= 512

    def test_dataset_handles_empty_package_column(self):
        """Test that dataset handles empty or missing package names."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            csv_path = f.name
            writer = csv.writer(f)
            writer.writerow(["tokens", "label", "package", "filepath", "hash"])
            writer.writerow(
                [
                    "LOAD_CONST x STORE_GLOBAL x",
                    "benign",
                    "",  # Empty package
                    "/test.py",
                    "hash1",
                ]
            )
            writer.writerow(
                ["LOAD_CONST y RETURN_VALUE", "benign", "", "/test2.py", "hash2"]
            )

        try:
            dataset = LongformerPackageDataset(
                csv_path=csv_path,
                tokenizer_path="distilbert-base-uncased",
                max_length=512,
                min_objects_per_package=1,
            )

            # Should replace empty with "unknown" and group them together
            assert "unknown" in dataset.package_data
            assert len(dataset.package_data["unknown"]) == 2

        finally:
            Path(csv_path).unlink()

    def test_dataset_validates_required_columns(self):
        """Test that dataset raises error when required columns are missing."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            csv_path = f.name
            writer = csv.writer(f)
            # Missing 'package' column
            writer.writerow(["tokens", "label", "filepath"])
            writer.writerow(["LOAD_CONST x", "benign", "/test.py"])

        try:
            with pytest.raises(ValueError, match="CSV must contain columns"):
                dataset = LongformerPackageDataset(
                    csv_path=csv_path,
                    tokenizer_path="distilbert-base-uncased",
                    max_length=512,
                )
        finally:
            Path(csv_path).unlink()


class TestCreateDataloaders:
    @pytest.fixture
    def sample_csv(self):
        """Create a minimal CSV for dataloader testing."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            csv_path = f.name
            writer = csv.writer(f)
            writer.writerow(["tokens", "label", "package", "filepath", "hash"])

            # Create enough data for train/val split
            for i in range(10):
                writer.writerow(
                    [
                        f"LOAD_CONST var{i} STORE_GLOBAL var{i}",
                        "malicious" if i % 2 == 0 else "benign",
                        f"package_{i % 3}",
                        f"/path/file{i}.py",
                        f"hash{i}",
                    ]
                )

        yield csv_path
        Path(csv_path).unlink()

    def test_create_dataloaders_returns_train_and_val(self, sample_csv):
        """Test that create_dataloaders returns training and validation loaders."""
        train_loader, val_loader = create_longformer_dataloaders(
            training_csv=sample_csv,
            tokenizer_path="distilbert-base-uncased",
            batch_size=2,
            max_length=512,
            val_split=0.2,
        )

        assert train_loader is not None
        assert val_loader is not None

    def test_create_dataloaders_no_val_split(self, sample_csv):
        """Test that create_dataloaders works without validation split."""
        train_loader, val_loader = create_longformer_dataloaders(
            training_csv=sample_csv,
            tokenizer_path="distilbert-base-uncased",
            batch_size=2,
            max_length=512,
            val_split=None,
        )

        assert train_loader is not None
        assert val_loader is None


class TestLongformerCollateFunction:
    def test_collate_fn_batches_correctly(self):
        """Test that collate function properly batches samples with equal-length tensors."""
        import torch

        # Create sample batch with equal-length tensors (as required by the collate function)
        batch = [
            {
                "input_ids": torch.tensor([1, 2, 3, 4, 5]),
                "attention_mask": torch.tensor([1, 1, 1, 1, 1]),
                "global_attention_mask": torch.tensor([1, 0, 0, 0, 1]),
                "labels": torch.tensor([1, 0, 0, 0]),  # 4 labels
            },
            {
                "input_ids": torch.tensor([6, 7, 8, 9, 10]),
                "attention_mask": torch.tensor([1, 1, 1, 1, 1]),
                "global_attention_mask": torch.tensor([1, 0, 0, 1, 1]),
                "labels": torch.tensor([0, 1, 0, 0]),  # 4 labels
            },
        ]

        result = longformer_collate_fn(batch)

        # Check that tensors are properly batched
        assert "input_ids" in result
        assert "attention_mask" in result
        assert "global_attention_mask" in result
        assert "labels" in result

        # Batch size should be 2
        assert result["input_ids"].shape[0] == 2
        assert result["labels"].shape[0] == 2

        # Sequences should maintain the same length
        assert result["input_ids"].shape[1] == 5
