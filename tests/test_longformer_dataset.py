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
    LongformerFileDataset,
    LongformerObjectDataset,
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

            # When there are no malicious packages, benign samples are filtered out
            # This is expected behavior - the dataset is for training on malicious vs benign
            assert len(dataset.package_data) == 0
            assert len(dataset.training_samples) == 0

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
            train_csv=sample_csv,
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
            train_csv=sample_csv,
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


class TestLongformerFileDataset:
    @pytest.fixture
    def sample_csv_file(self):
        """Create sample CSV data for file-based testing."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            csv_path = f.name
            writer = csv.writer(f)
            writer.writerow(["tokens", "label", "filepath", "package", "hash"])

            # File 1 has 2 malicious objects
            writer.writerow(
                ["LOAD_CONST url CALL_FUNCTION", "malicious", "/file1.py", "pkg1", "h1"]
            )
            writer.writerow(
                [
                    "LOAD_CONST eval CALL_FUNCTION",
                    "malicious",
                    "/file1.py",
                    "pkg1",
                    "h2",
                ]
            )

            # File 2 has 2 benign objects
            writer.writerow(
                ["LOAD_CONST x RETURN_VALUE", "benign", "/file2.py", "pkg2", "h3"]
            )
            writer.writerow(
                ["LOAD_CONST y BINARY_ADD", "benign", "/file2.py", "pkg2", "h4"]
            )

        yield csv_path
        Path(csv_path).unlink()

    def test_file_dataset_groups_by_filepath(self, sample_csv_file):
        """Test that file dataset groups objects by filepath."""
        dataset = LongformerFileDataset(
            csv_path=sample_csv_file,
            tokenizer_path="distilbert-base-uncased",
            max_length=512,
        )

        # Should have 2 files
        assert len(dataset.file_data) == 2
        assert "/file1.py" in dataset.file_data
        assert "/file2.py" in dataset.file_data

        # Each file should have 2 objects
        assert len(dataset.file_data["/file1.py"]) == 2
        assert len(dataset.file_data["/file2.py"]) == 2

    def test_file_dataset_creates_one_sample_per_file(self, sample_csv_file):
        """Test that file dataset creates one training sample per file."""
        dataset = LongformerFileDataset(
            csv_path=sample_csv_file,
            tokenizer_path="distilbert-base-uncased",
            max_length=512,
        )

        # Should have 2 training samples (one per file)
        assert len(dataset) == 2

    def test_file_dataset_sample_format(self, sample_csv_file):
        """Test that file dataset samples have correct format."""
        dataset = LongformerFileDataset(
            csv_path=sample_csv_file,
            tokenizer_path="distilbert-base-uncased",
            max_length=512,
        )

        sample = dataset[0]

        assert "filepath" in sample
        assert "input_ids" in sample
        assert "attention_mask" in sample
        assert "global_attention_mask" in sample
        assert "labels" in sample
        assert "object_count" in sample

    def test_file_dataset_benign_sampling(self):
        """Test that file dataset creates random benign files based on malicious count."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            csv_path = f.name
            writer = csv.writer(f)
            writer.writerow(["tokens", "label", "filepath", "package", "hash"])

            # 2 malicious files
            writer.writerow(
                ["LOAD_CONST url CALL_FUNCTION", "malicious", "/mal1.py", "pkg1", "h1"]
            )
            writer.writerow(
                ["LOAD_CONST eval CALL_FUNCTION", "malicious", "/mal2.py", "pkg2", "h2"]
            )

            # 10 benign objects from different files
            for i in range(10):
                writer.writerow(
                    [
                        f"LOAD_CONST x{i} RETURN_VALUE",
                        "benign",
                        f"/benign{i}.py",
                        "pkg",
                        f"h{i + 3}",
                    ]
                )

        try:
            # With benign_ratio=4, should create 2 * 4 = 8 benign files
            dataset = LongformerFileDataset(
                csv_path=csv_path,
                tokenizer_path="distilbert-base-uncased",
                max_length=512,
                benign_ratio=4,
                max_benign_samples_per_file=3,
            )

            # Should have 2 malicious + 8 benign = 10 files
            assert len(dataset) == 10

            # Check that we have the right number of each type
            malicious_count = sum(
                1
                for sample in dataset.training_samples
                if any(label != "benign" for label in sample.get("file_labels", []))
            )
            assert malicious_count == 2

        finally:
            Path(csv_path).unlink()


class TestLongformerObjectDataset:
    @pytest.fixture
    def sample_csv_object(self):
        """Create sample CSV data for object-based testing."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            csv_path = f.name
            writer = csv.writer(f)
            writer.writerow(["tokens", "label", "filepath", "package", "hash"])

            writer.writerow(
                ["LOAD_CONST url CALL_FUNCTION", "malicious", "/file1.py", "pkg1", "h1"]
            )
            writer.writerow(
                [
                    "LOAD_CONST eval CALL_FUNCTION",
                    "suspicious",
                    "/file1.py",
                    "pkg1",
                    "h2",
                ]
            )
            writer.writerow(
                ["LOAD_CONST x RETURN_VALUE", "benign", "/file2.py", "pkg2", "h3"]
            )

        yield csv_path
        Path(csv_path).unlink()

    def test_object_dataset_creates_one_sample_per_object(self, sample_csv_object):
        """Test that object dataset creates one training sample per CodeObject."""
        dataset = LongformerObjectDataset(
            csv_path=sample_csv_object,
            tokenizer_path="distilbert-base-uncased",
            max_length=512,
        )

        # Should have 3 training samples (one per object)
        assert len(dataset) == 3

    def test_object_dataset_sample_format(self, sample_csv_object):
        """Test that object dataset samples have correct format."""
        dataset = LongformerObjectDataset(
            csv_path=sample_csv_object,
            tokenizer_path="distilbert-base-uncased",
            max_length=512,
        )

        sample = dataset[0]

        assert "object_id" in sample
        assert "filepath" in sample
        assert "package" in sample
        assert "input_ids" in sample
        assert "attention_mask" in sample
        assert "global_attention_mask" in sample
        assert "labels" in sample
        assert "label_name" in sample

    def test_object_dataset_preserves_individual_labels(self, sample_csv_object):
        """Test that object dataset preserves individual object labels."""
        dataset = LongformerObjectDataset(
            csv_path=sample_csv_object,
            tokenizer_path="distilbert-base-uncased",
            max_length=512,
        )

        # Check that different objects have different labels
        labels = [sample["label_name"] for sample in dataset.training_samples]
        assert "malicious" in labels
        assert "suspicious" in labels
        assert "benign" in labels

    def test_object_dataset_benign_sampling(self):
        """Test that object dataset picks one random benign per malicious object."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            csv_path = f.name
            writer = csv.writer(f)
            writer.writerow(["tokens", "label"])

            # 2 malicious objects
            writer.writerow(["LOAD_CONST url CALL_FUNCTION", "malicious"])
            writer.writerow(["LOAD_CONST eval CALL_FUNCTION", "malicious"])

            # 5 benign objects
            for i in range(5):
                writer.writerow([f"LOAD_CONST x{i} RETURN_VALUE", "benign"])

        try:
            dataset = LongformerObjectDataset(
                csv_path=csv_path,
                tokenizer_path="distilbert-base-uncased",
                max_length=512,
            )

            # Should have 2 malicious + 2 random benign (1 per malicious) = 4 total
            assert len(dataset) == 4

            # Count labels
            labels = [sample["label_name"] for sample in dataset.training_samples]
            assert labels.count("malicious") == 2
            assert labels.count("benign") == 2

        finally:
            Path(csv_path).unlink()


class TestDataloaderStrategies:
    @pytest.fixture
    def strategy_csv(self):
        """Create CSV for testing different strategies."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            csv_path = f.name
            writer = csv.writer(f)
            writer.writerow(["tokens", "label", "filepath", "package", "hash"])

            for i in range(10):
                writer.writerow(
                    [
                        f"LOAD_CONST var{i} STORE_GLOBAL",
                        "malicious" if i % 2 == 0 else "benign",
                        f"/file{i % 3}.py",
                        f"package_{i % 2}",
                        f"hash{i}",
                    ]
                )

        yield csv_path
        Path(csv_path).unlink()

    def test_create_dataloaders_with_package_strategy(self, strategy_csv):
        """Test dataloader creation with package strategy."""
        train_loader, val_loader = create_longformer_dataloaders(
            train_csv=strategy_csv,
            strategy="package",
            tokenizer_path="distilbert-base-uncased",
            batch_size=2,
            max_length=512,
            val_split=0.2,
        )

        assert train_loader is not None
        assert val_loader is not None

    def test_create_dataloaders_with_file_strategy(self, strategy_csv):
        """Test dataloader creation with file strategy."""
        train_loader, val_loader = create_longformer_dataloaders(
            train_csv=strategy_csv,
            strategy="file",
            tokenizer_path="distilbert-base-uncased",
            batch_size=2,
            max_length=512,
            val_split=0.2,
        )

        assert train_loader is not None
        assert val_loader is not None

    def test_create_dataloaders_with_object_strategy(self, strategy_csv):
        """Test dataloader creation with object strategy."""
        train_loader, val_loader = create_longformer_dataloaders(
            train_csv=strategy_csv,
            strategy="object",
            tokenizer_path="distilbert-base-uncased",
            batch_size=2,
            max_length=512,
            val_split=0.2,
        )

        assert train_loader is not None
        assert val_loader is not None

    def test_create_dataloaders_invalid_strategy(self, strategy_csv):
        """Test that invalid strategy raises ValueError."""
        with pytest.raises(ValueError, match="Unknown strategy"):
            create_longformer_dataloaders(
                train_csv=strategy_csv,
                strategy="invalid",
                tokenizer_path="distilbert-base-uncased",
                batch_size=2,
                max_length=512,
            )
