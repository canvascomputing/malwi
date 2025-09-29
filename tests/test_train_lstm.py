import pytest
import tempfile
import numpy as np
import torch
import csv
from pathlib import Path
from unittest.mock import patch, MagicMock

from research.train_lstm import (
    MalwareSequenceDataset,
    MalwareLSTM,
    collate_fn,
    load_embeddings_data,
    train_lstm_model,
)


class TestMalwareSequenceDataset:
    @pytest.fixture
    def sample_data(self):
        """Create sample malicious packages and benign embeddings."""
        # Create 4-dimensional embeddings for testing
        malicious_packages = {
            "package_1": [
                np.array([0.1, 0.2, 0.3, 0.4], dtype=np.float32),
                np.array([0.5, 0.6, 0.7, 0.8], dtype=np.float32),
            ],
            "package_2": [
                np.array([0.9, 1.0, 1.1, 1.2], dtype=np.float32),
            ],
        }

        benign_embeddings = [
            np.array([1.3, 1.4, 1.5, 1.6], dtype=np.float32),
            np.array([1.7, 1.8, 1.9, 2.0], dtype=np.float32),
            np.array([2.1, 2.2, 2.3, 2.4], dtype=np.float32),
        ]

        return malicious_packages, benign_embeddings

    def test_dataset_creation(self, sample_data):
        """Test basic dataset creation."""
        malicious_packages, benign_embeddings = sample_data

        dataset = MalwareSequenceDataset(
            malicious_packages=malicious_packages,
            benign_embeddings=benign_embeddings,
            max_benign_samples=2,
            random_seed=42,
        )

        # Should have 2 malicious sequences + some benign sequences
        assert len(dataset) >= 2
        assert len(dataset.sequences) == len(dataset.labels)

        # Check that we have both malicious and benign sequences
        unique_labels = set(dataset.labels)
        assert 0 in unique_labels  # Benign
        assert 1 in unique_labels  # Malicious

    def test_malicious_sequences_structure(self, sample_data):
        """Test that malicious sequences have the correct structure."""
        malicious_packages, benign_embeddings = sample_data

        dataset = MalwareSequenceDataset(
            malicious_packages=malicious_packages,
            benign_embeddings=benign_embeddings,
            max_benign_samples=1,
            random_seed=42,
        )

        # Find malicious sequences
        malicious_indices = [i for i, label in enumerate(dataset.labels) if label == 1]

        assert len(malicious_indices) == 2  # One per package

        for idx in malicious_indices:
            sequence = dataset.sequences[idx]
            # Each sequence should have at least one embedding
            assert len(sequence) >= 1
            # All embeddings should be numpy arrays with correct shape
            for emb in sequence:
                assert isinstance(emb, np.ndarray)
                assert emb.shape == (4,)

    def test_dataset_getitem(self, sample_data):
        """Test dataset __getitem__ method."""
        malicious_packages, benign_embeddings = sample_data

        dataset = MalwareSequenceDataset(
            malicious_packages=malicious_packages,
            benign_embeddings=benign_embeddings,
            max_benign_samples=2,
            random_seed=42,
        )

        sequence_tensor, label_tensor = dataset[0]

        # Check tensor types and shapes
        assert isinstance(sequence_tensor, torch.Tensor)
        assert isinstance(label_tensor, torch.Tensor)
        assert sequence_tensor.dtype == torch.float32
        assert label_tensor.dtype == torch.long
        assert sequence_tensor.shape[1] == 4  # Embedding dimension
        assert label_tensor.shape == torch.Size([])  # Scalar

    def test_reproducible_sampling(self, sample_data):
        """Test that sampling is reproducible with fixed seed."""
        malicious_packages, benign_embeddings = sample_data

        dataset1 = MalwareSequenceDataset(
            malicious_packages=malicious_packages,
            benign_embeddings=benign_embeddings,
            max_benign_samples=2,
            random_seed=42,
        )

        dataset2 = MalwareSequenceDataset(
            malicious_packages=malicious_packages,
            benign_embeddings=benign_embeddings,
            max_benign_samples=2,
            random_seed=42,
        )

        # Should have same number of sequences
        assert len(dataset1) == len(dataset2)
        assert dataset1.labels == dataset2.labels


class TestMalwareLSTM:
    def test_model_initialization(self):
        """Test LSTM model initialization."""
        model = MalwareLSTM(
            embedding_dim=256,
            hidden_dim=128,
            num_layers=2,
            dropout=0.3,
        )

        assert model.embedding_dim == 256
        assert model.hidden_dim == 128
        assert model.num_layers == 2

        # Check layer types
        assert isinstance(model.lstm, torch.nn.LSTM)
        assert isinstance(model.classifier, torch.nn.Sequential)

    def test_model_forward_pass(self):
        """Test forward pass with sample data."""
        model = MalwareLSTM(embedding_dim=4, hidden_dim=8, num_layers=1)

        # Create sample input
        batch_size, seq_len, embedding_dim = 2, 3, 4
        sequences = torch.randn(batch_size, seq_len, embedding_dim)
        attention_mask = torch.ones(batch_size, seq_len, dtype=torch.bool)

        # Forward pass
        logits = model(sequences, attention_mask)

        # Check output shape
        assert logits.shape == (batch_size, 2)  # 2 classes

    def test_model_forward_with_padding(self):
        """Test forward pass with padded sequences."""
        model = MalwareLSTM(embedding_dim=4, hidden_dim=8, num_layers=1)

        # Create sample input with different sequence lengths
        batch_size, max_seq_len, embedding_dim = 2, 5, 4
        sequences = torch.zeros(batch_size, max_seq_len, embedding_dim)

        # First sequence has length 3, second has length 2
        sequences[0, :3] = torch.randn(3, embedding_dim)
        sequences[1, :2] = torch.randn(2, embedding_dim)

        attention_mask = torch.tensor(
            [[True, True, True, False, False], [True, True, False, False, False]]
        )

        # Forward pass
        logits = model(sequences, attention_mask)

        # Check output shape
        assert logits.shape == (batch_size, 2)


class TestCollateFn:
    def test_collate_basic(self):
        """Test collate function with variable-length sequences."""
        # Create sample batch data
        seq1 = torch.randn(3, 4)  # Length 3
        seq2 = torch.randn(2, 4)  # Length 2
        seq3 = torch.randn(4, 4)  # Length 4

        batch = [
            (seq1, torch.tensor(1)),
            (seq2, torch.tensor(0)),
            (seq3, torch.tensor(1)),
        ]

        padded_sequences, attention_mask, labels = collate_fn(batch)

        # Check shapes
        assert padded_sequences.shape == (3, 4, 4)  # batch_size, max_len, embedding_dim
        assert attention_mask.shape == (3, 4)
        assert labels.shape == (3,)

        # Check padding correctness
        assert torch.equal(padded_sequences[0, :3], seq1)
        assert torch.equal(padded_sequences[1, :2], seq2)
        assert torch.equal(padded_sequences[2, :4], seq3)

        # Check attention mask
        expected_mask = torch.tensor(
            [
                [True, True, True, False],
                [True, True, False, False],
                [True, True, True, True],
            ]
        )
        assert torch.equal(attention_mask, expected_mask)

    def test_collate_same_length(self):
        """Test collate function when all sequences have same length."""
        seq1 = torch.randn(3, 4)
        seq2 = torch.randn(3, 4)

        batch = [
            (seq1, torch.tensor(1)),
            (seq2, torch.tensor(0)),
        ]

        padded_sequences, attention_mask, labels = collate_fn(batch)

        # No padding should be needed
        assert padded_sequences.shape == (2, 3, 4)
        assert torch.all(attention_mask)  # All True


class TestLoadEmbeddingsData:
    @pytest.fixture
    def sample_embedding_csv(self):
        """Create a sample CSV with embeddings."""
        emb1 = np.array([0.1, 0.2, 0.3, 0.4], dtype=np.float32)
        emb2 = np.array([0.5, 0.6, 0.7, 0.8], dtype=np.float32)
        emb3 = np.array([0.9, 1.0, 1.1, 1.2], dtype=np.float32)

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
                "LOAD_CONST benign",
                "hash3",
                "python",
                "/benign.py",
                "benign",
                "",
                ",".join(map(str, emb3)),
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

    def test_load_embeddings_data(self, sample_embedding_csv):
        """Test loading embeddings data from CSV."""
        malicious_packages, benign_embeddings = load_embeddings_data(
            sample_embedding_csv
        )

        assert len(malicious_packages) == 1
        assert "package_1" in malicious_packages
        assert len(malicious_packages["package_1"]) == 2

        assert len(benign_embeddings) == 1
        assert isinstance(benign_embeddings[0], np.ndarray)


class TestTrainLSTMModel:
    @pytest.fixture
    def sample_embedding_csv(self):
        """Create a larger sample CSV for training."""
        # Create more realistic training data
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package", "embedding"]
        ]

        # Add malicious packages
        for pkg_id in range(3):
            for file_id in range(2):
                emb = np.random.rand(4).astype(np.float32)
                csv_content.append(
                    [
                        f"MAL_CODE_{pkg_id}_{file_id}",
                        f"hash_{pkg_id}_{file_id}",
                        "python",
                        f"/pkg{pkg_id}/file{file_id}.py",
                        "malicious",
                        f"package_{pkg_id}",
                        ",".join(map(str, emb)),
                    ]
                )

        # Add benign samples
        for sample_id in range(10):
            emb = np.random.rand(4).astype(np.float32)
            csv_content.append(
                [
                    f"BENIGN_{sample_id}",
                    f"hash_benign_{sample_id}",
                    "python",
                    f"/benign{sample_id}.py",
                    "benign",
                    "",
                    ",".join(map(str, emb)),
                ]
            )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerows(csv_content)
            temp_file_path = f.name

        yield temp_file_path
        Path(temp_file_path).unlink()

    def test_train_lstm_model_basic(self, sample_embedding_csv):
        """Test basic LSTM training (short run for testing)."""
        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as f:
            model_path = f.name

        try:
            success = train_lstm_model(
                csv_path=sample_embedding_csv,
                output_model_path=model_path,
                epochs=1,  # Short training for testing
                batch_size=2,
                learning_rate=0.01,
                hidden_dim=8,
                num_layers=1,
                max_benign_samples=3,
                device="cpu",
            )

            assert success
            assert Path(model_path).exists()

        finally:
            if Path(model_path).exists():
                Path(model_path).unlink()

    def test_train_lstm_model_missing_file(self):
        """Test error handling for missing CSV file."""
        success = train_lstm_model(
            csv_path="nonexistent.csv",
            output_model_path="test_model.pth",
            epochs=1,
            device="cpu",
        )

        assert not success

    @patch("research.train_lstm.load_embeddings_data")
    def test_train_lstm_model_no_data(self, mock_load):
        """Test error handling when no data is loaded."""
        mock_load.return_value = ({}, [])  # Empty data

        success = train_lstm_model(
            csv_path="dummy.csv",
            output_model_path="test_model.pth",
            epochs=1,
            device="cpu",
        )

        assert not success
