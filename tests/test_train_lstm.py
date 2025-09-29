import pytest
import tempfile
import numpy as np
import torch
import csv
from pathlib import Path
from unittest.mock import patch, MagicMock

from research.train_lstm import (
    MalwareDataset,
    MalwareLSTM,
    train_lstm_model,
)


class TestMalwareDataset:
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

        dataset = MalwareDataset(
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

        dataset = MalwareDataset(
            malicious_packages=malicious_packages,
            benign_embeddings=benign_embeddings,
            max_benign_samples=20,  # Allow enough benign samples for mixed sequences
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

        dataset = MalwareDataset(
            malicious_packages=malicious_packages,
            benign_embeddings=benign_embeddings,
            max_benign_samples=2,
            random_seed=42,
        )

        sequence, label = dataset[0]

        # Check types
        assert isinstance(sequence, list)
        assert isinstance(label, int)
        # Check that sequence contains numpy arrays
        for emb in sequence:
            assert isinstance(emb, np.ndarray)
            assert emb.shape[0] == 4  # Embedding dimension

    def test_reproducible_sampling(self, sample_data):
        """Test that sampling is reproducible with fixed seed."""
        malicious_packages, benign_embeddings = sample_data

        dataset1 = MalwareDataset(
            malicious_packages=malicious_packages,
            benign_embeddings=benign_embeddings,
            max_benign_samples=2,
            random_seed=42,
        )

        dataset2 = MalwareDataset(
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


class TestTrainLSTMModel:
    @pytest.fixture
    def sample_embedding_csv(self):
        """Create a sample CSV for training."""
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package", "embedding"]
        ]

        # Add malicious packages
        for pkg_id in range(2):
            for file_id in range(2):
                emb = np.random.rand(8).astype(np.float32)  # Match hidden_dim
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
        for sample_id in range(8):
            emb = np.random.rand(8).astype(np.float32)  # Match hidden_dim
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
                output_model=model_path,
                epochs=1,  # Short training for testing
                batch_size=2,
                learning_rate=0.01,
                embedding_dim=8,  # Match test data
                hidden_dim=8,
                num_layers=1,
                max_benign_samples=3,
                use_focal_loss=False,
            )

            assert success
            assert Path(model_path).exists()

        finally:
            if Path(model_path).exists():
                Path(model_path).unlink()

    def test_train_lstm_model_missing_file(self):
        """Test error handling for missing CSV file."""
        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as f:
            model_path = f.name

        try:
            success = train_lstm_model(
                csv_path="nonexistent.csv",
                output_model=model_path,
                epochs=1,
            )

            assert not success
        finally:
            if Path(model_path).exists():
                Path(model_path).unlink()
