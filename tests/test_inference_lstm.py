import pytest
import tempfile
import numpy as np
import torch
from pathlib import Path
from unittest.mock import MagicMock

from common.predict_lstm import (
    MalwareLSTM,
    get_sequence_lstm_prediction,
    run_lstm_sequence_analysis,
    initialize_lstm_model,
    analyze_object_sequences_with_lstm,
)


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

    def test_model_forward_pass(self):
        """Test forward pass of LSTM model."""
        model = MalwareLSTM(embedding_dim=4, hidden_dim=8, num_layers=1)

        # Create sample input
        batch_size, seq_len, embedding_dim = 2, 3, 4
        sequences = torch.randn(batch_size, seq_len, embedding_dim)
        attention_mask = torch.ones(batch_size, seq_len, dtype=torch.bool)

        # Forward pass
        logits = model(sequences, attention_mask)

        # Check output shape
        assert logits.shape == (batch_size, 2)  # 2 classes


class TestLSTMPrediction:
    @pytest.fixture
    def mock_model_path(self):
        """Create a temporary model file."""
        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as f:
            # Save a dummy model state with default dimensions
            model = MalwareLSTM(embedding_dim=256, hidden_dim=128, num_layers=2)
            torch.save(model.state_dict(), f.name)
            temp_path = f.name

        yield temp_path
        Path(temp_path).unlink()

    def test_initialize_lstm_model(self, mock_model_path):
        """Test LSTM model initialization."""
        initialize_lstm_model(mock_model_path)
        # Test passes if no exception is raised

    def test_get_sequence_lstm_prediction(self, mock_model_path):
        """Test sequence prediction function."""
        initialize_lstm_model(mock_model_path)

        # Create sample embeddings with correct dimension (256)
        embeddings = [
            np.random.rand(256).astype(np.float32),
            np.random.rand(256).astype(np.float32),
        ]

        result = get_sequence_lstm_prediction(embeddings)

        assert result["status"] == "success"
        assert result["prediction"] in ["benign", "malicious"]
        assert 0.0 <= result["confidence"] <= 1.0
        assert "probabilities" in result

    def test_predict_empty_sequence(self, mock_model_path):
        """Test prediction with empty sequence."""
        initialize_lstm_model(mock_model_path)

        result = get_sequence_lstm_prediction([])

        assert result["status"] == "error"
        assert "No embeddings provided" in result["message"]

    def test_analyze_object_sequences(self, mock_model_path):
        """Test analyzing object sequences."""
        initialize_lstm_model(mock_model_path)

        # Create mock objects with embeddings
        obj1 = MagicMock()
        obj1.file_path = "file1.py"
        obj1.embedding = np.random.rand(256).astype(np.float32)

        obj2 = MagicMock()
        obj2.file_path = "file2.py"
        obj2.embedding = np.random.rand(256).astype(np.float32)

        results = analyze_object_sequences_with_lstm([obj1, obj2])

        assert "sequences" in results
        assert "overall" in results
        assert results["overall"]["prediction"] in ["benign", "malicious"]
        assert 0.0 <= results["overall"]["confidence"] <= 1.0


class TestRunLSTMAnalysis:
    @pytest.fixture
    def mock_objects(self):
        """Create mock MalwiObjects."""
        obj1 = MagicMock()
        obj1.name = "malicious_func"
        obj1.file_path = "malware.py"
        obj1.embedding = np.random.rand(256).astype(np.float32)

        obj2 = MagicMock()
        obj2.name = "benign_func"
        obj2.file_path = "benign.py"
        obj2.embedding = np.random.rand(256).astype(np.float32)

        return [obj1, obj2]

    @pytest.fixture
    def mock_lstm_model(self):
        """Create a temporary LSTM model file."""
        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as f:
            model = MalwareLSTM(embedding_dim=256, hidden_dim=128, num_layers=2)
            torch.save(model.state_dict(), f.name)
            temp_path = f.name

        yield temp_path
        Path(temp_path).unlink()

    def test_run_lstm_analysis_success(self, mock_objects, mock_lstm_model):
        """Test successful LSTM analysis run."""
        initialize_lstm_model(mock_lstm_model)

        results = run_lstm_sequence_analysis(mock_objects)

        assert "overall" in results
        assert "sequences" in results
        assert results["objects_analyzed"] == 2
        assert results["objects_skipped"] == 0

    def test_run_lstm_analysis_no_objects(self):
        """Test LSTM analysis with no objects."""
        results = run_lstm_sequence_analysis([])

        assert results["status"] == "error"
        assert results["message"] == "No objects to analyze"

    def test_run_lstm_analysis_no_embeddings(self, mock_lstm_model):
        """Test LSTM analysis with objects without embeddings."""
        initialize_lstm_model(mock_lstm_model)

        obj = MagicMock()
        obj.name = "test_func"
        obj.file_path = "test.py"
        obj.embedding = None

        results = run_lstm_sequence_analysis([obj])

        assert results["status"] == "error"
        assert "No objects have embeddings" in results["message"]
