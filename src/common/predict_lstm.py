"""
LSTM prediction module for sequence-based malware detection.

This module provides LSTM-based prediction capabilities to analyze sequences
of code objects, complementing the DistilBERT predictions for improved malware detection.
"""

import torch
import torch.nn as nn
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from collections import defaultdict

# Import messaging utilities consistent with predict_distilbert
import sys
import os

# Label constants for consistency with training
BENIGN_LABEL = 0
MALICIOUS_LABEL = 1
PREDICTION_THRESHOLD = 0.5

# Singleton pattern for LSTM model (similar to DistilBERT)
_lstm_model = None
_lstm_model_path = None
_lstm_device = None


def initialize_lstm_model(model_path: Optional[str] = None) -> None:
    """
    Initialize the LSTM model (singleton pattern).

    Args:
        model_path: Path to trained LSTM model file
    """
    global _lstm_model, _lstm_model_path, _lstm_device

    if model_path is None:
        model_path = "malware_lstm_model.pth"

    if not Path(model_path).exists():
        print(f"Warning: LSTM model not found at {model_path}", file=sys.stderr)
        return

    _lstm_model_path = model_path
    _lstm_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Load model
    _lstm_model = MalwareLSTM()
    state_dict = torch.load(_lstm_model_path, map_location=_lstm_device)
    _lstm_model.load_state_dict(state_dict)
    _lstm_model.to(_lstm_device)
    _lstm_model.eval()


def _ensure_lstm_initialized() -> bool:
    """Ensure LSTM model is initialized."""
    if _lstm_model is None:
        initialize_lstm_model()
    return _lstm_model is not None


class MalwareLSTM(nn.Module):
    """LSTM model for malware detection on embedding sequences."""

    def __init__(
        self,
        embedding_dim: int = 256,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
        num_classes: int = 2,
    ):
        """
        Initialize LSTM model.

        Args:
            embedding_dim: Dimension of input embeddings (from DistilBERT)
            hidden_dim: Hidden dimension of LSTM
            num_layers: Number of LSTM layers
            dropout: Dropout rate
            num_classes: Number of output classes (2 for binary classification)
        """
        super().__init__()

        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        # LSTM layers
        self.lstm = nn.LSTM(
            input_size=embedding_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=True,
        )

        # Classification head
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim),  # *2 for bidirectional
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(self, sequences, attention_mask):
        """
        Forward pass.

        Args:
            sequences: Padded sequences [batch_size, seq_len, embedding_dim]
            attention_mask: Attention mask [batch_size, seq_len]

        Returns:
            logits: Classification logits [batch_size, num_classes]
        """
        batch_size, seq_len, _ = sequences.shape

        # LSTM forward pass
        lstm_out, (hidden, cell) = self.lstm(sequences)

        # Use attention mask to get the last valid output for each sequence
        # Find the last non-padded position for each sequence
        lengths = attention_mask.sum(dim=1) - 1  # -1 for 0-indexing

        # Gather the last valid LSTM output for each sequence
        batch_indices = torch.arange(batch_size, device=sequences.device)
        last_outputs = lstm_out[batch_indices, lengths]

        # Classification
        logits = self.classifier(last_outputs)

        return logits


def get_sequence_lstm_prediction(embeddings: List[np.ndarray]) -> Dict[str, Any]:
    """
    Get LSTM prediction for a sequence of embeddings.

    Args:
        embeddings: List of embedding arrays (e.g., from DistilBERT CLS tokens)

    Returns:
        Dictionary containing prediction results
    """
    prediction_result = {
        "status": "pending",
        "prediction": "unknown",
        "confidence": 0.0,
    }

    if not embeddings:
        prediction_result["status"] = "error"
        prediction_result["message"] = "No embeddings provided"
        return prediction_result

    # Ensure model is initialized
    if not _ensure_lstm_initialized():
        prediction_result["status"] = "error"
        prediction_result["message"] = "LSTM model not available"
        return prediction_result

    try:
        with torch.no_grad():
            # Convert embeddings to tensor
            sequence = torch.stack(
                [torch.from_numpy(emb).float() for emb in embeddings]
            )
            sequence = sequence.unsqueeze(0)  # Add batch dimension
            sequence = sequence.to(_lstm_device)

            # Create attention mask
            attention_mask = torch.ones(1, len(embeddings), dtype=torch.bool)
            attention_mask = attention_mask.to(_lstm_device)

            # Get prediction
            logits = _lstm_model(sequence, attention_mask)
            probs = torch.softmax(logits, dim=1)

            malicious_prob = probs[0, MALICIOUS_LABEL].item()
            benign_prob = probs[0, BENIGN_LABEL].item()

            prediction_result["status"] = "success"
            prediction_result["prediction"] = (
                "malicious" if malicious_prob > PREDICTION_THRESHOLD else "benign"
            )
            prediction_result["confidence"] = max(malicious_prob, benign_prob)
            prediction_result["probabilities"] = {
                "benign": benign_prob,
                "malicious": malicious_prob,
            }

    except Exception as e:
        prediction_result["status"] = "error"
        prediction_result["message"] = str(e)

    return prediction_result


def analyze_object_sequences_with_lstm(
    objects: List,
    group_by_file: bool = True,
    max_sequence_length: int = 50,
) -> Dict[str, Any]:
    """
    Analyze sequences of MalwiObjects using LSTM.

    Args:
        objects: List of MalwiObjects with embeddings
        group_by_file: If True, group by file path; otherwise treat as one sequence
        max_sequence_length: Maximum number of objects in a sequence

    Returns:
        Dictionary with analysis results
    """
    if not _ensure_lstm_initialized():
        return {
            "status": "error",
            "message": "LSTM model not available",
        }

    if group_by_file:
        # Group objects by file
        objects_by_file = defaultdict(list)
        for obj in objects:
            if hasattr(obj, "file_path"):
                objects_by_file[obj.file_path].append(obj)
    else:
        # Treat all objects as one sequence
        objects_by_file = {"<package>": objects}

    results = {"sequences": {}, "overall": {}}
    total_malicious = 0
    max_confidence = 0.0

    for file_path, file_objects in objects_by_file.items():
        # Get embeddings from objects
        embeddings = []
        for obj in file_objects[:max_sequence_length]:
            if hasattr(obj, "embedding") and obj.embedding is not None:
                embeddings.append(obj.embedding)

        if embeddings:
            prediction = get_sequence_lstm_prediction(embeddings)
            if prediction["status"] == "success":
                is_malicious = prediction["prediction"] == "malicious"
                results["sequences"][file_path] = {
                    "prediction": prediction["prediction"],
                    "confidence": prediction["confidence"],
                    "num_objects": len(embeddings),
                }
                if is_malicious:
                    total_malicious += 1
                    max_confidence = max(max_confidence, prediction["confidence"])

    # Overall verdict
    results["overall"] = {
        "prediction": "malicious" if total_malicious > 0 else "benign",
        "confidence": max_confidence if total_malicious > 0 else 1.0,
        "malicious_sequences": total_malicious,
        "total_sequences": len(results["sequences"]),
    }

    return results


def compute_embedding_for_object(obj, model_path: str = None) -> Optional[np.ndarray]:
    """
    Compute DistilBERT embedding for a MalwiObject.

    Args:
        obj: MalwiObject instance
        model_path: Path to DistilBERT model (uses default if None)

    Returns:
        256-dimensional embedding array or None if computation fails
    """
    try:
        # Import here to avoid circular dependencies
        from transformers import AutoTokenizer, DistilBertModel
        import torch

        # Get token string from object
        token_string = obj.to_token_string(map_special_tokens=True)

        if not token_string or not token_string.strip():
            return None

        # Load model and tokenizer
        if model_path is None:
            model_path = "malwi_models"  # Default path

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = DistilBertModel.from_pretrained(model_path)
        model.to(device)
        model.eval()

        # Tokenize and get embedding
        encoded = tokenizer(
            token_string,
            return_tensors="pt",
            truncation=True,
            padding="max_length",
            max_length=512,
        )

        input_ids = encoded["input_ids"].to(device)
        attention_mask = encoded["attention_mask"].to(device)

        with torch.no_grad():
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            # Get CLS token embedding
            cls_embedding = outputs.last_hidden_state[:, 0, :].cpu().numpy()

        return cls_embedding[0]  # Return first (and only) embedding

    except Exception as e:
        print(
            f"Warning: Failed to compute embedding for {obj.name}: {e}", file=sys.stderr
        )
        return None


def run_lstm_sequence_analysis(
    objects: List,
) -> Dict[str, Any]:
    """
    Run LSTM analysis on a list of objects.

    Args:
        objects: List of MalwiObjects to analyze (must have embeddings pre-computed)

    Returns:
        Dictionary with analysis results
    """
    if not objects:
        return {"status": "error", "message": "No objects to analyze"}

    if not _ensure_lstm_initialized():
        return {"status": "error", "message": "LSTM model not available"}

    try:
        # Filter objects with embeddings (should already be computed during DistilBERT prediction)
        objects_with_embeddings = [
            obj
            for obj in objects
            if hasattr(obj, "embedding") and obj.embedding is not None
        ]

        if not objects_with_embeddings:
            return {
                "status": "error",
                "message": "No objects have embeddings for analysis",
            }

        # Analyze sequences
        results = analyze_object_sequences_with_lstm(
            objects_with_embeddings,
            group_by_file=True,
            max_sequence_length=50,
        )

        results["objects_analyzed"] = len(objects_with_embeddings)
        results["objects_skipped"] = len(objects) - len(objects_with_embeddings)

        return results

    except Exception as e:
        return {"status": "error", "message": str(e)}
