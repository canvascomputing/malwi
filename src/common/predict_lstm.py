"""
LSTM prediction module for malware detection.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional, Any
from collections import defaultdict
import sys

# Label constants - Binary classification
BENIGN_LABEL = 0
MALICIOUS_LABEL = 1
PREDICTION_THRESHOLD = 0.5

# Singleton pattern for LSTM model
_lstm_model = None
_lstm_model_path = None
_lstm_device = None


def initialize_lstm_model(model_path: Optional[str] = None) -> None:
    """Initialize the LSTM model."""
    global _lstm_model, _lstm_model_path, _lstm_device

    if model_path is None:
        model_path = "malwi_models/malware_lstm_model.pth"

    if not Path(model_path).exists():
        print(f"Warning: LSTM model not found at {model_path}", file=sys.stderr)
        return

    _lstm_model_path = model_path
    _lstm_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    try:
        state_dict = torch.load(_lstm_model_path, map_location=_lstm_device)

        from research.train_lstm import MalwareLSTM

        _lstm_model = MalwareLSTM()
        _lstm_model.load_state_dict(state_dict)
        _lstm_model.to(_lstm_device)
        _lstm_model.eval()
        print(f"Successfully loaded LSTM model from {model_path}", file=sys.stderr)

    except RuntimeError as e:
        print(
            f"Warning: LSTM model incompatible with current architecture",
            file=sys.stderr,
        )
        print(
            f"LSTM analysis will be disabled. To enable, retrain with: uv run python -m src.research.train_lstm training_rl_embeddings.csv",
            file=sys.stderr,
        )
        _lstm_model = None


def _ensure_lstm_initialized() -> bool:
    """Ensure LSTM model is initialized."""
    if _lstm_model is None:
        initialize_lstm_model()
    return _lstm_model is not None


def get_sequence_lstm_prediction(embeddings: List[np.ndarray]) -> Dict[str, Any]:
    """Get LSTM prediction for a sequence of embeddings."""
    prediction_result = {
        "status": "pending",
        "prediction": "unknown",
        "confidence": 0.0,
    }

    if not embeddings:
        prediction_result["status"] = "error"
        prediction_result["message"] = "No embeddings provided"
        return prediction_result

    if not _ensure_lstm_initialized():
        prediction_result["status"] = "disabled"
        prediction_result["message"] = "LSTM model not available - inference disabled"
        prediction_result["prediction"] = "unknown"
        prediction_result["confidence"] = 0.0
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

            # Binary prediction
            benign_prob = probs[0, BENIGN_LABEL].item()
            malicious_prob = probs[0, MALICIOUS_LABEL].item()

            prediction = (
                "malicious" if malicious_prob > PREDICTION_THRESHOLD else "benign"
            )
            confidence = max(benign_prob, malicious_prob)

            prediction_result["status"] = "success"
            prediction_result["prediction"] = prediction
            prediction_result["confidence"] = confidence
            prediction_result["probabilities"] = {
                "benign": benign_prob,
                "malicious": malicious_prob,
            }
            prediction_result["sequence_length"] = len(embeddings)

    except Exception as e:
        prediction_result["status"] = "error"
        prediction_result["message"] = str(e)

    return prediction_result


def analyze_object_sequences_with_lstm(
    objects: List,
    group_by_file: bool = True,
    max_sequence_length: int = 50,
) -> Dict[str, Any]:
    """Analyze sequences of MalwiObjects using LSTM."""
    if not _ensure_lstm_initialized():
        return {
            "status": "disabled",
            "message": "LSTM model not available - analysis disabled",
            "sequences": {},
            "overall": {
                "prediction": "unknown",
                "confidence": 0.0,
                "malicious_sequences": 0,
                "benign_sequences": 0,
                "total_sequences": 0,
            },
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
    total_benign = 0
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
                results["sequences"][file_path] = {
                    "prediction": prediction["prediction"],
                    "confidence": prediction["confidence"],
                    "probabilities": prediction["probabilities"],
                    "num_objects": len(embeddings),
                }

                if prediction["prediction"] == "malicious":
                    total_malicious += 1
                    max_confidence = max(max_confidence, prediction["confidence"])
                else:  # benign
                    total_benign += 1

    # Determine overall verdict
    if total_malicious > 0:
        overall_prediction = "malicious"
        overall_confidence = max_confidence
    else:
        overall_prediction = "benign"
        overall_confidence = 1.0 - (max_confidence if max_confidence > 0 else 0)

    results["overall"] = {
        "prediction": overall_prediction,
        "confidence": overall_confidence,
        "malicious_sequences": total_malicious,
        "benign_sequences": total_benign,
        "total_sequences": len(results["sequences"]),
    }

    return results


def run_lstm_sequence_analysis(objects: List) -> Dict[str, Any]:
    """Run LSTM analysis on a list of objects."""
    if not objects:
        return {"status": "error", "message": "No objects to analyze"}

    if not _ensure_lstm_initialized():
        return {
            "status": "disabled",
            "message": "LSTM model not available - analysis disabled",
            "objects_analyzed": 0,
            "objects_skipped": len(objects) if objects else 0,
        }

    try:
        # Filter objects with embeddings
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
