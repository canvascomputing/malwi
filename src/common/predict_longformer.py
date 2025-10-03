"""
Longformer prediction module for package-level malware detection.

This module provides deep analysis capabilities using a Longformer model
that processes entire packages with cross-file context understanding.
"""

import torch
import torch.nn.functional as F
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from collections import defaultdict
import sys
import json
from transformers import AutoTokenizer

# Import the Longformer model architecture
from transformers import LongformerForSequenceClassification, LongformerConfig
from research.longformer_constants import (
    ID_TO_LABEL,
    LABEL_TO_ID,
    NUM_LABELS,
)

# Singleton pattern for Longformer model
_longformer_model = None
_longformer_tokenizer = None
_longformer_model_path = None
_longformer_device = None
_longformer_config = None


def initialize_longformer_model(
    model_path: Optional[str] = None, tokenizer_path: Optional[str] = None
) -> None:
    """Initialize the Longformer model for deep analysis."""
    global _longformer_model, _longformer_tokenizer, _longformer_model_path
    global _longformer_device, _longformer_config

    if model_path is None:
        # Default to the provided sample model
        model_path = "/Users/mav/My Drive/malwi/v21/longformer"

    if tokenizer_path is None:
        # Default to malwi_models if available, else try default path
        tokenizer_path = "malwi_models"
        if not Path(tokenizer_path).exists():
            # Fall back to same directory as model
            tokenizer_path = (
                str(Path(model_path).parent) if model_path else "malwi_models"
            )

    model_dir = Path(model_path)
    if not model_dir.exists():
        print(f"Warning: Longformer model not found at {model_path}", file=sys.stderr)
        return

    _longformer_model_path = model_path

    # Use same device selection logic as DistilBERT
    if torch.cuda.is_available():
        _longformer_device = torch.device("cuda")
    elif torch.backends.mps.is_available():
        _longformer_device = torch.device("mps")
    else:
        _longformer_device = torch.device("cpu")

    try:
        # Load model configuration
        config_path = model_dir / "config.json"
        with open(config_path, "r") as f:
            _longformer_config = json.load(f)

        # Initialize custom trained tokenizer to match training
        try:
            _longformer_tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)
        except Exception as e:
            # Fallback to DistilBERT tokenizer if custom tokenizer not found
            _longformer_tokenizer = AutoTokenizer.from_pretrained(
                "distilbert-base-uncased"
            )

        # Initialize model with exact config from saved model
        saved_vocab_size = _longformer_config.get("vocab_size", 30523)
        max_pos = _longformer_config.get("max_position_embeddings", 4098)

        # Reconstruct the exact config used during training
        hidden_size = _longformer_config.get("hidden_size", 256)

        # Infer architecture params based on hidden size if not saved
        # hidden_size=768 → base model, hidden_size=256 → small model
        if hidden_size == 768:
            # Base Longformer configuration
            default_heads = 12
            default_layers = 12
            default_intermediate = 3072
        else:
            # Small model configuration
            default_heads = 4
            default_layers = 4
            default_intermediate = 1024

        num_layers = _longformer_config.get("num_hidden_layers", default_layers)

        config = LongformerConfig(
            vocab_size=saved_vocab_size,
            max_position_embeddings=max_pos,
            hidden_size=hidden_size,
            num_attention_heads=_longformer_config.get(
                "num_attention_heads", default_heads
            ),
            num_hidden_layers=num_layers,
            intermediate_size=_longformer_config.get(
                "intermediate_size", default_intermediate
            ),
            attention_window=_longformer_config.get(
                "attention_window", [512] * num_layers
            ),
            num_labels=_longformer_config.get("num_labels", NUM_LABELS),
            id2label=_longformer_config.get("id_to_label", ID_TO_LABEL),
            label2id=_longformer_config.get("label_to_id", LABEL_TO_ID),
            problem_type="multi_label_classification",
        )

        # Load model with exact matching config
        # Set seed BEFORE loading to ensure deterministic random initialization
        torch.manual_seed(42)
        if torch.backends.mps.is_available():
            torch.mps.manual_seed(42)
        torch.use_deterministic_algorithms(True, warn_only=True)

        _longformer_model = LongformerForSequenceClassification.from_pretrained(
            model_path,
            config=config,
            local_files_only=True,
            ignore_mismatched_sizes=True,  # This causes random init of token_type_embeddings
        )
        _longformer_model.to(_longformer_device)
        _longformer_model.eval()

    except Exception as e:
        print(f"Error loading Longformer model: {e}", file=sys.stderr)
        _longformer_model = None


def create_package_windows(
    code_objects: List[Dict[str, Any]], max_length: int = 4096
) -> List[Tuple[torch.Tensor, torch.Tensor, torch.Tensor]]:
    """
    Create windowed sequences from multiple code objects (matching training format).

    Args:
        code_objects: List of code objects with 'tokens' field
        max_length: Maximum sequence length

    Returns:
        List of tuples (input_ids, attention_mask, global_attention_mask) for each window
    """
    if _longformer_tokenizer is None:
        raise ValueError("Longformer tokenizer not initialized")

    # Extract valid CodeObjects and prepare for windowing
    valid_objects = []
    for obj in code_objects:
        tokens = obj.get("tokens", "")
        if isinstance(tokens, list):
            tokens = " ".join(tokens)

        token_list = tokens.split() if tokens else []
        if token_list:
            valid_objects.append(
                {"tokens": token_list, "name": obj.get("name", "unknown")}
            )

    if not valid_objects:
        return []

    # Window parameters (matching training)
    window_size = max_length // 2  # Half max length to leave room for special tokens
    window_stride = max(
        1, len(valid_objects) // 4
    )  # Ensure we advance at least 1 object

    windows = []

    # Create overlapping windows
    start_idx = 0
    while start_idx < len(valid_objects):
        window_tokens = []

        # Add CodeObjects to current window
        obj_idx = start_idx
        while obj_idx < len(valid_objects) and len(window_tokens) < window_size:
            obj = valid_objects[obj_idx]

            # Check if we can fit this object
            if len(window_tokens) + len(obj["tokens"]) <= window_size:
                window_tokens.extend(obj["tokens"])
                # Add period as separator between objects
                window_tokens.append(".")
                obj_idx += 1
            else:
                break

        # Remove trailing separator
        if window_tokens and window_tokens[-1] == ".":
            window_tokens.pop()

        if window_tokens:
            # Join tokens and tokenize
            sequence_text = " ".join(window_tokens)

            # Tokenize with proper max length
            effective_max_length = min(
                max_length - 2, 4096
            )  # Reserve space for [CLS] and [SEP]
            encoded = _longformer_tokenizer(
                sequence_text,
                truncation=True,
                padding="max_length",
                max_length=effective_max_length,
                return_tensors="pt",
            )

            input_ids = encoded["input_ids"]
            attention_mask = encoded["attention_mask"]

            # Create global attention mask
            global_attention_mask = torch.zeros_like(input_ids)

            # Global attention on [CLS] token
            global_attention_mask[0, 0] = 1

            # Global attention on [SEP] tokens
            if _longformer_tokenizer.sep_token_id:
                global_attention_mask[
                    input_ids == _longformer_tokenizer.sep_token_id
                ] = 1

            windows.append((input_ids, attention_mask, global_attention_mask))

        # Move to next window
        start_idx += window_stride

        # Stop if we've reached the end
        if obj_idx >= len(valid_objects):
            break

    return windows


def predict_package_malware(
    code_objects: List[Dict[str, Any]],
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """
    Predict malware in a package using Longformer deep analysis.

    Args:
        code_objects: List of code objects to analyze
        window_size: Number of objects per window
        threshold: Prediction threshold

    Returns:
        Dictionary with predictions and analysis results
    """
    if _longformer_model is None:
        print("Longformer model not initialized", file=sys.stderr)
        return {
            "error": "Model not initialized",
            "overall": {"prediction": "unknown", "confidence": 0.0},
        }

    try:
        # Create windows from code objects
        windows = create_package_windows(
            code_objects,
            max_length=_longformer_config.get("max_position_embeddings", 4096),
        )

        if not windows:
            return {
                "error": "No valid windows created from code objects",
                "overall": {"prediction": "unknown", "confidence": 0.0},
            }

        all_predictions = []
        all_probabilities = []

        # Process each window
        with torch.no_grad():
            for window_idx, (
                input_ids,
                attention_mask,
                global_attention_mask,
            ) in enumerate(windows):
                # Move to device
                input_ids = input_ids.to(_longformer_device)
                attention_mask = attention_mask.to(_longformer_device)
                global_attention_mask = global_attention_mask.to(_longformer_device)

                # Get predictions using standard model
                outputs = _longformer_model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    global_attention_mask=global_attention_mask,
                )

                # Convert to probabilities and predictions
                probabilities = torch.sigmoid(outputs.logits)
                predictions = (probabilities > threshold).float()

                all_predictions.append(predictions.cpu())
                all_probabilities.append(probabilities.cpu())

        # Aggregate predictions across windows
        if len(all_predictions) > 1:
            # Use max confidence aggregation
            all_probs_tensor = torch.stack(all_probabilities)
            max_probs, _ = torch.max(all_probs_tensor, dim=0)
            final_predictions = (max_probs > threshold).float()
            final_probabilities = max_probs
        else:
            final_predictions = all_predictions[0]
            final_probabilities = all_probabilities[0]

        # Extract results
        results = {
            "overall": {
                "prediction": "benign",
                "confidence": 0.0,
                "files_analyzed": len(code_objects),
                "windows_processed": len(windows),
            },
            "per_label": {},
            "detailed_analysis": {},
        }

        # Process each label (sorted for determinism)
        for label_idx in sorted(ID_TO_LABEL.keys()):
            label_name = ID_TO_LABEL[label_idx]
            prob = float(final_probabilities[0, label_idx])
            pred = bool(final_predictions[0, label_idx])

            results["per_label"][label_name] = {
                "detected": pred,
                "confidence": prob,
            }

            # Update overall prediction
            if label_name != "benign" and pred:
                if label_name == "malicious" or (
                    results["overall"]["prediction"] == "benign"
                ):
                    results["overall"]["prediction"] = label_name
                    results["overall"]["confidence"] = max(
                        results["overall"]["confidence"], prob
                    )

        # If no threats detected, set to benign
        if results["overall"]["prediction"] == "benign":
            results["overall"]["confidence"] = float(
                final_probabilities[0, LABEL_TO_ID["benign"]]
            )

        # Add detailed analysis
        results["detailed_analysis"] = {
            "model_type": "Longformer",
            "context_window": _longformer_config.get("max_position_embeddings", 4096),
            "cross_file_analysis": True,
            "package_level_detection": True,
        }

        return results

    except Exception as e:
        print(f"Error during Longformer prediction: {e}", file=sys.stderr)
        return {
            "error": str(e),
            "overall": {"prediction": "error", "confidence": 0.0},
        }


def run_deep_analysis(
    malwi_objects: List[Any],
    package_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run deep analysis on a collection of MalWi objects.

    This is the main entry point for deep analysis using Longformer.

    Args:
        malwi_objects: List of MalwiObject instances
        package_name: Optional package name for grouping

    Returns:
        Dictionary with deep analysis results
    """
    # Initialize model if needed
    if _longformer_model is None:
        initialize_longformer_model()

    if _longformer_model is None:
        return {
            "error": "Longformer model could not be loaded",
            "overall": {"prediction": "unknown", "confidence": 0.0},
        }

    # Convert MalwiObjects to format expected by predict function
    # Use the same method as DistilBERT: obj.to_token_string(map_special_tokens=True)
    # IMPORTANT: Sort objects by (filepath, name) for deterministic ordering
    sorted_objects = sorted(
        malwi_objects,
        key=lambda obj: (
            obj.file_path if hasattr(obj, "file_path") else "",
            obj.name if hasattr(obj, "name") else "",
        ),
    )

    code_objects = []
    for obj in sorted_objects:
        # Get tokens using the exact same method as DistilBERT
        tokens = (
            obj.to_token_string(map_special_tokens=True)
            if hasattr(obj, "to_token_string")
            else ""
        )

        code_obj = {
            "tokens": tokens,
            "filepath": obj.file_path if hasattr(obj, "file_path") else "unknown",
            "name": obj.name if hasattr(obj, "name") else "unknown",
        }
        code_objects.append(code_obj)

    # Run prediction
    results = predict_package_malware(code_objects)

    # Add package information
    if package_name:
        results["package"] = package_name

    # Add summary statistics
    malicious_count = sum(
        1
        for label, info in results.get("per_label", {}).items()
        if label != "benign" and info.get("detected", False)
    )

    results["overall"]["malicious_sequences"] = malicious_count
    results["overall"]["analysis_type"] = "deep_longformer"

    return results
