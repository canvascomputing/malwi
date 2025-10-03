"""
Concrete predictor implementations for DistilBERT and Longformer.

This module provides ready-to-use predictor classes that implement the
unified prediction API.
"""

from typing import Any, Optional
import torch
import torch.nn.functional as F

from common.prediction import (
    Predictor,
    ModelType,
    PredictionWindow,
    WindowPredictionResult,
)
from common.windowing import (
    TokenSlidingWindowStrategy,
    ObjectGroupingWindowStrategy,
    MaxConfidenceAggregation,
)


class DistilBERTPredictor(Predictor):
    """DistilBERT predictor for single code objects."""

    def __init__(self, model: Any, tokenizer: Any, stride: int = 256):
        """
        Initialize DistilBERT predictor.

        Args:
            model: DistilBERT model instance
            tokenizer: Tokenizer instance
            stride: Window stride in tokens (default: 256)
        """
        super().__init__(
            window_strategy=TokenSlidingWindowStrategy(stride=stride),
            aggregation_strategy=MaxConfidenceAggregation(ModelType.DISTILBERT),
            model_type=ModelType.DISTILBERT,
        )
        self.model = model
        self.tokenizer = tokenizer
        self.device = next(model.parameters()).device

    def predict_window(self, window: PredictionWindow) -> WindowPredictionResult:
        """
        Predict a single window with DistilBERT.

        Args:
            window: PredictionWindow to process

        Returns:
            WindowPredictionResult with label confidences
        """
        with torch.no_grad():
            outputs = self.model(
                input_ids=window.input_ids.to(self.device),
                attention_mask=window.attention_mask.to(self.device),
            )

        logits = outputs.logits
        probabilities = F.softmax(logits, dim=-1).cpu()[0]

        # Get label mapping from model config
        if (
            hasattr(self.model.config, "id2label")
            and self.model.config.id2label
            and not any(
                k.startswith("LABEL_") for k in self.model.config.id2label.values()
            )
        ):
            label_map = self.model.config.id2label
        else:
            # Fallback for backward compatibility with binary models
            label_map = {0: "benign", 1: "malicious"}

        # Create labels dictionary
        labels_dict = {
            label_map[idx]: prob.item()
            for idx, prob in enumerate(probabilities)
            if idx in label_map
        }

        # Predicted label (highest confidence)
        prediction_idx = torch.argmax(probabilities).item()
        predicted_label = label_map.get(prediction_idx, f"unknown_{prediction_idx}")

        return WindowPredictionResult(
            window_index=window.window_index,
            labels=labels_dict,
            predicted_label=predicted_label,
            confidence=probabilities[prediction_idx].item(),
            metadata=window.metadata,
        )

    def prepare_object_input(self, obj: Any) -> str:
        """
        Convert MalwiObject to token string input.

        Args:
            obj: MalwiObject instance

        Returns:
            Space-separated token string
        """
        return obj.to_token_string(map_special_tokens=True)

    def get_max_length(self) -> int:
        """Get maximum sequence length for DistilBERT."""
        return self.tokenizer.model_max_length

    def get_tokenizer(self) -> Any:
        """Get tokenizer instance."""
        return self.tokenizer


class LongformerPredictor(Predictor):
    """Longformer predictor for package-level analysis."""

    def __init__(
        self,
        model: Any,
        tokenizer: Any,
        max_length: int = 4096,
        label_map: Optional[dict] = None,
    ):
        """
        Initialize Longformer predictor.

        Args:
            model: Longformer model instance
            tokenizer: Tokenizer instance
            max_length: Maximum sequence length (default: 4096)
            label_map: Optional label mapping (default: use longformer_constants)
        """
        super().__init__(
            window_strategy=ObjectGroupingWindowStrategy(),
            aggregation_strategy=MaxConfidenceAggregation(ModelType.LONGFORMER),
            model_type=ModelType.LONGFORMER,
        )
        self.model = model
        self.tokenizer = tokenizer
        self.max_length_override = max_length
        self.device = next(model.parameters()).device
        self._label_map = label_map

    def predict_window(self, window: PredictionWindow) -> WindowPredictionResult:
        """
        Predict a single window with Longformer.

        Args:
            window: PredictionWindow to process

        Returns:
            WindowPredictionResult with label confidences
        """
        with torch.no_grad():
            outputs = self.model(
                input_ids=window.input_ids.to(self.device),
                attention_mask=window.attention_mask.to(self.device),
                global_attention_mask=window.global_attention_mask.to(self.device),
            )

        # Multi-label classification with sigmoid
        probabilities = torch.sigmoid(outputs.logits).cpu()[0]

        # Get label mapping
        if self._label_map is not None:
            label_map = self._label_map
        else:
            # Import here to avoid circular dependency
            from research.longformer_constants import ID_TO_LABEL

            label_map = ID_TO_LABEL

        # Create labels dictionary
        labels_dict = {
            label_map[idx]: prob.item()
            for idx, prob in enumerate(probabilities)
            if idx in label_map
        }

        # Predicted label (highest confidence)
        prediction_idx = torch.argmax(probabilities).item()
        predicted_label = label_map.get(prediction_idx, f"unknown_{prediction_idx}")

        return WindowPredictionResult(
            window_index=window.window_index,
            labels=labels_dict,
            predicted_label=predicted_label,
            confidence=probabilities[prediction_idx].item(),
            metadata=window.metadata,
        )

    def prepare_object_input(self, obj: Any) -> List[Dict[str, Any]]:
        """
        Convert MalwiObject to list of code objects.

        Args:
            obj: MalwiObject instance

        Returns:
            List with single code object dict
        """
        return [
            {
                "tokens": obj.to_token_string(map_special_tokens=True),
                "name": obj.name if hasattr(obj, "name") else "unknown",
            }
        ]

    def get_max_length(self) -> int:
        """Get maximum sequence length for Longformer."""
        return self.max_length_override

    def get_tokenizer(self) -> Any:
        """Get tokenizer instance."""
        return self.tokenizer


# Singleton predictor instances (initialized lazily)
_distilbert_predictor: Optional[DistilBERTPredictor] = None
_longformer_predictor: Optional[LongformerPredictor] = None


def get_distilbert_predictor() -> DistilBERTPredictor:
    """
    Get or create the singleton DistilBERT predictor.

    Returns:
        DistilBERTPredictor instance
    """
    global _distilbert_predictor

    if _distilbert_predictor is None:
        # Import here to avoid circular dependency
        from common.predict_distilbert import HF_MODEL_INSTANCE, get_thread_tokenizer

        _distilbert_predictor = DistilBERTPredictor(
            model=HF_MODEL_INSTANCE, tokenizer=get_thread_tokenizer()
        )

    return _distilbert_predictor


def get_longformer_predictor() -> Optional[LongformerPredictor]:
    """
    Get or create the singleton Longformer predictor.

    Returns:
        LongformerPredictor instance, or None if Longformer not initialized
    """
    global _longformer_predictor

    if _longformer_predictor is None:
        # Import here to avoid circular dependency
        from common.predict_longformer import (
            _longformer_model,
            _longformer_tokenizer,
            _longformer_config,
        )

        if _longformer_model is None or _longformer_tokenizer is None:
            return None

        max_length = _longformer_config.get("max_position_embeddings", 4096)

        _longformer_predictor = LongformerPredictor(
            model=_longformer_model,
            tokenizer=_longformer_tokenizer,
            max_length=max_length,
        )

    return _longformer_predictor
