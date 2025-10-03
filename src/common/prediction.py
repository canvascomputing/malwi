"""
Unified prediction API for malware detection models.

This module provides abstract base classes and data structures for a consistent
prediction interface across different models (DistilBERT, Longformer, etc.).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import torch


class ModelType(Enum):
    """Supported model types."""

    DISTILBERT = "distilbert"
    LONGFORMER = "longformer"


@dataclass
class PredictionWindow:
    """A window of tokens/objects for prediction."""

    input_ids: torch.Tensor
    attention_mask: torch.Tensor
    global_attention_mask: Optional[torch.Tensor] = None  # For Longformer
    window_index: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WindowPredictionResult:
    """Result from predicting a single window."""

    window_index: int
    labels: Dict[str, float]  # label_name -> confidence score
    predicted_label: str  # Highest confidence label
    confidence: float  # Confidence of predicted label
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AggregatedPredictionResult:
    """Final aggregated prediction result."""

    labels: Dict[str, float]  # label_name -> aggregated confidence
    predicted_label: str  # Overall predicted label
    confidence: float  # Overall confidence
    windows_processed: int
    model_type: ModelType
    threshold: float
    detected_labels: Dict[str, bool]  # label_name -> is_above_threshold
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_harmful(self, exclude_labels: Optional[List[str]] = None) -> bool:
        """
        Check if any harmful labels are detected above threshold.

        Args:
            exclude_labels: Labels to exclude from harmful check (default: ["benign"])

        Returns:
            True if any non-excluded label is detected above threshold
        """
        exclude = exclude_labels or ["benign"]
        return any(
            detected and label not in exclude
            for label, detected in self.detected_labels.items()
        )

    def get_detected_harmful_labels(
        self, exclude_labels: Optional[List[str]] = None
    ) -> Dict[str, float]:
        """
        Get harmful labels that are above threshold.

        Args:
            exclude_labels: Labels to exclude (default: ["benign"])

        Returns:
            Dictionary of label -> confidence for detected harmful labels
        """
        exclude = exclude_labels or ["benign"]
        return {
            label: self.labels[label]
            for label, detected in self.detected_labels.items()
            if detected and label not in exclude
        }


class WindowStrategy(ABC):
    """Abstract base class for windowing strategies."""

    @abstractmethod
    def create_windows(
        self, input_data: Any, max_length: int, tokenizer: Any
    ) -> List[PredictionWindow]:
        """
        Create prediction windows from input data.

        Args:
            input_data: Input data (format depends on strategy)
            max_length: Maximum sequence length
            tokenizer: Tokenizer instance

        Returns:
            List of PredictionWindow objects
        """
        pass


class AggregationStrategy(ABC):
    """Abstract base class for aggregation strategies."""

    @abstractmethod
    def aggregate(
        self, window_results: List[WindowPredictionResult], threshold: float
    ) -> AggregatedPredictionResult:
        """
        Aggregate window predictions into final result.

        Args:
            window_results: List of predictions from individual windows
            threshold: Classification threshold

        Returns:
            AggregatedPredictionResult
        """
        pass


class Predictor(ABC):
    """Abstract base class for all predictors."""

    def __init__(
        self,
        window_strategy: WindowStrategy,
        aggregation_strategy: AggregationStrategy,
        model_type: ModelType,
    ):
        """
        Initialize predictor with strategies.

        Args:
            window_strategy: Strategy for creating windows
            aggregation_strategy: Strategy for aggregating window results
            model_type: Type of model (DistilBERT, Longformer, etc.)
        """
        self.window_strategy = window_strategy
        self.aggregation_strategy = aggregation_strategy
        self.model_type = model_type

    @abstractmethod
    def predict_window(self, window: PredictionWindow) -> WindowPredictionResult:
        """
        Predict a single window.

        Args:
            window: PredictionWindow to process

        Returns:
            WindowPredictionResult
        """
        pass

    def predict(
        self,
        input_data: Any,
        threshold: float = 0.7,
        max_length: Optional[int] = None,
    ) -> AggregatedPredictionResult:
        """
        Full prediction pipeline: window -> predict -> aggregate.

        Args:
            input_data: Input data (format depends on window strategy)
            threshold: Classification threshold (default: 0.7)
            max_length: Maximum sequence length (default: model's max length)

        Returns:
            AggregatedPredictionResult with final predictions
        """
        # Create windows
        windows = self.window_strategy.create_windows(
            input_data, max_length or self.get_max_length(), self.get_tokenizer()
        )

        if not windows:
            # No windows created - return empty result
            return AggregatedPredictionResult(
                labels={},
                predicted_label="unknown",
                confidence=0.0,
                windows_processed=0,
                model_type=self.model_type,
                threshold=threshold,
                detected_labels={},
            )

        # Predict each window
        window_results = [self.predict_window(w) for w in windows]

        # Aggregate results
        return self.aggregation_strategy.aggregate(window_results, threshold)

    @abstractmethod
    def prepare_object_input(self, obj: Any) -> Any:
        """
        Convert a MalwiObject to the appropriate input format for this predictor.

        Args:
            obj: MalwiObject instance

        Returns:
            Input data in the format expected by this predictor's window strategy
        """
        pass

    def predict_object(
        self, obj: Any, threshold: float = 0.7
    ) -> AggregatedPredictionResult:
        """
        Predict labels for a MalwiObject.

        Args:
            obj: MalwiObject instance
            threshold: Classification threshold (default: 0.7)

        Returns:
            AggregatedPredictionResult with predictions
        """
        input_data = self.prepare_object_input(obj)
        return self.predict(input_data, threshold=threshold)

    @abstractmethod
    def get_max_length(self) -> int:
        """
        Get maximum sequence length for this model.

        Returns:
            Maximum token length
        """
        pass

    @abstractmethod
    def get_tokenizer(self) -> Any:
        """
        Get tokenizer for this model.

        Returns:
            Tokenizer instance
        """
        pass
