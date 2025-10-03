"""
Windowing and aggregation strategies for prediction pipelines.

This module implements different strategies for creating prediction windows
and aggregating results from multiple windows.
"""

from typing import List, Dict, Any
import torch

from common.prediction import (
    WindowStrategy,
    AggregationStrategy,
    PredictionWindow,
    WindowPredictionResult,
    AggregatedPredictionResult,
    ModelType,
)


class TokenSlidingWindowStrategy(WindowStrategy):
    """Sliding window strategy for token-level sequences (DistilBERT)."""

    def __init__(self, stride: int = 256):
        """
        Initialize with stride.

        Args:
            stride: Number of tokens to advance per window (default: 256)
        """
        self.stride = stride

    def create_windows(
        self, input_data: str, max_length: int, tokenizer: Any
    ) -> List[PredictionWindow]:
        """
        Create overlapping token windows from a token string.

        Args:
            input_data: Token string (space-separated tokens)
            max_length: Maximum sequence length
            tokenizer: Tokenizer instance

        Returns:
            List of PredictionWindow objects
        """
        # Tokenize full sequence
        encoded = tokenizer(
            input_data, truncation=False, padding=False, return_tensors="pt"
        )

        input_ids = encoded["input_ids"][0]
        attention_mask = encoded["attention_mask"][0]
        num_tokens = attention_mask.sum().item()

        windows = []
        for i in range(0, num_tokens, self.stride):
            start_idx = i
            end_idx = min(i + max_length, num_tokens)

            window_input_ids = input_ids[start_idx:end_idx]
            window_attention_mask = attention_mask[start_idx:end_idx]

            # Pad if needed
            padding_needed = max_length - len(window_input_ids)
            if padding_needed > 0:
                pad_tensor = torch.full(
                    (padding_needed,),
                    tokenizer.pad_token_id,
                    dtype=window_input_ids.dtype,
                )
                window_input_ids = torch.cat([window_input_ids, pad_tensor])

                mask_pad = torch.zeros(
                    padding_needed, dtype=window_attention_mask.dtype
                )
                window_attention_mask = torch.cat([window_attention_mask, mask_pad])

            windows.append(
                PredictionWindow(
                    input_ids=window_input_ids.unsqueeze(0),
                    attention_mask=window_attention_mask.unsqueeze(0),
                    window_index=len(windows),
                    metadata={"start_token": start_idx, "end_token": end_idx},
                )
            )

            # Stop if we've covered all tokens
            if end_idx >= num_tokens:
                break

        return windows


class ObjectGroupingWindowStrategy(WindowStrategy):
    """Windowing strategy for grouping multiple code objects (Longformer)."""

    def __init__(self, window_stride_ratio: float = 0.25):
        """
        Initialize with window stride ratio.

        Args:
            window_stride_ratio: Fraction of objects to advance per window (default: 1/4)
        """
        self.window_stride_ratio = window_stride_ratio

    def create_windows(
        self, input_data: List[Dict[str, Any]], max_length: int, tokenizer: Any
    ) -> List[PredictionWindow]:
        """
        Create windows from multiple code objects.

        Args:
            input_data: List of code objects with 'tokens' field
            max_length: Maximum sequence length
            tokenizer: Tokenizer instance

        Returns:
            List of PredictionWindow objects
        """
        # Extract valid objects
        valid_objects = []
        for obj in input_data:
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

        # Window parameters
        window_size = max_length // 2  # Reserve space for special tokens
        window_stride = max(1, int(len(valid_objects) * self.window_stride_ratio))

        windows = []
        start_idx = 0

        while start_idx < len(valid_objects):
            window_tokens = []
            obj_idx = start_idx

            # Add objects to window
            while obj_idx < len(valid_objects) and len(window_tokens) < window_size:
                obj = valid_objects[obj_idx]
                if len(window_tokens) + len(obj["tokens"]) <= window_size:
                    window_tokens.extend(obj["tokens"])
                    window_tokens.append(".")  # Separator
                    obj_idx += 1
                else:
                    break

            # Remove trailing separator
            if window_tokens and window_tokens[-1] == ".":
                window_tokens.pop()

            if window_tokens:
                # Tokenize window
                sequence_text = " ".join(window_tokens)
                effective_max_length = min(max_length - 2, 4096)

                encoded = tokenizer(
                    sequence_text,
                    truncation=True,
                    padding="max_length",
                    max_length=effective_max_length,
                    return_tensors="pt",
                )

                # Create global attention mask for Longformer
                global_attention_mask = torch.zeros_like(encoded["input_ids"])
                global_attention_mask[0, 0] = 1  # CLS token
                if tokenizer.sep_token_id:
                    global_attention_mask[
                        encoded["input_ids"] == tokenizer.sep_token_id
                    ] = 1

                windows.append(
                    PredictionWindow(
                        input_ids=encoded["input_ids"],
                        attention_mask=encoded["attention_mask"],
                        global_attention_mask=global_attention_mask,
                        window_index=len(windows),
                        metadata={
                            "start_object": start_idx,
                            "end_object": obj_idx,
                            "num_objects": obj_idx - start_idx,
                        },
                    )
                )

            start_idx += window_stride
            if obj_idx >= len(valid_objects):
                break

        return windows


class MaxConfidenceAggregation(AggregationStrategy):
    """Aggregate by taking maximum confidence per label across windows."""

    def __init__(self, model_type: ModelType):
        """
        Initialize with model type.

        Args:
            model_type: Type of model for metadata
        """
        self.model_type = model_type

    def aggregate(
        self, window_results: List[WindowPredictionResult], threshold: float
    ) -> AggregatedPredictionResult:
        """
        Take max confidence for each label across windows.

        Args:
            window_results: List of predictions from individual windows
            threshold: Classification threshold

        Returns:
            AggregatedPredictionResult
        """
        if not window_results:
            return AggregatedPredictionResult(
                labels={},
                predicted_label="unknown",
                confidence=0.0,
                windows_processed=0,
                model_type=self.model_type,
                threshold=threshold,
                detected_labels={},
            )

        # Collect all labels
        all_labels = set()
        for wr in window_results:
            all_labels.update(wr.labels.keys())

        # Max confidence per label
        aggregated_labels = {}
        for label in all_labels:
            max_conf = max(wr.labels.get(label, 0.0) for wr in window_results)
            aggregated_labels[label] = max_conf

        # Determine predicted label (highest confidence)
        if aggregated_labels:
            predicted_label = max(aggregated_labels.items(), key=lambda x: x[1])[0]
            confidence = aggregated_labels[predicted_label]
        else:
            predicted_label = "unknown"
            confidence = 0.0

        # Detect labels above threshold
        detected_labels = {
            label: conf >= threshold for label, conf in aggregated_labels.items()
        }

        return AggregatedPredictionResult(
            labels=aggregated_labels,
            predicted_label=predicted_label,
            confidence=confidence,
            windows_processed=len(window_results),
            model_type=self.model_type,
            threshold=threshold,
            detected_labels=detected_labels,
        )


class VotingAggregation(AggregationStrategy):
    """Aggregate by voting on predicted labels across windows."""

    def __init__(self, model_type: ModelType):
        """
        Initialize with model type.

        Args:
            model_type: Type of model for metadata
        """
        self.model_type = model_type

    def aggregate(
        self, window_results: List[WindowPredictionResult], threshold: float
    ) -> AggregatedPredictionResult:
        """
        Vote on most common predicted label across windows.

        Args:
            window_results: List of predictions from individual windows
            threshold: Classification threshold

        Returns:
            AggregatedPredictionResult
        """
        if not window_results:
            return AggregatedPredictionResult(
                labels={},
                predicted_label="unknown",
                confidence=0.0,
                windows_processed=0,
                model_type=self.model_type,
                threshold=threshold,
                detected_labels={},
            )

        # Count votes for each label
        from collections import Counter

        label_votes = Counter(wr.predicted_label for wr in window_results)

        # Most common label
        predicted_label = label_votes.most_common(1)[0][0]

        # Average confidence for predicted label
        confidences = [
            wr.confidence
            for wr in window_results
            if wr.predicted_label == predicted_label
        ]
        confidence = sum(confidences) / len(confidences)

        # Aggregate all labels (average confidence)
        all_labels = set()
        for wr in window_results:
            all_labels.update(wr.labels.keys())

        aggregated_labels = {}
        for label in all_labels:
            label_confidences = [wr.labels.get(label, 0.0) for wr in window_results]
            aggregated_labels[label] = sum(label_confidences) / len(label_confidences)

        # Detect labels above threshold
        detected_labels = {
            label: conf >= threshold for label, conf in aggregated_labels.items()
        }

        return AggregatedPredictionResult(
            labels=aggregated_labels,
            predicted_label=predicted_label,
            confidence=confidence,
            windows_processed=len(window_results),
            model_type=self.model_type,
            threshold=threshold,
            detected_labels=detected_labels,
        )
