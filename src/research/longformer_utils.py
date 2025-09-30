"""
Utility functions for Longformer-based malware detection.

This module contains helper functions for creating attention masks
and aggregating labels that are shared across training and prediction.
"""

import torch
from typing import Dict, Optional
from research.longformer_constants import LABEL_TO_ID


def create_global_attention_mask(
    input_ids: torch.Tensor,
    tokenizer,
) -> torch.Tensor:
    """
    Create global attention mask for Longformer.

    Sets global attention on:
    - [CLS] token (position 0)
    - [SEP] token (end of sequence)

    Args:
        input_ids: Token IDs [batch_size, seq_length]
        tokenizer: Tokenizer instance

    Returns:
        Global attention mask [batch_size, seq_length]
    """
    batch_size, seq_length = input_ids.shape
    global_attention_mask = torch.zeros_like(input_ids, dtype=torch.long)

    # Global attention on [CLS] token (position 0)
    global_attention_mask[:, 0] = 1

    # Global attention on [SEP] tokens
    sep_token_id = tokenizer.sep_token_id
    if sep_token_id is not None:
        global_attention_mask[input_ids == sep_token_id] = 1

    return global_attention_mask


def aggregate_package_labels(
    file_labels: list, strategy: str = "majority"
) -> Dict[str, float]:
    """
    Aggregate file-level labels into package-level labels.

    Args:
        file_labels: List of file-level label strings
        strategy: Aggregation strategy ("majority", "any_positive", "weighted")

    Returns:
        Package-level label probabilities
    """
    if not file_labels:
        return {label: 0.0 for label in LABEL_TO_ID.keys()}

    # Count label occurrences
    label_counts = {label: 0 for label in LABEL_TO_ID.keys()}
    for file_label in file_labels:
        if file_label in label_counts:
            label_counts[file_label] += 1

    total_files = len(file_labels)

    if strategy == "majority":
        # Majority vote with minimum threshold
        return {
            label: 1.0 if count > total_files * 0.5 else 0.0
            for label, count in label_counts.items()
        }
    elif strategy == "any_positive":
        # Any positive detection triggers package-level detection
        result = {label: 0.0 for label in LABEL_TO_ID.keys()}

        # Check if any non-benign labels exist
        has_malicious = any(
            count > 0 for label, count in label_counts.items() if label != "benign"
        )

        if has_malicious:
            # Set non-benign labels that exist
            for label, count in label_counts.items():
                if label != "benign" and count > 0:
                    result[label] = 1.0
        else:
            # All files are benign
            result["benign"] = 1.0

        return result
    elif strategy == "weighted":
        # Weighted by proportion of files
        return {label: count / total_files for label, count in label_counts.items()}
    else:
        raise ValueError(f"Unknown aggregation strategy: {strategy}")
