"""
Constants for Longformer-based malware detection.

This module contains shared constants used across Longformer training,
dataset creation, and prediction modules.
"""

# Label constants - Multi-label classification
LABEL_TO_ID = {
    "benign": 0,
    "malicious": 1,
    "suspicious": 2,
    "telemetry": 3,
}
ID_TO_LABEL = {v: k for k, v in LABEL_TO_ID.items()}
NUM_LABELS = len(LABEL_TO_ID)
