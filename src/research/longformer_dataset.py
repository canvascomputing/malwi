"""
Package-aware dataset for Longformer training.

This module implements a PyTorch dataset that groups files by package,
concatenates their token sequences, and creates appropriate attention masks
for Longformer's efficient processing.
"""

import pandas as pd
import torch
from torch.utils.data import Dataset
from transformers import AutoTokenizer
from typing import Dict, List, Tuple, Optional
import random
from collections import defaultdict

from common.messaging import info, warning, error, progress
from research.longformer_constants import (
    LABEL_TO_ID,
    ID_TO_LABEL,
)
from research.longformer_utils import (
    aggregate_package_labels,
    create_global_attention_mask,
)


class LongformerPackageDataset(Dataset):
    """
    Dataset for package-level malware detection with Longformer.

    Groups CodeObjects by package, creates windowed sequences from multiple
    CodeObjects within each package, and generates appropriate labels and attention masks.
    """

    def __init__(
        self,
        csv_path: str,
        tokenizer_path: str = "malwi_models",
        max_length: int = 4096,
        label_aggregation_strategy: str = "any_positive",
        min_objects_per_package: int = 1,
        max_benign_samples_per_package: int = 10,
        benign_ratio: int = 4,
    ):
        """
        Initialize the dataset.

        Args:
            csv_path: Path to CSV with tokens, label, package columns
            tokenizer_path: Path to DistilBERT tokenizer
            max_length: Maximum sequence length for Longformer
            label_aggregation_strategy: How to aggregate CodeObject labels to package labels
            min_objects_per_package: Minimum CodeObjects required per package
            max_benign_samples_per_package: Maximum number of random samples to use from benign packages
            benign_ratio: Number of random benign collections to create per benign package
        """
        self.csv_path = csv_path
        self.max_length = max_length
        self.label_aggregation_strategy = label_aggregation_strategy
        self.min_objects_per_package = min_objects_per_package
        self.max_benign_samples_per_package = max_benign_samples_per_package
        self.benign_ratio = benign_ratio

        # Load custom trained tokenizer
        progress("Loading tokenizer...")

        # Use the custom trained tokenizer from malwi_models by default
        if tokenizer_path == "allenai/longformer-base-4096":
            # Override default to use custom tokenizer
            tokenizer_path = "malwi_models"
            info("Using custom trained tokenizer from malwi_models")

        progress(f"Loading tokenizer from {tokenizer_path}...")
        self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)

        info(f"Loaded tokenizer with vocab_size={len(self.tokenizer)}")

        # Load and process data
        self.package_data = self._load_and_group_data()

        # Pre-compute all training samples (windows) for efficiency
        self.training_samples = []
        for package_name, code_objects in self.package_data.items():
            package_samples = self._create_training_samples(package_name, code_objects)
            self.training_samples.extend(package_samples)

        info(f"Loaded {len(self.package_data)} packages for training")
        info(f"Generated {len(self.training_samples)} training windows")
        info(
            f"Average CodeObjects per package: {sum(len(objs) for objs in self.package_data.values()) / len(self.package_data):.1f}"
        )
        info(
            f"Average windows per package: {len(self.training_samples) / len(self.package_data):.1f}"
        )

    def _load_and_group_data(self) -> Dict[str, List[Dict]]:
        """
        Load CSV data and group by package.

        Returns:
            Dictionary mapping package names to lists of file data
        """
        progress(f"Loading training data from {self.csv_path}...")

        # Load CSV
        try:
            df = pd.read_csv(self.csv_path)
        except Exception as e:
            error(f"Failed to load CSV: {e}")
            raise

        # Validate required columns
        required_cols = ["tokens", "label", "package"]
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            error(f"Missing required columns: {missing_cols}")
            raise ValueError(f"CSV must contain columns: {required_cols}")

        # Handle missing package names
        df["package"] = df["package"].fillna("unknown")
        df["package"] = df["package"].replace("", "unknown")

        # Filter valid rows
        initial_count = len(df)
        df = df.dropna(subset=["tokens"])
        df = df[df["tokens"].str.strip() != ""]

        filtered_count = len(df)
        if filtered_count < initial_count:
            warning(
                f"Filtered out {initial_count - filtered_count} rows with invalid tokens"
            )

        info(f"Processing {filtered_count} CodeObjects from CSV...")

        # Group by package
        package_groups = defaultdict(list)
        for _, row in df.iterrows():
            package_name = str(row["package"])
            code_object_data = {
                "tokens": str(row["tokens"]),
                "label": str(row["label"]),
                "filepath": row.get("filepath", "unknown"),
                "hash": row.get("hash", "unknown"),
            }
            package_groups[package_name].append(code_object_data)

        # Filter packages by CodeObject count
        filtered_packages = {}
        all_benign_samples = []
        malicious_package_count = 0

        for package_name, code_objects in package_groups.items():
            if len(code_objects) >= self.min_objects_per_package:
                # Check if this is a malicious package
                labels = [obj["label"] for obj in code_objects]
                has_malicious = any(label != "benign" for label in labels)

                if has_malicious:
                    # Keep malicious packages as-is
                    malicious_package_count += 1
                    filtered_packages[package_name] = code_objects
                else:
                    # Collect all benign samples for later random sampling
                    all_benign_samples.extend(code_objects)

        # Create random benign collections based on malicious package count
        filtered_packages.update(
            self._create_benign_collections(all_benign_samples, malicious_package_count)
        )

        info(
            f"Filtered to {len(filtered_packages)} packages with {self.min_objects_per_package}+ CodeObjects"
        )

        return filtered_packages

    def _create_benign_collections(
        self, all_benign_samples: List[Dict], malicious_package_count: int
    ) -> Dict[str, List[Dict]]:
        """
        Create random benign collections based on malicious package count.

        Creates malicious_package_count * benign_ratio collections, each with up to
        max_benign_samples_per_package random samples from all available benign samples.

        Args:
            all_benign_samples: All benign CodeObject data from all benign packages
            malicious_package_count: Number of malicious packages

        Returns:
            Dictionary mapping benign collection names to random sample lists
        """
        if not all_benign_samples or malicious_package_count == 0:
            info(
                "No benign samples or malicious packages found - skipping benign collection creation"
            )
            return {}

        # Calculate total number of benign collections needed
        total_benign_collections = malicious_package_count * self.benign_ratio

        benign_collections = {}

        for i in range(total_benign_collections):
            # Sample random objects for this collection
            sample_size = min(
                self.max_benign_samples_per_package, len(all_benign_samples)
            )
            sampled_objects = random.sample(all_benign_samples, sample_size)

            # Create unique collection name
            collection_name = f"benign_collection_{i + 1}"
            benign_collections[collection_name] = sampled_objects

        info(
            f"Created {total_benign_collections} benign collections from {len(all_benign_samples)} total benign samples"
        )
        info(
            f"  - Based on {malicious_package_count} malicious packages × {self.benign_ratio} benign ratio"
        )
        info(
            f"  - Each collection has up to {self.max_benign_samples_per_package} random samples"
        )

        return benign_collections

    def _create_package_windows(
        self, code_objects: List[Dict]
    ) -> Tuple[List[str], List[str]]:
        """
        Create windowed sequences from CodeObjects within a package.

        Instead of concatenating, we create overlapping windows that include
        multiple CodeObjects to provide package-level context while maintaining
        manageable sequence lengths.

        Args:
            code_objects: List of CodeObject data dictionaries

        Returns:
            Tuple of (windowed_sequences, labels_per_window)
        """
        # Extract valid CodeObjects
        valid_objects = []
        for obj in code_objects:
            tokens = obj["tokens"].strip()
            if tokens:
                valid_objects.append(
                    {
                        "tokens": tokens.split(),  # Tokenize to list
                        "label": obj["label"],
                    }
                )

        if not valid_objects:
            return [], []

        # Window parameters
        window_size = (
            self.max_length // 2
        )  # Half max length to leave room for special tokens
        window_stride = window_size // 4  # 75% overlap for better context

        windows = []
        window_labels = []

        # Create overlapping windows
        start_idx = 0
        while start_idx < len(valid_objects):
            window_tokens = []
            window_obj_labels = []

            # Add CodeObjects to current window
            obj_idx = start_idx
            while obj_idx < len(valid_objects) and len(window_tokens) < window_size:
                obj = valid_objects[obj_idx]

                # Check if we can fit this object
                if len(window_tokens) + len(obj["tokens"]) <= window_size:
                    window_tokens.extend(obj["tokens"])
                    # Add a period as separator between objects
                    window_tokens.append(".")
                    window_obj_labels.append(obj["label"])
                    obj_idx += 1
                else:
                    break

            # Remove trailing separator
            if window_tokens and window_tokens[-1] == ".":
                window_tokens.pop()  # Remove trailing separator

            if window_tokens:
                windows.append(" ".join(window_tokens))
                window_labels.append(window_obj_labels)

            # Move to next window
            start_idx += max(
                1, window_stride // 10
            )  # Ensure we advance at least 1 object

            # Stop if we've reached the end
            if obj_idx >= len(valid_objects):
                break

        return windows, window_labels

    def _create_training_samples(
        self, package_name: str, code_objects: List[Dict]
    ) -> List[Dict]:
        """
        Create training samples from package CodeObjects using windowing.

        Args:
            package_name: Name of the package
            code_objects: List of CodeObject data for the package

        Returns:
            List of training sample dictionaries (one per window)
        """
        # Create windows from CodeObjects
        window_sequences, window_labels_lists = self._create_package_windows(
            code_objects
        )

        if not window_sequences:
            return []

        training_samples = []

        for window_idx, (window_text, window_obj_labels) in enumerate(
            zip(window_sequences, window_labels_lists)
        ):
            # Tokenize the window sequence
            encoded = self.tokenizer(
                window_text,
                truncation=True,
                padding="max_length",
                max_length=self.max_length,
                return_tensors="pt",
            )

            # Extract tokenized components
            input_ids = encoded["input_ids"].squeeze(0)
            attention_mask = encoded["attention_mask"].squeeze(0)

            # Create global attention mask
            global_attention_mask = create_global_attention_mask(
                input_ids.unsqueeze(0), self.tokenizer
            ).squeeze(0)

            # Aggregate CodeObject labels within this window
            package_labels = aggregate_package_labels(
                window_obj_labels, self.label_aggregation_strategy
            )

            # Convert to multi-label tensor
            label_tensor = torch.zeros(len(LABEL_TO_ID), dtype=torch.float)
            for label_name, probability in package_labels.items():
                if label_name in LABEL_TO_ID:
                    label_tensor[LABEL_TO_ID[label_name]] = probability

            training_samples.append(
                {
                    "package_name": f"{package_name}_window_{window_idx}",
                    "original_package": package_name,
                    "window_index": window_idx,
                    "input_ids": input_ids,
                    "attention_mask": attention_mask,
                    "global_attention_mask": global_attention_mask,
                    "labels": label_tensor,
                    "object_count": len(window_obj_labels),
                    "window_labels": window_obj_labels,
                    "original_length": len(window_text.split()),
                }
            )

        return training_samples

    def __len__(self) -> int:
        """Return number of training samples (windows)."""
        return len(self.training_samples)

    def __getitem__(self, idx: int) -> Dict:
        """
        Get a training sample by index.

        Args:
            idx: Sample index

        Returns:
            Training sample dictionary
        """
        return self.training_samples[idx]

    def get_label_distribution(self) -> Dict[str, int]:
        """
        Get distribution of labels across all training windows.

        Returns:
            Dictionary mapping label names to counts
        """
        label_counts = defaultdict(int)

        for sample in self.training_samples:
            labels_tensor = sample["labels"]
            for label_idx, probability in enumerate(labels_tensor):
                if probability > 0.5:  # Count as positive if probability > 0.5
                    label_name = ID_TO_LABEL[label_idx]
                    label_counts[label_name] += 1

        return dict(label_counts)

    def get_sample_info(self, idx: int) -> Dict:
        """
        Get detailed information about a training sample.

        Args:
            idx: Sample index

        Returns:
            Sample information dictionary
        """
        sample = self.training_samples[idx]
        return {
            "package_name": sample["package_name"],
            "original_package": sample["original_package"],
            "window_index": sample["window_index"],
            "object_count": sample["object_count"],
            "sequence_length": sample["original_length"],
            "window_labels": sample["window_labels"],
        }

    def get_package_info(self, package_name: str) -> Dict:
        """
        Get detailed information about a package.

        Args:
            package_name: Name of the package

        Returns:
            Package information dictionary
        """
        if package_name not in self.package_data:
            return {"error": f"Package '{package_name}' not found"}

        code_objects = self.package_data[package_name]

        return {
            "package_name": package_name,
            "object_count": len(code_objects),
            "objects": [
                {
                    "filepath": obj.get("filepath", "unknown"),
                    "label": obj["label"],
                    "token_count": len(obj["tokens"].split()),
                }
                for obj in code_objects
            ],
        }


def longformer_collate_fn(batch):
    """
    Custom collate function for Longformer dataset.

    Only collates tensor fields, preserves metadata as lists to avoid shape mismatch errors.
    """
    if not batch:
        raise ValueError("Empty batch")

    # Define which fields should be collated as tensors
    tensor_keys = ["input_ids", "attention_mask", "global_attention_mask", "labels"]

    # Define which fields should be kept as lists
    metadata_keys = [
        "package_name",
        "original_package",
        "window_index",
        "object_count",
        "window_labels",
        "original_length",
    ]

    try:
        # Check tensor shapes
        for key in tensor_keys:
            if key in batch[0]:
                shapes = [sample[key].shape for sample in batch]
                if not all(shape == shapes[0] for shape in shapes):
                    raise ValueError(f"Shape mismatch for {key}: {shapes}")

        # Collate tensors using default_collate
        collated_tensors = {}
        for key in tensor_keys:
            if key in batch[0]:
                values = [sample[key] for sample in batch]
                from torch.utils.data._utils.collate import default_collate

                collated_tensors[key] = default_collate(values)

        # Keep metadata as lists
        collated_metadata = {}
        for key in metadata_keys:
            if key in batch[0]:
                collated_metadata[key] = [sample[key] for sample in batch]

        # Combine results
        result = {**collated_tensors, **collated_metadata}
        return result

    except Exception as e:
        # Provide detailed error information for debugging
        error_msg = f"Batch collation failed: {e}"
        if batch:
            error_msg += f" (batch_size={len(batch)})"
            for key in tensor_keys:
                if key in batch[0]:
                    shapes = [sample[key].shape for sample in batch]
                    if not all(shape == shapes[0] for shape in shapes):
                        error_msg += f" {key}_shapes: {shapes}"

            # Show metadata that might be causing issues
            for key in metadata_keys:
                if key in batch[0]:
                    values = [sample[key] for sample in batch]
                    value_types = [type(v).__name__ for v in values]
                    if key == "window_labels":
                        # Show lengths for list fields
                        lengths = [
                            len(v) if isinstance(v, list) else "not_list"
                            for v in values
                        ]
                        error_msg += f" {key}_lengths: {lengths}"
                    else:
                        error_msg += f" {key}_types: {value_types}"

        raise RuntimeError(error_msg) from e


def create_longformer_dataloaders(
    train_csv: str,
    val_csv: Optional[str] = None,
    tokenizer_path: str = "malwi_models",
    batch_size: int = 2,
    max_length: int = 4098,
    val_split: float = 0.2,
    max_benign_samples_per_package: int = 10,
    benign_ratio: int = 4,
    **dataset_kwargs,
) -> Tuple[torch.utils.data.DataLoader, Optional[torch.utils.data.DataLoader]]:
    """
    Create training and validation data loaders for Longformer.

    Args:
        train_csv: Path to training CSV
        val_csv: Path to validation CSV (optional)
        tokenizer_path: Path to tokenizer
        batch_size: Batch size for data loaders
        max_length: Maximum sequence length
        val_split: Validation split ratio if val_csv not provided
        max_benign_samples_per_package: Maximum number of random samples per benign collection
        benign_ratio: Number of random benign collections to create per benign package
        **dataset_kwargs: Additional arguments for dataset

    Returns:
        Tuple of (train_loader, val_loader)
    """
    from torch.utils.data import DataLoader, random_split

    # Create training dataset
    train_dataset = LongformerPackageDataset(
        csv_path=train_csv,
        tokenizer_path=tokenizer_path,
        max_length=max_length,
        max_benign_samples_per_package=max_benign_samples_per_package,
        benign_ratio=benign_ratio,
        **dataset_kwargs,
    )

    # Create validation dataset
    val_loader = None
    if val_csv:
        val_dataset = LongformerPackageDataset(
            csv_path=val_csv,
            tokenizer_path=tokenizer_path,
            max_length=max_length,
            max_benign_samples_per_package=max_benign_samples_per_package,
            benign_ratio=benign_ratio,
            **dataset_kwargs,
        )
        val_loader = DataLoader(
            val_dataset,
            batch_size=batch_size,
            shuffle=False,
            num_workers=0,  # Avoid multiprocessing issues with tokenizer
            collate_fn=longformer_collate_fn,
        )
    elif val_split > 0:
        # Split training dataset
        total_size = len(train_dataset)
        val_size = int(total_size * val_split)
        train_size = total_size - val_size

        train_subset, val_subset = random_split(train_dataset, [train_size, val_size])

        val_loader = DataLoader(
            val_subset,
            batch_size=batch_size,
            shuffle=False,
            num_workers=0,
            collate_fn=longformer_collate_fn,
        )

        # Use train_subset for training
        train_dataset = train_subset

    # Create training data loader
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=0,  # Avoid multiprocessing issues with tokenizer
        collate_fn=longformer_collate_fn,
    )

    return train_loader, val_loader
