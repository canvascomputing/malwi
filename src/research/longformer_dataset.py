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
            benign_ratio: Training balance ratio - creates this many benign collections per malicious package (not per benign package)
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

        if len(self.package_data) > 0:
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


class LongformerFileDataset(Dataset):
    """
    Dataset for file-level malware detection with Longformer.

    Groups CodeObjects by file, concatenating all objects from each file into
    a single training sample for file-level analysis. Uses random benign sampling.
    """

    def __init__(
        self,
        csv_path: str,
        tokenizer_path: str = "malwi_models",
        max_length: int = 4096,
        label_aggregation_strategy: str = "any_positive",
        max_benign_samples_per_file: int = 10,
        benign_ratio: int = 4,
    ):
        """
        Initialize the dataset.

        Args:
            csv_path: Path to CSV with tokens, label, filepath columns
            tokenizer_path: Path to DistilBERT tokenizer
            max_length: Maximum sequence length for Longformer
            label_aggregation_strategy: How to aggregate CodeObject labels to file labels
            max_benign_samples_per_file: Maximum number of random samples per benign file
            benign_ratio: Number of benign files to create per malicious file
        """
        self.csv_path = csv_path
        self.max_length = max_length
        self.label_aggregation_strategy = label_aggregation_strategy
        self.max_benign_samples_per_file = max_benign_samples_per_file
        self.benign_ratio = benign_ratio

        # Load tokenizer
        progress(f"Loading tokenizer from {tokenizer_path}...")
        if tokenizer_path == "allenai/longformer-base-4096":
            tokenizer_path = "malwi_models"
            info("Using custom trained tokenizer from malwi_models")

        self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)
        info(f"Loaded tokenizer with vocab_size={len(self.tokenizer)}")

        # Load and process data
        self.file_data = self._load_and_group_by_file()

        # Pre-compute all training samples
        self.training_samples = []
        for filepath, code_objects in self.file_data.items():
            sample = self._create_training_sample(filepath, code_objects)
            if sample:
                self.training_samples.append(sample)

        info(f"Loaded {len(self.file_data)} files for training")
        info(f"Generated {len(self.training_samples)} training samples")

    def _load_and_group_by_file(self) -> Dict[str, List[Dict]]:
        """Load CSV data and group by filepath with benign sampling."""
        progress(f"Loading training data from {self.csv_path}...")

        df = pd.read_csv(self.csv_path)

        # Validate required columns
        required_cols = ["tokens", "label", "filepath"]
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            error(f"Missing required columns: {missing_cols}")
            raise ValueError(f"CSV must contain columns: {required_cols}")

        # Handle missing filepaths
        df["filepath"] = df["filepath"].fillna("unknown")
        df["filepath"] = df["filepath"].replace("", "unknown")

        # Filter valid rows
        df = df.dropna(subset=["tokens"])
        df = df[df["tokens"].str.strip() != ""]

        info(f"Processing {len(df)} CodeObjects from CSV...")

        # Group by filepath
        file_groups = defaultdict(list)
        for _, row in df.iterrows():
            filepath = str(row["filepath"])
            code_object_data = {
                "tokens": str(row["tokens"]),
                "label": str(row["label"]),
                "package": row.get("package", "unknown"),
                "hash": row.get("hash", "unknown"),
            }
            file_groups[filepath].append(code_object_data)

        # Filter files: keep malicious, collect benign samples
        filtered_files = {}
        all_benign_samples = []
        malicious_file_count = 0

        for filepath, code_objects in file_groups.items():
            labels = [obj["label"] for obj in code_objects]
            has_malicious = any(label != "benign" for label in labels)

            if has_malicious:
                # Keep malicious files as-is
                malicious_file_count += 1
                filtered_files[filepath] = code_objects
            else:
                # Collect benign samples for random sampling
                all_benign_samples.extend(code_objects)

        # Create random benign files based on malicious file count
        filtered_files.update(
            self._create_benign_files(all_benign_samples, malicious_file_count)
        )

        info(
            f"Filtered to {len(filtered_files)} files ({malicious_file_count} malicious + random benign)"
        )

        return filtered_files

    def _create_benign_files(
        self, all_benign_samples: List[Dict], malicious_file_count: int
    ) -> Dict[str, List[Dict]]:
        """
        Create random benign files based on malicious file count.

        Creates malicious_file_count * benign_ratio files, each with up to
        max_benign_samples_per_file random samples.

        Args:
            all_benign_samples: All benign CodeObject data from all benign files
            malicious_file_count: Number of malicious files

        Returns:
            Dictionary mapping benign file names to random sample lists
        """
        if not all_benign_samples or malicious_file_count == 0:
            info(
                "No benign samples or malicious files found - skipping benign file creation"
            )
            return {}

        # Calculate total number of benign files needed
        total_benign_files = malicious_file_count * self.benign_ratio

        benign_files = {}

        for i in range(total_benign_files):
            # Sample random objects for this file
            sample_size = min(self.max_benign_samples_per_file, len(all_benign_samples))
            sampled_objects = random.sample(all_benign_samples, sample_size)

            # Create unique file name
            file_name = f"benign_file_{i + 1}"
            benign_files[file_name] = sampled_objects

        info(
            f"Created {total_benign_files} benign files from {len(all_benign_samples)} total benign samples"
        )
        info(
            f"  - Based on {malicious_file_count} malicious files × {self.benign_ratio} benign ratio"
        )
        info(
            f"  - Each file has up to {self.max_benign_samples_per_file} random samples"
        )

        return benign_files

    def _create_training_sample(
        self, filepath: str, code_objects: List[Dict]
    ) -> Optional[Dict]:
        """Create a training sample from all CodeObjects in a file."""
        # Concatenate all tokens from the file
        all_tokens = []
        all_labels = []

        for obj in code_objects:
            tokens = obj["tokens"].strip()
            if tokens:
                all_tokens.extend(tokens.split())
                all_tokens.append(".")  # Separator between objects
                all_labels.append(obj["label"])

        # Remove trailing separator
        if all_tokens and all_tokens[-1] == ".":
            all_tokens.pop()

        if not all_tokens:
            return None

        # Join tokens
        token_text = " ".join(all_tokens)

        # Tokenize
        encoded = self.tokenizer(
            token_text,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )

        input_ids = encoded["input_ids"].squeeze(0)
        attention_mask = encoded["attention_mask"].squeeze(0)

        # Create global attention mask
        global_attention_mask = create_global_attention_mask(
            input_ids.unsqueeze(0), self.tokenizer
        ).squeeze(0)

        # Aggregate labels
        file_labels = aggregate_package_labels(
            all_labels, self.label_aggregation_strategy
        )

        # Convert to multi-label tensor
        label_tensor = torch.zeros(len(LABEL_TO_ID), dtype=torch.float)
        for label_name, probability in file_labels.items():
            if label_name in LABEL_TO_ID:
                label_tensor[LABEL_TO_ID[label_name]] = probability

        return {
            "filepath": filepath,
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "global_attention_mask": global_attention_mask,
            "labels": label_tensor,
            "object_count": len(all_labels),
            "file_labels": all_labels,
            "original_length": len(all_tokens),
        }

    def __len__(self) -> int:
        return len(self.training_samples)

    def __getitem__(self, idx: int) -> Dict:
        return self.training_samples[idx]

    def get_label_distribution(self) -> Dict[str, int]:
        """Get distribution of labels across all files."""
        label_counts = defaultdict(int)
        for sample in self.training_samples:
            labels_tensor = sample["labels"]
            for label_idx, probability in enumerate(labels_tensor):
                if probability > 0.5:
                    label_name = ID_TO_LABEL[label_idx]
                    label_counts[label_name] += 1
        return dict(label_counts)


class LongformerObjectDataset(Dataset):
    """
    Dataset for object-level malware detection with Longformer.

    Each CodeObject becomes an individual training sample. Uses random benign sampling
    controlled by benign_ratio.
    """

    def __init__(
        self,
        csv_path: str,
        tokenizer_path: str = "malwi_models",
        max_length: int = 4096,
        benign_ratio: int = 1,
        random_seed: int = 42,
    ):
        """
        Initialize the dataset.

        Args:
            csv_path: Path to CSV with tokens, label columns
            tokenizer_path: Path to DistilBERT tokenizer
            max_length: Maximum sequence length for Longformer
            benign_ratio: Number of random benign objects per malicious object (default: 1)
            random_seed: Seed for random benign sampling (default: 42)
        """
        self.csv_path = csv_path
        self.max_length = max_length
        self.benign_ratio = benign_ratio
        self.random_seed = random_seed

        # Seed random number generator for reproducibility
        random.seed(random_seed)

        # Load tokenizer
        progress(f"Loading tokenizer from {tokenizer_path}...")
        if tokenizer_path == "allenai/longformer-base-4096":
            tokenizer_path = "malwi_models"
            info("Using custom trained tokenizer from malwi_models")

        self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)
        info(f"Loaded tokenizer with vocab_size={len(self.tokenizer)}")

        # Load and process data
        self.training_samples = self._load_objects()

        info(f"Loaded {len(self.training_samples)} CodeObjects for training")

    def _load_objects(self) -> List[Dict]:
        """Load CSV data and create training samples with benign sampling."""
        progress(f"Loading training data from {self.csv_path}...")

        df = pd.read_csv(self.csv_path)

        # Validate required columns
        required_cols = ["tokens", "label"]
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            error(f"Missing required columns: {missing_cols}")
            raise ValueError(f"CSV must contain columns: {required_cols}")

        # Filter valid rows
        df = df.dropna(subset=["tokens"])
        df = df[df["tokens"].str.strip() != ""]

        info(f"Processing {len(df)} CodeObjects from CSV...")

        # Separate malicious and benign objects
        malicious_objects = []
        benign_objects = []

        for idx, row in df.iterrows():
            tokens = str(row["tokens"]).strip()
            if not tokens:
                continue

            label = str(row["label"])
            obj_data = {
                "idx": idx,
                "tokens": tokens,
                "label": label,
                "filepath": row.get("filepath", "unknown"),
                "package": row.get("package", "unknown"),
            }

            if label == "benign":
                benign_objects.append(obj_data)
            else:
                malicious_objects.append(obj_data)

        # Create training samples
        training_samples = []

        # Add all malicious objects
        for obj in malicious_objects:
            sample = self._create_object_sample(obj)
            if sample:
                training_samples.append(sample)

        # Pick random benign objects based on benign_ratio
        if benign_objects and malicious_objects:
            num_benign_samples = len(malicious_objects) * self.benign_ratio
            sampled_benign = random.choices(benign_objects, k=num_benign_samples)

            for obj in sampled_benign:
                sample = self._create_object_sample(obj)
                if sample:
                    training_samples.append(sample)

            info(
                f"Created {len(malicious_objects)} malicious + {num_benign_samples} random benign samples (ratio: {self.benign_ratio})"
            )
        else:
            info(f"Created {len(training_samples)} samples (no benign sampling)")

        return training_samples

    def _create_object_sample(self, obj_data: Dict) -> Optional[Dict]:
        """Create a training sample from object data."""
        tokens = obj_data["tokens"]

        # Tokenize
        encoded = self.tokenizer(
            tokens,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )

        input_ids = encoded["input_ids"].squeeze(0)
        attention_mask = encoded["attention_mask"].squeeze(0)

        # Create global attention mask
        global_attention_mask = create_global_attention_mask(
            input_ids.unsqueeze(0), self.tokenizer
        ).squeeze(0)

        # Get label
        label = obj_data["label"]
        label_tensor = torch.zeros(len(LABEL_TO_ID), dtype=torch.float)
        if label in LABEL_TO_ID:
            label_tensor[LABEL_TO_ID[label]] = 1.0

        return {
            "object_id": obj_data["idx"],
            "filepath": obj_data["filepath"],
            "package": obj_data["package"],
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "global_attention_mask": global_attention_mask,
            "labels": label_tensor,
            "label_name": label,
            "original_length": len(tokens.split()),
        }

    def __len__(self) -> int:
        return len(self.training_samples)

    def __getitem__(self, idx: int) -> Dict:
        return self.training_samples[idx]

    def get_label_distribution(self) -> Dict[str, int]:
        """Get distribution of labels across all objects."""
        label_counts = defaultdict(int)
        for sample in self.training_samples:
            labels_tensor = sample["labels"]
            for label_idx, probability in enumerate(labels_tensor):
                if probability > 0.5:
                    label_name = ID_TO_LABEL[label_idx]
                    label_counts[label_name] += 1
        return dict(label_counts)


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
    strategy: str = "package",
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
        benign_ratio: Training balance ratio - creates this many benign collections per malicious package
        strategy: Training strategy - "package" (default), "file", or "object"
        **dataset_kwargs: Additional arguments for dataset

    Returns:
        Tuple of (train_loader, val_loader)
    """
    from torch.utils.data import DataLoader, random_split

    # Select dataset class based on strategy
    if strategy == "package":
        dataset_class = LongformerPackageDataset
        dataset_args = {
            "csv_path": train_csv,
            "tokenizer_path": tokenizer_path,
            "max_length": max_length,
            "max_benign_samples_per_package": max_benign_samples_per_package,
            "benign_ratio": benign_ratio,
            **dataset_kwargs,
        }
    elif strategy == "file":
        dataset_class = LongformerFileDataset
        dataset_args = {
            "csv_path": train_csv,
            "tokenizer_path": tokenizer_path,
            "max_length": max_length,
            "max_benign_samples_per_file": max_benign_samples_per_package,
            "benign_ratio": benign_ratio,
            **{
                k: v
                for k, v in dataset_kwargs.items()
                if k == "label_aggregation_strategy"
            },
        }
    elif strategy == "object":
        dataset_class = LongformerObjectDataset
        dataset_args = {
            "csv_path": train_csv,
            "tokenizer_path": tokenizer_path,
            "max_length": max_length,
            "benign_ratio": benign_ratio,
        }
    else:
        raise ValueError(
            f"Unknown strategy: {strategy}. Must be 'package', 'file', or 'object'"
        )

    info(f"Using training strategy: {strategy}")

    # Create training dataset
    train_dataset = dataset_class(**dataset_args)

    # Create validation dataset
    val_loader = None
    if val_csv:
        val_dataset_args = dataset_args.copy()
        val_dataset_args["csv_path"] = val_csv
        val_dataset = dataset_class(**val_dataset_args)
        val_loader = DataLoader(
            val_dataset,
            batch_size=batch_size,
            shuffle=False,
            num_workers=0,  # Avoid multiprocessing issues with tokenizer
            collate_fn=longformer_collate_fn,
        )
    elif val_split is not None and val_split > 0:
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
