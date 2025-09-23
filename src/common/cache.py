"""Cache system for MalwiObject predictions to speed up repeated scans."""

import csv
import hashlib
from pathlib import Path
from typing import Dict, Optional, List, Tuple
from common.malwi_object import MalwiObject


class MalwiCache:
    """Cache system for storing and retrieving MalwiObject prediction results and triage decisions."""

    def __init__(self, cache_file: Optional[Path] = None):
        """
        Initialize cache system.

        Args:
            cache_file: Path to cache file. If None, caching is disabled.
        """
        self.cache_file = cache_file
        # Unified cache structure: hash -> (filename, object, labels, decision)
        # labels can be None/empty dict, decision can be None if not triaged
        self.cache_data: Dict[str, Tuple[str, str, Optional[Dict], Optional[str]]] = {}
        self.enabled = cache_file is not None

        if self.enabled:
            self._load_cache()

    def _load_cache(self):
        """Load existing cache data from file."""
        if not self.cache_file or not self.cache_file.exists():
            return

        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    hash_key = row["hash"]
                    filename = row["filename"]
                    object_name = row["object"]

                    # Handle labels (could be missing in old format or empty)
                    labels = {}
                    if "labels" in row and row["labels"]:
                        try:
                            # Parse labels from JSON-like string or legacy score
                            import json

                            labels = json.loads(row["labels"])
                        except (ValueError, json.JSONDecodeError):
                            # Fallback for legacy score format
                            if "score" in row and row["score"]:
                                try:
                                    score = float(row["score"])
                                    # Convert legacy score to labels
                                    if score > 0.5:
                                        labels = {"malicious": round(score, 3)}
                                    else:
                                        labels = {"benign": round(1.0 - score, 3)}
                                except ValueError:
                                    labels = {}

                    # Handle decision (could be missing in old format or empty)
                    decision = None
                    if "decision" in row and row["decision"]:
                        decision = row["decision"]

                    self.cache_data[hash_key] = (
                        filename,
                        object_name,
                        labels,
                        decision,
                    )
        except Exception:
            # If cache file is corrupted or has issues, start with empty cache
            self.cache_data = {}

    def _get_object_hash(self, obj: MalwiObject) -> str:
        """
        Generate SHA512 hash of the object's source code.

        Args:
            obj: MalwiObject to hash

        Returns:
            SHA512 hash as hex string
        """
        # Use source_code if available, otherwise fall back to bytecode representation
        content = (
            obj.source_code if obj.source_code else obj.to_string(for_hashing=True)
        )

        if not content:
            # Fallback to file path and object name for error cases
            content = f"{obj.file_path}:{obj.name}"

        # Create SHA512 hash
        return hashlib.sha512(content.encode("utf-8")).hexdigest()

    def get_cached_labels(self, obj: MalwiObject) -> Optional[Dict]:
        """
        Get cached prediction labels for an object.

        Args:
            obj: MalwiObject to look up

        Returns:
            Cached labels dict if found, None otherwise
        """
        if not self.enabled:
            return None

        hash_key = self._get_object_hash(obj)
        if hash_key in self.cache_data:
            return self.cache_data[hash_key][2]  # Return labels (3rd element)

        return None

    def cache_labels(self, obj: MalwiObject, labels: Dict[str, float]):
        """
        Cache prediction labels for an object.

        Args:
            obj: MalwiObject to cache
            labels: Dict of label names to confidence scores
        """
        if not self.enabled:
            return

        # Round label scores to 3 decimal places
        rounded_labels = {k: round(v, 3) for k, v in labels.items()}

        hash_key = self._get_object_hash(obj)
        filename = Path(obj.file_path).name

        # Store in memory cache - preserve existing decision if any
        existing_decision = None
        if hash_key in self.cache_data:
            existing_decision = self.cache_data[hash_key][3]  # 4th element is decision

        self.cache_data[hash_key] = (
            filename,
            obj.name,
            rounded_labels,
            existing_decision,
        )

        # Update cache file
        self._update_cache_file()

    def get_cached_triage_decision(self, obj: MalwiObject) -> Optional[str]:
        """
        Get cached triage decision for an object.

        Args:
            obj: MalwiObject to look up

        Returns:
            Cached triage decision if found, None otherwise
        """
        if not self.enabled:
            return None

        hash_key = self._get_object_hash(obj)
        if hash_key in self.cache_data:
            return self.cache_data[hash_key][3]  # Return decision (4th element)

        return None

    def cache_triage_decision(self, obj: MalwiObject, decision: str):
        """
        Cache triage decision for an object.

        Args:
            obj: MalwiObject to cache
            decision: Triage decision to cache (suspicious, benign)
        """
        if not self.enabled:
            return

        hash_key = self._get_object_hash(obj)
        filename = Path(obj.file_path).name

        # Store in memory cache - preserve existing labels if any
        existing_labels = {}
        if hash_key in self.cache_data:
            existing_labels = (
                self.cache_data[hash_key][2] or {}
            )  # 3rd element is labels

        self.cache_data[hash_key] = (filename, obj.name, existing_labels, decision)

        # Update cache file
        self._update_cache_file()

    def _update_cache_file(self):
        """
        Update the entire cache file with current cache data.
        This prevents duplicates and keeps the file clean.
        """
        try:
            # Create parent directories if they don't exist
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)

            # Write entire cache to file
            with open(self.cache_file, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)

                # Write header
                writer.writerow(["hash", "filename", "object", "labels", "decision"])

                # Write all cache entries
                import json

                for hash_key, (
                    filename,
                    object_name,
                    labels,
                    decision,
                ) in self.cache_data.items():
                    writer.writerow(
                        [
                            hash_key,
                            filename,
                            object_name,
                            json.dumps(labels) if labels else "",
                            decision if decision is not None else "",
                        ]
                    )

        except Exception:
            # If writing fails, continue without caching
            pass

    def get_cache_stats(self) -> Dict[str, int]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        triage_count = sum(
            1 for entry in self.cache_data.values() if entry[3] is not None
        )
        return {
            "total_entries": len(self.cache_data),
            "triage_entries": triage_count,
            "enabled": self.enabled,
        }
