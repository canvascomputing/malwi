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
        self.cache_data: Dict[str, Tuple[str, str, float]] = {}
        self.triage_cache_file = None
        self.triage_data: Dict[
            str, Tuple[str, str, str]
        ] = {}  # hash -> (filename, object, decision)
        self.enabled = cache_file is not None

        if self.enabled:
            self._load_cache()
            # Set up triage cache file (same directory, different extension)
            self.triage_cache_file = cache_file.with_suffix(".triage.csv")
            self._load_triage_cache()

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
                    score = round(float(row["score"]), 3)  # Round to 3 decimal places
                    self.cache_data[hash_key] = (filename, object_name, score)
        except Exception:
            # If cache file is corrupted or has issues, start with empty cache
            self.cache_data = {}

    def _load_triage_cache(self):
        """Load existing triage cache data from file."""
        if not self.triage_cache_file or not self.triage_cache_file.exists():
            return

        try:
            with open(self.triage_cache_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    hash_key = row["hash"]
                    filename = row["filename"]
                    object_name = row["object"]
                    decision = row["decision"]
                    self.triage_data[hash_key] = (filename, object_name, decision)
        except Exception:
            # If triage cache file is corrupted or has issues, start with empty cache
            self.triage_data = {}

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

    def get_cached_score(self, obj: MalwiObject) -> Optional[float]:
        """
        Get cached prediction score for an object.

        Args:
            obj: MalwiObject to look up

        Returns:
            Cached score if found, None otherwise
        """
        if not self.enabled:
            return None

        hash_key = self._get_object_hash(obj)
        if hash_key in self.cache_data:
            return self.cache_data[hash_key][2]  # Return score

        return None

    def cache_score(self, obj: MalwiObject, score: float):
        """
        Cache prediction score for an object.

        Args:
            obj: MalwiObject to cache
            score: Prediction score to cache
        """
        if not self.enabled:
            return

        # Round score to 3 decimal places
        rounded_score = round(score, 3)

        hash_key = self._get_object_hash(obj)
        filename = Path(obj.file_path).name

        # Store in memory cache
        self.cache_data[hash_key] = (filename, obj.name, rounded_score)

        # Append to file
        self._append_to_cache_file(hash_key, filename, obj.name, rounded_score)

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
        if hash_key in self.triage_data:
            return self.triage_data[hash_key][2]  # Return decision

        return None

    def cache_triage_decision(self, obj: MalwiObject, decision: str):
        """
        Cache triage decision for an object.

        Args:
            obj: MalwiObject to cache
            decision: Triage decision to cache (suspicious, benign, skip)
        """
        if not self.enabled:
            return

        hash_key = self._get_object_hash(obj)
        filename = Path(obj.file_path).name

        # Store in memory cache
        self.triage_data[hash_key] = (filename, obj.name, decision)

        # Append to file
        self._append_to_triage_cache_file(hash_key, filename, obj.name, decision)

    def _append_to_cache_file(
        self, hash_key: str, filename: str, object_name: str, score: float
    ):
        """
        Append new cache entry to file.

        Args:
            hash_key: SHA512 hash
            filename: Name of the file
            object_name: Name of the object
            score: Prediction score
        """
        try:
            # Create parent directories if they don't exist
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)

            # Check if file exists to write header
            file_exists = self.cache_file.exists()

            with open(self.cache_file, "a", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)

                # Write header if new file
                if not file_exists:
                    writer.writerow(["hash", "filename", "object", "score"])

                # Write data row
                writer.writerow([hash_key, filename, object_name, score])

        except Exception:
            # If writing fails, continue without caching
            pass

    def _append_to_triage_cache_file(
        self, hash_key: str, filename: str, object_name: str, decision: str
    ):
        """
        Append new triage cache entry to file.

        Args:
            hash_key: SHA512 hash
            filename: Name of the file
            object_name: Name of the object
            decision: Triage decision
        """
        try:
            # Create parent directories if they don't exist
            self.triage_cache_file.parent.mkdir(parents=True, exist_ok=True)

            # Check if file exists to write header
            file_exists = self.triage_cache_file.exists()

            with open(self.triage_cache_file, "a", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)

                # Write header if new file
                if not file_exists:
                    writer.writerow(["hash", "filename", "object", "decision"])

                # Write data row
                writer.writerow([hash_key, filename, object_name, decision])

        except Exception:
            # If writing fails, continue without caching
            pass

    def get_cache_stats(self) -> Dict[str, int]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        return {
            "total_entries": len(self.cache_data),
            "triage_entries": len(self.triage_data),
            "enabled": self.enabled,
        }
