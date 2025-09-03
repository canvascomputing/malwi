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
        # Unified cache structure: hash -> (filename, object, score, decision)
        # score can be None if not available, decision can be None if not triaged
        self.cache_data: Dict[str, Tuple[str, str, Optional[float], Optional[str]]] = {}
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

                    # Handle score (could be missing in old format or empty)
                    score = None
                    if "score" in row and row["score"]:
                        try:
                            score = round(
                                float(row["score"]), 3
                            )  # Round to 3 decimal places
                        except ValueError:
                            score = None

                    # Handle decision (could be missing in old format or empty)
                    decision = None
                    if "decision" in row and row["decision"]:
                        decision = row["decision"]

                    self.cache_data[hash_key] = (filename, object_name, score, decision)
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
            return self.cache_data[hash_key][2]  # Return score (3rd element)

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

        # Store in memory cache - preserve existing decision if any
        existing_decision = None
        if hash_key in self.cache_data:
            existing_decision = self.cache_data[hash_key][3]  # 4th element is decision

        self.cache_data[hash_key] = (
            filename,
            obj.name,
            rounded_score,
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

        # Store in memory cache - preserve existing score if any
        existing_score = None
        if hash_key in self.cache_data:
            existing_score = self.cache_data[hash_key][2]  # 3rd element is score

        self.cache_data[hash_key] = (filename, obj.name, existing_score, decision)

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
                writer.writerow(["hash", "filename", "object", "score", "decision"])

                # Write all cache entries
                for hash_key, (
                    filename,
                    object_name,
                    score,
                    decision,
                ) in self.cache_data.items():
                    writer.writerow(
                        [
                            hash_key,
                            filename,
                            object_name,
                            score if score is not None else "",
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
        return {
            "total_entries": len(self.cache_data),
            "triage_entries": len(self.triage_data),
            "enabled": self.enabled,
        }
