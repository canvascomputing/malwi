"""Test to prevent cache duplication issues."""

import tempfile
from pathlib import Path

from common.cache import MalwiCache
from common.malwi_object import MalwiObject


class TestCacheDuplication:
    """Test suite for cache duplication prevention."""

    def test_score_and_decision_no_duplication(self):
        """Test that caching score and decision for same object creates only one entry."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "test_cache.csv"
            cache = MalwiCache(cache_path)

            # Create a test object
            obj = MalwiObject(
                name="test_function",
                language="python",
                file_path=str(Path(temp_dir) / "test.py"),
                file_source_code="test code",
                source_code="test code",
            )
            obj.maliciousness = 0.95

            # Cache score first
            cache.cache_score(obj, 0.95)

            # Cache triage decision
            cache.cache_triage_decision(obj, "suspicious")

            # Read the cache file and count entries for this object
            with open(cache_path, "r") as f:
                lines = f.readlines()

            # Count non-header lines (data rows)
            data_rows = [line for line in lines if not line.startswith("hash,")]

            # Should have only ONE entry, not two
            assert len(data_rows) == 1, (
                f"Expected 1 cache entry, got {len(data_rows)}: {data_rows}"
            )

            # Verify the single entry has both score and decision
            data_row = data_rows[0].strip()
            assert "0.95" in data_row, "Score missing from cache entry"
            assert "suspicious" in data_row, "Decision missing from cache entry"

    def test_multiple_objects_no_duplication(self):
        """Test multiple objects don't create duplicate entries."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "test_cache.csv"
            cache = MalwiCache(cache_path)

            # Create two different objects
            obj1 = MalwiObject(
                name="test_function_1",
                language="python",
                file_path=str(Path(temp_dir) / "test1.py"),
                file_source_code="code 1",
                source_code="code 1",
            )
            obj1.maliciousness = 0.95

            obj2 = MalwiObject(
                name="test_function_2",
                language="python",
                file_path=str(Path(temp_dir) / "test2.py"),
                file_source_code="code 2",
                source_code="code 2",
            )
            obj2.maliciousness = 0.85

            # Cache scores and decisions for both
            cache.cache_score(obj1, 0.95)
            cache.cache_triage_decision(obj1, "suspicious")

            cache.cache_score(obj2, 0.85)
            cache.cache_triage_decision(obj2, "benign")

            # Read cache file
            with open(cache_path, "r") as f:
                lines = f.readlines()

            data_rows = [line for line in lines if not line.startswith("hash,")]

            # Should have exactly 2 entries (one per object)
            assert len(data_rows) == 2, (
                f"Expected 2 cache entries, got {len(data_rows)}: {data_rows}"
            )

            # Verify both entries have score and decision
            for row in data_rows:
                assert any(score in row for score in ["0.95", "0.85"]), (
                    f"Score missing from row: {row}"
                )
                assert any(decision in row for decision in ["suspicious", "benign"]), (
                    f"Decision missing from row: {row}"
                )

    def test_cache_update_preserves_existing_data(self):
        """Test that updating cache preserves existing score/decision."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "test_cache.csv"

            obj = MalwiObject(
                name="test_function",
                language="python",
                file_path=str(Path(temp_dir) / "test.py"),
                file_source_code="test",
                source_code="test",
            )

            # First session: cache only score
            cache1 = MalwiCache(cache_path)
            cache1.cache_score(obj, 0.95)

            # Second session: new cache instance, add decision
            cache2 = MalwiCache(cache_path)
            cache2.cache_triage_decision(obj, "suspicious")

            # Third session: verify both are preserved
            cache3 = MalwiCache(cache_path)
            assert cache3.get_cached_score(obj) == 0.95, "Score not preserved"
            assert cache3.get_cached_triage_decision(obj) == "suspicious", (
                "Decision not preserved"
            )

            # Verify file has only one entry
            with open(cache_path, "r") as f:
                lines = f.readlines()

            data_rows = [line for line in lines if not line.startswith("hash,")]
            assert len(data_rows) == 1, (
                f"Expected 1 entry after updates, got {len(data_rows)}: {data_rows}"
            )

    def test_decision_first_then_score(self):
        """Test caching decision first, then score doesn't duplicate."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "test_cache.csv"
            cache = MalwiCache(cache_path)

            obj = MalwiObject(
                name="test_function",
                language="python",
                file_path=str(Path(temp_dir) / "test.py"),
                file_source_code="test",
                source_code="test",
            )
            obj.maliciousness = 0.75

            # Cache decision first
            cache.cache_triage_decision(obj, "benign")

            # Then cache score
            cache.cache_score(obj, 0.75)

            # Should still have only one entry
            with open(cache_path, "r") as f:
                lines = f.readlines()

            data_rows = [line for line in lines if not line.startswith("hash,")]
            assert len(data_rows) == 1, (
                f"Expected 1 entry, got {len(data_rows)}: {data_rows}"
            )

            # Entry should have both values
            data_row = data_rows[0]
            assert "0.75" in data_row and "benign" in data_row
