"""Test triage caching behavior to ensure skip decisions are not cached."""

import tempfile
from pathlib import Path
from unittest.mock import Mock

from common.cache import MalwiCache
from common.malwi_report import triage_malicious_objects
from common.malwi_object import MalwiObject
from common.triage import TRIAGE_SKIP, TRIAGE_SUSPICIOUS, TRIAGE_BENIGN, TRIAGE_QUIT


class TestTriageCacheBehavior:
    """Test suite for triage caching behavior."""

    def test_skip_decision_not_cached(self):
        """Test that skip decisions are not cached."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "test_cache"
            cache = MalwiCache(cache_path)

            # Create a test file
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("import os\nos.system('test')")

            # Create a malicious object
            obj = MalwiObject(
                name="test_function",
                language="python",
                file_path=str(test_file),
                file_source_code="import os\nos.system('test')",
                source_code="os.system('test')",
            )
            obj.maliciousness = 0.95  # Set after creation

            # Mock triage provider that returns skip
            mock_provider = Mock()
            mock_provider.classify_object.return_value = TRIAGE_SKIP

            # Run triage
            result = triage_malicious_objects(
                test_file, [obj], [obj], mock_provider, cache
            )

            # Skip should return empty list (object not triaged as malicious)
            assert len(result) == 0

            # Most importantly: skip decision should NOT be cached
            cached_decision = cache.get_cached_triage_decision(obj)
            assert cached_decision is None, "Skip decision should not be cached"

    def test_suspicious_decision_cached(self):
        """Test that suspicious decisions are cached."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "test_cache"
            cache = MalwiCache(cache_path)

            # Create a test file
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("import os\nos.system('test')")

            # Create a malicious object
            obj = MalwiObject(
                name="test_function",
                language="python",
                file_path=str(test_file),
                file_source_code="import os\nos.system('test')",
                source_code="os.system('test')",
            )
            obj.maliciousness = 0.95  # Set after creation

            # Mock triage provider that returns suspicious
            mock_provider = Mock()
            mock_provider.classify_object.return_value = TRIAGE_SUSPICIOUS

            # Run triage
            result = triage_malicious_objects(
                test_file, [obj], [obj], mock_provider, cache
            )

            # Suspicious should return the object
            assert len(result) == 1
            assert result[0] == obj

            # Suspicious decision should be cached
            cached_decision = cache.get_cached_triage_decision(obj)
            assert cached_decision == TRIAGE_SUSPICIOUS

    def test_benign_decision_cached(self):
        """Test that benign decisions are cached."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "test_cache"
            cache = MalwiCache(cache_path)

            # Create a test file
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("import os\nos.system('test')")

            # Create a malicious object
            obj = MalwiObject(
                name="test_function",
                language="python",
                file_path=str(test_file),
                file_source_code="import os\nos.system('test')",
                source_code="os.system('test')",
            )
            obj.maliciousness = 0.95  # Set after creation

            # Mock triage provider that returns benign
            mock_provider = Mock()
            mock_provider.classify_object.return_value = TRIAGE_BENIGN

            # Run triage
            result = triage_malicious_objects(
                test_file, [obj], [obj], mock_provider, cache
            )

            # Benign should return empty list (object filtered out)
            assert len(result) == 0

            # Benign decision should be cached
            cached_decision = cache.get_cached_triage_decision(obj)
            assert cached_decision == TRIAGE_BENIGN

    def test_quit_decision_not_cached(self):
        """Test that quit decisions are not cached (and raise exception)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "test_cache"
            cache = MalwiCache(cache_path)

            # Create a test file
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("import os\nos.system('test')")

            # Create a malicious object
            obj = MalwiObject(
                name="test_function",
                language="python",
                file_path=str(test_file),
                file_source_code="import os\nos.system('test')",
                source_code="os.system('test')",
            )
            obj.maliciousness = 0.95  # Set after creation

            # Mock triage provider that returns quit
            mock_provider = Mock()
            mock_provider.classify_object.return_value = TRIAGE_QUIT

            # Run triage - should raise exception
            from common.malwi_report import TriageQuitException

            try:
                triage_malicious_objects(test_file, [obj], [obj], mock_provider, cache)
                assert False, "Should have raised TriageQuitException"
            except TriageQuitException:
                pass  # Expected

            # Quit decision should NOT be cached
            cached_decision = cache.get_cached_triage_decision(obj)
            assert cached_decision is None, "Quit decision should not be cached"

    def test_cache_persistence_skip_vs_definitive(self):
        """Test that skip decisions don't persist while definitive decisions do."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "test_cache"

            # Create a test file
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("import os\nos.system('test')")

            # Create two similar malicious objects
            obj1 = MalwiObject(
                name="test_function_1",
                language="python",
                file_path=str(test_file),
                file_source_code="import os\nos.system('test')",
                source_code="os.system('test1')",  # Different source to get different hash
            )
            obj1.maliciousness = 0.95  # Set after creation

            obj2 = MalwiObject(
                name="test_function_2",
                language="python",
                file_path=str(test_file),
                file_source_code="import os\nos.system('test')",
                source_code="os.system('test2')",  # Different source to get different hash
            )
            obj2.maliciousness = 0.95  # Set after creation

            # First session: skip obj1, mark obj2 as suspicious
            cache1 = MalwiCache(cache_path)

            mock_provider1 = Mock()
            mock_provider1.classify_object.side_effect = [
                TRIAGE_SKIP,
                TRIAGE_SUSPICIOUS,
            ]

            result1 = triage_malicious_objects(
                test_file, [obj1, obj2], [obj1, obj2], mock_provider1, cache1
            )

            assert len(result1) == 1  # Only obj2 (suspicious)
            assert result1[0] == obj2

            # Second session: new cache instance (simulating fresh scan)
            cache2 = MalwiCache(cache_path)

            # obj1 should not have cached decision (was skipped)
            assert cache2.get_cached_triage_decision(obj1) is None

            # obj2 should have cached decision (was marked suspicious)
            assert cache2.get_cached_triage_decision(obj2) == TRIAGE_SUSPICIOUS

            # If we run triage again, obj1 should be presented again (not cached)
            # but obj2 should use cached decision
            mock_provider2 = Mock()
            mock_provider2.classify_object.side_effect = [
                TRIAGE_BENIGN
            ]  # Only called for obj1

            result2 = triage_malicious_objects(
                test_file,
                [obj1, obj2],  # Same objects
                [obj1, obj2],
                mock_provider2,
                cache2,
            )

            # obj1 was triaged as benign (new decision), obj2 used cached suspicious decision
            assert len(result2) == 1  # Only obj2 (still suspicious from cache)
            assert result2[0] == obj2

            # Now obj1 should have benign cached
            assert cache2.get_cached_triage_decision(obj1) == TRIAGE_BENIGN
            # obj2 should still have suspicious cached
            assert cache2.get_cached_triage_decision(obj2) == TRIAGE_SUSPICIOUS
