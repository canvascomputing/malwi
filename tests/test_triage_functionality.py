"""Tests for triage functionality including file modification."""

import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from common.malwi_object import MalwiObject
from common.malwi_report import triage_malicious_objects, TriageQuitException


class TestTriageMaliciousObjects:
    """Test the triage_malicious_objects function."""

    @patch("questionary.select")
    def test_triage_suspicious_classification(self, mock_questionary_select, tmp_path):
        """Test triage when user classifies finding as suspicious."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("exec('test')\nprint('normal')")

        # Create mock MalwiObject
        obj = MalwiObject(
            name="test_module",
            language="python",
            file_path=str(test_file),
            file_source_code="exec('test')",
            location=(1, 1),
        )
        obj.maliciousness = 0.95

        # Mock user selecting "Suspicious"
        mock_questionary_select.return_value.ask.return_value = (
            "Suspicious (keep as malicious)"
        )

        # Run triage (passing obj as both malicious and all_objects for test)
        result = triage_malicious_objects(test_file, [obj], [obj])

        # Object should be kept as malicious
        assert len(result) == 1
        assert result[0] == obj

        # File should not be modified
        assert test_file.read_text() == "exec('test')\nprint('normal')"

    @patch("questionary.select")
    def test_triage_benign_classification(self, mock_questionary_select, tmp_path):
        """Test triage when user classifies finding as benign."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("exec('test')\nprint('normal')")

        # Create mock MalwiObject
        obj = MalwiObject(
            name="test_module",
            language="python",
            file_path=str(test_file),
            file_source_code="exec('test')",
            location=(1, 1),
        )
        obj.maliciousness = 0.95

        # Mock user selecting "Benign"
        mock_questionary_select.return_value.ask.return_value = (
            "Benign (false positive)"
        )

        # Run triage (passing obj as both malicious and all_objects for test)
        result = triage_malicious_objects(test_file, [obj], [obj])

        # Object should not be kept as malicious
        assert len(result) == 0

        # File should be modified (line 1 commented out)
        modified_content = test_file.read_text()
        lines = modified_content.split("\n")
        assert lines[0] == "# exec('test')"
        assert lines[1] == "print('normal')"  # Unchanged

    @patch("questionary.select")
    def test_triage_skip_classification(self, mock_questionary_select, tmp_path):
        """Test triage when user selects skip."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("exec('test')\nprint('normal')")

        # Create mock MalwiObject
        obj = MalwiObject(
            name="test_module",
            language="python",
            file_path=str(test_file),
            file_source_code="exec('test')",
            location=(1, 1),
        )
        obj.maliciousness = 0.95

        # Mock user selecting "Skip"
        mock_questionary_select.return_value.ask.return_value = "Skip (unsure)"

        # Run triage (passing obj as both malicious and all_objects for test)
        result = triage_malicious_objects(test_file, [obj], [obj])

        # Object should not be kept as malicious
        assert len(result) == 0

        # File should not be modified
        assert test_file.read_text() == "exec('test')\nprint('normal')"

    @patch("questionary.select")
    def test_triage_quit_classification(self, mock_questionary_select, tmp_path):
        """Test triage when user selects quit."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("exec('test')\nprint('normal')")

        # Create mock MalwiObject
        obj = MalwiObject(
            name="test_module",
            language="python",
            file_path=str(test_file),
            file_source_code="exec('test')",
            location=(1, 1),
        )
        obj.maliciousness = 0.95

        # Mock user selecting "Quit"
        mock_questionary_select.return_value.ask.return_value = "Quit (stop triaging)"

        # Run triage and expect exception
        with pytest.raises(TriageQuitException):
            triage_malicious_objects(test_file, [obj], [obj])

        # File should not be modified
        assert test_file.read_text() == "exec('test')\nprint('normal')"

    @patch("questionary.select")
    def test_triage_multiple_objects_mixed_classification(
        self, mock_questionary_select, tmp_path
    ):
        """Test triage with multiple objects and mixed classifications."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("exec('test1')\nexec('test2')\nprint('normal')")

        # Create mock MalwiObjects
        obj1 = MalwiObject(
            name="obj1",
            language="python",
            file_path=str(test_file),
            file_source_code="exec('test1')",
            location=(1, 1),
        )

        obj2 = MalwiObject(
            name="obj2",
            language="python",
            file_path=str(test_file),
            file_source_code="exec('test2')",
            location=(2, 2),
        )

        # Mock user selecting "Suspicious" for first, "Benign" for second
        mock_questionary_select.return_value.ask.side_effect = [
            "Suspicious (keep as malicious)",
            "Benign (false positive)",
        ]

        # Run triage
        result = triage_malicious_objects(test_file, [obj1, obj2], [obj1, obj2])

        # Only first object should be kept as malicious
        assert len(result) == 1
        assert result[0] == obj1

        # File should have second line commented out
        modified_content = test_file.read_text()
        lines = modified_content.split("\n")
        assert lines[0] == "exec('test1')"  # Unchanged (suspicious)
        assert lines[1] == "# exec('test2')"  # Commented out (benign)
        assert lines[2] == "print('normal')"  # Unchanged

    @patch("questionary.select")
    def test_triage_empty_list(self, mock_questionary_select, tmp_path):
        """Test triage with empty list of malicious objects."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('normal')")

        # Run triage with empty list
        result = triage_malicious_objects(test_file, [], [])

        # Should return empty list
        assert len(result) == 0

        # File should not be modified
        assert test_file.read_text() == "print('normal')"

        # questionary should not be called
        mock_questionary_select.assert_not_called()

    @patch("questionary.select")
    def test_triage_module_object_warning(self, mock_questionary_select, tmp_path):
        """Test that module-level objects show warning but can still be triaged."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')\nexec('malicious')")

        # Create module object that spans most of file (would normally cause entire file to be commented)
        module_obj = MalwiObject(
            name="<module>",
            language="python",
            file_path=str(test_file),
            file_source_code="print('test')\nexec('malicious')",
            location=(1, 2),  # Spans entire file
        )
        module_obj.maliciousness = 1.0

        # Mock user selecting "Benign" for the module (this should be handled carefully)
        mock_questionary_select.return_value.ask.return_value = (
            "Benign (false positive)"
        )

        # Run triage with module object
        result = triage_malicious_objects(test_file, [module_obj], [module_obj])

        # Module should be removed (classified as benign)
        assert len(result) == 0

        # File should be handled appropriately for module objects
        # (Implementation should prevent commenting out entire file)
        modified_content = test_file.read_text()
        # The file should now be commented out since user explicitly marked it as benign
        lines = modified_content.split("\n")
        # Check that all lines are commented out (user's explicit choice)
        non_empty_lines = [line for line in lines if line.strip()]
        commented_lines = [
            line for line in non_empty_lines if line.strip().startswith("#")
        ]
        assert len(commented_lines) == len(non_empty_lines), (
            "All non-empty lines should be commented when user marks module as benign"
        )

    @patch("questionary.select")
    def test_triage_single_module_object_benign_comments_entire_file(
        self, mock_questionary_select, tmp_path
    ):
        """Test the exact scenario from setup.py - single module object marked as benign."""
        test_file = tmp_path / "setup.py"
        test_content = """import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="test-package",
    version="1.0.0",
    author="Test Author",
    description="Test package",
    long_description=long_description,
)"""
        test_file.write_text(test_content)

        # Create module object that spans entire file (exactly like in the user's case)
        module_obj = MalwiObject(
            name="<module>",
            language="python",
            file_path=str(test_file),
            file_source_code=test_content,
            location=(1, len(test_content.split("\n"))),  # Spans entire file
        )
        module_obj.maliciousness = 0.998  # High maliciousness like in the real case

        # Mock user selecting "Benign" for the module
        mock_questionary_select.return_value.ask.return_value = (
            "Benign (false positive)"
        )

        # Run triage with module object
        result = triage_malicious_objects(test_file, [module_obj], [module_obj])

        # Module should be removed (classified as benign)
        assert len(result) == 0

        # File should be commented out since user explicitly marked it as benign
        modified_content = test_file.read_text()
        lines = modified_content.split("\n")

        # Check that non-empty lines are commented
        non_empty_lines = [line for line in lines if line.strip()]
        commented_lines = [
            line for line in non_empty_lines if line.strip().startswith("#")
        ]

        # Should have commented out all the lines since user explicitly chose benign
        assert len(commented_lines) > 0, (
            "Should have commented lines when user marks module as benign"
        )
        assert len(commented_lines) == len(non_empty_lines), (
            f"Expected {len(non_empty_lines)} commented lines, got {len(commented_lines)}"
        )
