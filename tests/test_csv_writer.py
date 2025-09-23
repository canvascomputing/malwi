"""Test the CSV writer functionality (regression test for 'path' attribute issue)."""

import pytest
import tempfile
import csv
from pathlib import Path
from unittest.mock import MagicMock

from research.csv_writer import CSVWriter
from common.malwi_object import MalwiObject


class TestCSVWriter:
    """Test suite for CSVWriter class."""

    @pytest.fixture
    def mock_malwi_object(self):
        """Create a mock MalwiObject for testing."""
        obj = MalwiObject(
            name="test_function",
            language="python",
            file_path="/test/path/example.py",
            file_source_code="def test(): pass",
        )

        # Mock the methods that CSVWriter uses
        obj.to_string = MagicMock(return_value="LOAD_CONST test_function")
        obj.to_hash = MagicMock(return_value="abc123def456")

        return obj

    def test_csv_writer_basic_functionality(self, mock_malwi_object):
        """Test basic CSV writing functionality."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_file_path = f.name

        try:
            # Create CSVWriter and write data
            writer = CSVWriter(Path(csv_file_path))
            writer.write_code_objects([mock_malwi_object])
            writer.close()

            # Read back the CSV and verify contents
            with open(csv_file_path, "r", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)

            assert len(rows) == 2  # Header + 1 data row

            # Check header
            expected_header = ["tokens", "hash", "language", "filepath", "label"]
            assert rows[0] == expected_header

            # Check data row
            data_row = rows[1]
            assert data_row[0] == "LOAD_CONST test_function"  # tokens
            assert data_row[1] == "abc123def456"  # hash
            assert data_row[2] == "python"  # language
            assert (
                data_row[3] == "/test/path/example.py"
            )  # filepath (was obj.path before fix)
            assert data_row[4] == ""  # label (empty when not provided)

        finally:
            # Clean up
            Path(csv_file_path).unlink()

    def test_csv_writer_file_path_attribute_access(self, mock_malwi_object):
        """Regression test: ensure CSVWriter accesses file_path (not path) attribute."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_file_path = f.name

        try:
            # This test specifically checks that the CSVWriter doesn't try to access obj.path
            writer = CSVWriter(Path(csv_file_path))

            # Ensure the object doesn't have a 'path' attribute (it should use 'file_path')
            assert hasattr(mock_malwi_object, "file_path")
            assert not hasattr(mock_malwi_object, "path")

            # This should not raise an AttributeError
            writer.write_code_objects([mock_malwi_object])
            writer.close()

            # Verify the file was written successfully
            with open(csv_file_path, "r", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)

            assert len(rows) == 2  # Header + data row
            assert (
                rows[1][3] == "/test/path/example.py"
            )  # filepath should be correctly written

        except AttributeError as e:
            pytest.fail(f"CSVWriter tried to access missing 'path' attribute: {e}")
        finally:
            # Clean up
            Path(csv_file_path).unlink()

    def test_csv_writer_multiple_objects(self):
        """Test CSV writer with multiple MalwiObjects (regression test for path attribute)."""
        # Create multiple objects to test batch processing
        objects = []

        for i in range(3):
            obj = MalwiObject(
                name=f"test_function_{i}",
                language="python",
                file_path=f"/app/module_{i}.py",
                file_source_code=f"def test_{i}(): pass",
            )
            obj.to_string = MagicMock(return_value=f"LOAD_CONST test_function_{i}")
            obj.to_hash = MagicMock(return_value=f"hash{i}")
            objects.append(obj)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_file_path = f.name

        try:
            # Write all objects - this was failing with AttributeError before fix
            writer = CSVWriter(Path(csv_file_path))
            writer.write_code_objects(objects)
            writer.close()

            # Read and verify
            with open(csv_file_path, "r", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)

            assert len(rows) == 4  # Header + 3 data rows

            # Verify each row has the correct file_path (was obj.path before)
            for i in range(3):
                assert rows[i + 1][3] == f"/app/module_{i}.py"
                assert rows[i + 1][0] == f"LOAD_CONST test_function_{i}"
                assert rows[i + 1][1] == f"hash{i}"
                assert rows[i + 1][2] == "python"

        finally:
            Path(csv_file_path).unlink()

    def test_csv_writer_manual_close(self, mock_malwi_object):
        """Test CSVWriter with manual close."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_file_path = f.name

        try:
            # Test manual close
            writer = CSVWriter(Path(csv_file_path))
            writer.write_code_objects([mock_malwi_object])
            writer.close()

            # Verify file was written and closed properly
            with open(csv_file_path, "r", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)

            assert len(rows) == 2
            assert rows[1][3] == "/test/path/example.py"

        finally:
            Path(csv_file_path).unlink()

    def test_csv_writer_empty_list(self):
        """Test CSV writer with empty list of objects."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_file_path = f.name

        try:
            writer = CSVWriter(Path(csv_file_path))
            writer.write_code_objects([])  # Empty list
            writer.close()

            # Should still have header
            with open(csv_file_path, "r", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)

            assert len(rows) == 1  # Only header
            assert rows[0] == ["tokens", "hash", "language", "filepath", "label"]

        finally:
            Path(csv_file_path).unlink()
