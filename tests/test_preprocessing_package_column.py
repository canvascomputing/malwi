import pytest
import tempfile
import csv
from pathlib import Path
from unittest.mock import MagicMock

from research.csv_writer import CSVWriter
from research.preprocess import _process_single_file_with_compiler
from common.malwi_object import MalwiObject
from common.bytecode import ASTCompiler


class TestPreprocessingPackageColumn:
    @pytest.fixture
    def mock_malwi_object(self):
        obj = MalwiObject(
            name="test_function",
            language="python",
            file_path="/test/path/package_name/example.py",
            file_source_code="def test(): pass",
        )

        obj.to_string = MagicMock(return_value="LOAD_CONST test_function")
        obj.to_hash = MagicMock(return_value="abc123def456")

        return obj

    def test_csv_writer_includes_package_column(self, mock_malwi_object):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_file_path = f.name

        try:
            writer = CSVWriter(Path(csv_file_path))
            writer.write_code_objects(
                [mock_malwi_object], label="malicious", package="package_name"
            )
            writer.close()

            with open(csv_file_path, "r", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)

            assert len(rows) == 2

            expected_header = [
                "tokens",
                "hash",
                "language",
                "filepath",
                "label",
                "package",
            ]
            assert rows[0] == expected_header

            data_row = rows[1]
            assert data_row[0] == "LOAD_CONST test_function"
            assert data_row[1] == "abc123def456"
            assert data_row[2] == "python"
            assert data_row[3] == "/test/path/package_name/example.py"
            assert data_row[4] == "malicious"
            assert data_row[5] == "package_name"

        finally:
            Path(csv_file_path).unlink()

    def test_csv_writer_package_empty_when_not_provided(self, mock_malwi_object):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_file_path = f.name

        try:
            writer = CSVWriter(Path(csv_file_path))
            writer.write_code_objects([mock_malwi_object], label="benign")
            writer.close()

            with open(csv_file_path, "r", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)

            assert len(rows) == 2
            data_row = rows[1]
            assert data_row[5] == ""

        finally:
            Path(csv_file_path).unlink()

    def test_process_file_includes_package_name(self):
        test_code = """
def test_function():
    return 42
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            temp_file_path = f.name

        try:
            compiler = ASTCompiler("python")
            result = _process_single_file_with_compiler(
                Path(temp_file_path),
                compiler,
                label="malicious",
                package_name="test_package",
            )

            assert result["success"] is True
            assert len(result["code_objects"]) > 0

            for obj_data in result["code_objects"]:
                assert "package" in obj_data
                assert obj_data["package"] == "test_package"
                assert obj_data["label"] == "malicious"

        finally:
            Path(temp_file_path).unlink()

    def test_process_file_package_empty_when_none(self):
        test_code = """
def simple_function():
    x = 1
    return x
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            temp_file_path = f.name

        try:
            compiler = ASTCompiler("python")
            result = _process_single_file_with_compiler(
                Path(temp_file_path), compiler, package_name=None
            )

            assert result["success"] is True

            for obj_data in result["code_objects"]:
                assert "package" in obj_data
                assert obj_data["package"] == ""

        finally:
            Path(temp_file_path).unlink()

    def test_csv_writer_multiple_packages(self):
        objects_data = [
            ("package_a", "func_a", "/path/package_a/file1.py"),
            ("package_a", "func_b", "/path/package_a/file2.py"),
            ("package_b", "func_c", "/path/package_b/file1.py"),
        ]

        objects = []
        for package, func_name, filepath in objects_data:
            obj = MalwiObject(
                name=func_name,
                language="python",
                file_path=filepath,
                file_source_code=f"def {func_name}(): pass",
            )
            obj.to_string = MagicMock(return_value=f"LOAD_CONST {func_name}")
            obj.to_hash = MagicMock(return_value=f"hash_{func_name}")
            objects.append((obj, package))

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_file_path = f.name

        try:
            writer = CSVWriter(Path(csv_file_path))
            for obj, package in objects:
                writer.write_code_objects([obj], label="malicious", package=package)
            writer.close()

            with open(csv_file_path, "r", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)

            assert len(rows) == 4

            assert rows[1][5] == "package_a"
            assert rows[2][5] == "package_a"
            assert rows[3][5] == "package_b"

        finally:
            Path(csv_file_path).unlink()

    def test_header_consistency_across_writes(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_file_path = f.name

        try:
            obj = MalwiObject(
                name="test",
                language="python",
                file_path="/test.py",
                file_source_code="pass",
            )
            obj.to_string = MagicMock(return_value="LOAD_CONST test")
            obj.to_hash = MagicMock(return_value="hash123")

            writer = CSVWriter(Path(csv_file_path))
            writer.write_code_objects([obj], package="pkg1")
            writer.close()

            with open(csv_file_path, "r", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)

            expected_header = [
                "tokens",
                "hash",
                "language",
                "filepath",
                "label",
                "package",
            ]
            assert rows[0] == expected_header

            assert len(rows) == 2
            assert rows[1][5] == "pkg1"

        finally:
            Path(csv_file_path).unlink()
