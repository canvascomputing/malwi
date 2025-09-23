"""Test suite for code extraction functionality."""

import pytest
import tempfile
from pathlib import Path

# Add src to path to import from source
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from common.malwi_object import MalwiObject
from common.malwi_report import MalwiReport
from common.bytecode import ASTCompiler


class TestCodeExtraction:
    """Test code extraction functionality for functions, classes, and lambdas."""

    def test_function_header_extraction_python(self):
        """Test that Python function headers are properly extracted."""
        test_code = """import os

def simple_function():
    print("hello")

def function_with_params(name, age=25):
    return f"Hello {name}, age {age}"

async def async_function(data):
    await process(data)
    return data

def generator_function():
    yield 1
    yield 2
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            f.flush()

            try:
                # Create AST compiler and process the file
                compiler = ASTCompiler("python")
                code_objects = compiler.process_file(Path(f.name))

                # Find function objects (exclude <module>)
                function_objects = [
                    obj for obj in code_objects if obj.name != "<module>"
                ]

                # Verify we found the expected functions
                expected_functions = [
                    "simple_function",
                    "function_with_params",
                    "async_function",
                    "generator_function",
                ]
                found_functions = [obj.name for obj in function_objects]

                for expected in expected_functions:
                    assert expected in found_functions, (
                        f"Expected function '{expected}' not found"
                    )

                # Test that function headers are included in source code
                for obj in function_objects:
                    assert obj.source_code is not None, (
                        f"Source code missing for {obj.name}"
                    )

                    if obj.name == "simple_function":
                        assert "def simple_function():" in obj.source_code
                        assert 'print("hello")' in obj.source_code

                    elif obj.name == "function_with_params":
                        assert (
                            "def function_with_params(name, age=25):" in obj.source_code
                        )
                        assert 'return f"Hello {name}, age {age}"' in obj.source_code

                    elif obj.name == "async_function":
                        assert "async def async_function(data):" in obj.source_code
                        assert "await process(data)" in obj.source_code

                    elif obj.name == "generator_function":
                        assert "def generator_function():" in obj.source_code
                        assert "yield 1" in obj.source_code
                        assert "yield 2" in obj.source_code

            finally:
                os.unlink(f.name)

    def test_class_header_extraction_python(self):
        """Test that Python class headers are properly extracted."""
        test_code = """class SimpleClass:
    def method(self):
        pass

class InheritedClass(SimpleClass):
    def __init__(self, name):
        self.name = name
        super().__init__()
    
    def get_name(self):
        return self.name

class ClassWithMultipleInheritance(SimpleClass, object):
    pass
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            f.flush()

            try:
                # Create AST compiler and process the file
                compiler = ASTCompiler("python")
                code_objects = compiler.process_file(Path(f.name))

                # Find class objects (exclude <module> and methods)
                class_objects = [
                    obj
                    for obj in code_objects
                    if obj.name
                    in ["SimpleClass", "InheritedClass", "ClassWithMultipleInheritance"]
                ]

                # Verify we found the expected classes
                expected_classes = [
                    "SimpleClass",
                    "InheritedClass",
                    "ClassWithMultipleInheritance",
                ]
                found_classes = [obj.name for obj in class_objects]

                for expected in expected_classes:
                    assert expected in found_classes, (
                        f"Expected class '{expected}' not found"
                    )

                # Test that class headers are included in source code
                for obj in class_objects:
                    assert obj.source_code is not None, (
                        f"Source code missing for {obj.name}"
                    )

                    if obj.name == "SimpleClass":
                        assert "class SimpleClass:" in obj.source_code
                        assert "def method(self):" in obj.source_code

                    elif obj.name == "InheritedClass":
                        assert "class InheritedClass(SimpleClass):" in obj.source_code
                        assert "def __init__(self, name):" in obj.source_code
                        assert "def get_name(self):" in obj.source_code

                    elif obj.name == "ClassWithMultipleInheritance":
                        assert (
                            "class ClassWithMultipleInheritance(SimpleClass, object):"
                            in obj.source_code
                        )

            finally:
                os.unlink(f.name)

    def test_lambda_extraction_python(self):
        """Test that Python lambda definitions are properly extracted."""
        test_code = """# Simple lambda
add = lambda x, y: x + y

# Lambda with default parameter
greet = lambda name="World": f"Hello {name}"

# Lambda in a function call
numbers = [1, 2, 3, 4, 5]
squared = list(map(lambda x: x**2, numbers))

# Lambda with complex logic
process = lambda data: data.strip().upper() if data else "EMPTY"
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            f.flush()

            try:
                # Create AST compiler and process the file
                compiler = ASTCompiler("python")
                code_objects = compiler.process_file(Path(f.name))

                # Find lambda objects
                lambda_objects = [obj for obj in code_objects if obj.name == "lambda"]

                # We should have lambda objects
                assert len(lambda_objects) > 0, "No lambda objects found"

                # Test that lambda definitions are included in source code
                for obj in lambda_objects:
                    assert obj.source_code is not None, (
                        f"Source code missing for lambda"
                    )
                    assert "lambda" in obj.source_code, (
                        f"Lambda keyword missing in source: {obj.source_code}"
                    )

            finally:
                os.unlink(f.name)

    def test_javascript_function_extraction(self):
        """Test that JavaScript function headers are properly extracted."""
        test_code = """function regularFunction() {
    console.log("hello");
}

function functionWithParams(name, age = 25) {
    return `Hello ${name}, age ${age}`;
}

async function asyncFunction(data) {
    await process(data);
    return data;
}

function* generatorFunction() {
    yield 1;
    yield 2;
}

// Arrow function
const arrowFunc = (x, y) => {
    return x + y;
};
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(test_code)
            f.flush()

            try:
                # Create AST compiler and process the file
                compiler = ASTCompiler("javascript")
                code_objects = compiler.process_file(Path(f.name))

                # Find function objects (exclude <module>)
                function_objects = [
                    obj for obj in code_objects if obj.name != "<module>"
                ]

                # Verify we found functions
                assert len(function_objects) > 0, "No function objects found"

                # Test that function headers are included in source code
                for obj in function_objects:
                    assert obj.source_code is not None, (
                        f"Source code missing for {obj.name}"
                    )

                    if obj.name == "regularFunction":
                        assert "function regularFunction()" in obj.source_code
                        assert 'console.log("hello");' in obj.source_code

                    elif obj.name == "functionWithParams":
                        assert (
                            "function functionWithParams(name, age = 25)"
                            in obj.source_code
                        )

                    elif obj.name == "asyncFunction":
                        assert "async function asyncFunction(data)" in obj.source_code
                        assert "await process(data);" in obj.source_code

                    elif obj.name == "generatorFunction":
                        assert "function* generatorFunction()" in obj.source_code
                        assert "yield 1;" in obj.source_code

            finally:
                os.unlink(f.name)

    def test_code_format_output(self):
        """Test the complete code format output functionality."""
        # Create test files with malicious-like content to trigger detection
        test_python_code = """import subprocess
import os

def malicious_function():
    subprocess.run("rm -rf /", shell=True)
    os.system("evil command")
    
class MaliciousClass:
    def execute_payload(self):
        exec("dangerous code")
"""

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create test files
            py_file = tmpdir_path / "test.py"
            py_file.write_text(test_python_code)

            # Create report with very low threshold to catch everything
            report = MalwiReport.create(
                input_path=tmpdir_path,
                accepted_extensions=["py"],
                silent=True,
                malicious_threshold=0.001,  # Very low threshold to catch all objects
            )

            # Manually create some malicious objects for testing if none detected
            if not report.labelled_objects and report.all_objects:
                # Take any object and mark it as malicious for testing
                test_obj = report.all_objects[0]
                test_obj.labels = {"malicious": 0.9}  # High maliciousness score
                report.labelled_objects = [test_obj]

            # Generate code format output
            code_output = report.to_code_text()

            # Code format now shows ALL objects, not just malicious ones
            # Should have extension headers
            assert "Files with extension: .py" in code_output

            # Should have file path comments
            assert "# File:" in code_output
            assert "# Object:" in code_output

            # Should have maliciousness score
            assert "# Labels:" in code_output

            # Should have embedding count information
            assert "# Embedding count:" in code_output
            assert "tokens" in code_output

            # Check that function headers are included in the output if functions exist
            for obj in report.all_objects:
                if "malicious_function" in obj.name:
                    assert "def malicious_function():" in code_output

                if "MaliciousClass" in obj.name:
                    assert "class MaliciousClass:" in code_output

    def test_empty_code_format_output(self):
        """Test code format output when no malicious objects are found."""
        test_code = """print("hello world")
def safe_function():
    return "safe"
"""

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            py_file = tmpdir_path / "safe.py"
            py_file.write_text(test_code)

            # Create report with default threshold (should not detect this as malicious)
            report = MalwiReport.create(
                input_path=tmpdir_path,
                accepted_extensions=["py"],
                silent=True,
                malicious_threshold=0.7,  # Default threshold
            )

            # Generate code format output
            code_output = report.to_code_text()

            # Code format now shows ALL objects, not just malicious ones
            # Should contain the safe function even if it's not malicious
            assert "safe_function" in code_output
            assert "# Labels:" in code_output
            assert "# File:" in code_output

    def test_source_code_population_method(self):
        """Test source code population from AST CodeObject on MalwiObject."""
        test_code = '''import subprocess

def malicious_function(param1, param2="default"):
    """A test function with docstring."""
    subprocess.run("evil command", shell=True)
    return "malicious"

class MaliciousClass:
    """A test class."""
    def __init__(self):
        self.value = 42
        
    def method(self):
        import os
        os.system("rm -rf /")
        return self.value * 2
'''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            f.flush()

            try:
                # Create a MalwiReport to get MalwiObjects
                report = MalwiReport.create(
                    input_path=Path(f.name),
                    accepted_extensions=["py"],
                    silent=True,
                    malicious_threshold=0.001,  # Very low threshold to catch everything
                )

                # Test source code population for each MalwiObject
                for obj in report.all_objects:
                    # Code is now available via merged source_code property
                    # Verify source code is available
                    assert obj.source_code is not None

                    obj_code = obj.source_code

                    # Test specific objects
                    if obj.name == "malicious_function":
                        assert (
                            'def malicious_function(param1, param2="default"):'
                            in obj_code
                        )
                        assert '"""A test function with docstring."""' in obj_code
                        assert "subprocess.run(" in obj_code

                    elif obj.name == "MaliciousClass":
                        assert "class MaliciousClass:" in obj_code
                        assert '"""A test class."""' in obj_code
                        assert "def __init__(self):" in obj_code
                        assert "def method(self):" in obj_code

            finally:
                os.unlink(f.name)

    def test_nested_functions_and_classes(self):
        """Test extraction of nested functions and classes."""
        test_code = """def outer_function():
    def inner_function():
        return "inner"
    
    class InnerClass:
        def inner_method(self):
            return "method"
    
    return inner_function()

class OuterClass:
    class NestedClass:
        def nested_method(self):
            return "nested"
    
    def outer_method(self):
        def local_function():
            return "local"
        return local_function()
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            f.flush()

            try:
                # Create AST compiler and process the file
                compiler = ASTCompiler("python")
                code_objects = compiler.process_file(Path(f.name))

                # Find top-level objects (nesting_depth == 0)
                top_level_objects = [
                    obj
                    for obj in code_objects
                    if obj.name in ["outer_function", "OuterClass"]
                ]

                # Verify we found the top-level objects
                assert len(top_level_objects) >= 2, (
                    "Should find at least outer_function and OuterClass"
                )

                # Test that headers are included
                for obj in top_level_objects:
                    assert obj.source_code is not None

                    if obj.name == "outer_function":
                        assert "def outer_function():" in obj.source_code
                        # Should include nested content
                        assert "def inner_function():" in obj.source_code
                        assert "class InnerClass:" in obj.source_code

                    elif obj.name == "OuterClass":
                        assert "class OuterClass:" in obj.source_code
                        # Should include nested content
                        assert "class NestedClass:" in obj.source_code
                        assert "def outer_method(self):" in obj.source_code

            finally:
                os.unlink(f.name)

    def test_embedding_count_functionality(self):
        """Test the embedding_count attribute on CodeObject and MalwiObject."""
        test_code = """import subprocess
import os

def simple_function():
    print("hello")

def complex_function():
    subprocess.run("command", shell=True)
    os.system("another command")
    for i in range(100):
        print(f"iteration {i}")
        if i % 10 == 0:
            os.listdir("/")
    return "done"

class TestClass:
    def __init__(self):
        self.value = 42
        
    def method_with_lots_of_code(self):
        # This method has more complex bytecode
        data = []
        for i in range(50):
            data.append(i * 2)
            if i % 5 == 0:
                subprocess.call(["ls", "-la"])
        return sum(data)
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            f.flush()

            try:
                # Test CodeObject embedding_count by mocking the tokenizer
                from unittest.mock import patch, MagicMock

                # Create a mock tokenizer that returns predictable results
                mock_tokenizer = MagicMock()
                mock_encoded = MagicMock()
                mock_encoded.__getitem__.return_value.shape = [1, 25]  # Mock 25 tokens
                mock_tokenizer.return_value = mock_encoded

                with patch(
                    "common.predict_distilbert.get_thread_tokenizer",
                    return_value=mock_tokenizer,
                ):
                    # Test CodeObject embedding_count
                    compiler = ASTCompiler("python")
                    code_objects = compiler.process_file(Path(f.name))

                    for obj in code_objects:
                        # Verify embedding_count property exists and returns a positive integer
                        assert hasattr(obj, "embedding_count"), (
                            f"CodeObject {obj.name} missing embedding_count"
                        )
                        count = obj.embedding_count
                        assert isinstance(count, int), (
                            f"embedding_count should be int, got {type(count)}"
                        )
                        assert count > 0, (
                            f"embedding_count should be positive, got {count}"
                        )

                        # Verify that calling it again returns the same value (cached)
                        count2 = obj.embedding_count
                        assert count == count2, "embedding_count should be cached"

                        # With our mock, all should return 25 tokens
                        assert count == 25, f"Mock should return 25 tokens, got {count}"

                    # Test MalwiObject embedding_count
                    report = MalwiReport.create(
                        input_path=Path(f.name),
                        accepted_extensions=["py"],
                        silent=True,
                        malicious_threshold=0.7,
                    )

                    for obj in report.all_objects:
                        # Verify MalwiObject has embedding_count property
                        assert hasattr(obj, "embedding_count"), (
                            f"MalwiObject {obj.name} missing embedding_count"
                        )
                        count = obj.embedding_count
                        assert isinstance(count, int), (
                            f"embedding_count should be int, got {type(count)}"
                        )
                        assert count > 0, (
                            f"embedding_count should be positive, got {count}"
                        )

                        # Verify embedding_count is included in dictionary representation
                        obj_dict = obj.to_dict()
                        assert "embedding_count" in obj_dict["contents"][0], (
                            "embedding_count missing from to_dict()"
                        )
                        dict_count = obj_dict["contents"][0]["embedding_count"]
                        assert dict_count == count, (
                            "embedding_count in dict should match property"
                        )

            finally:
                os.unlink(f.name)

    def test_embedding_count_window_detection(self):
        """Test that embedding_count can detect potential DistilBERT window overflow."""
        # Create code that should exceed the typical 512 token window
        large_function_code = (
            """def large_function():
    # This function has many operations to create a large bytecode
"""
            + "\n".join(
                [
                    f'    operation_{i} = subprocess.run("command_{i}", shell=True)'
                    for i in range(100)
                ]
            )
            + """
    return "done"
"""
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(large_function_code)
            f.flush()

            try:
                from unittest.mock import patch, MagicMock

                # Create a mock tokenizer that returns a large token count to simulate overflow
                mock_tokenizer = MagicMock()
                mock_encoded = MagicMock()
                mock_encoded.__getitem__.return_value.shape = [
                    1,
                    600,
                ]  # Mock 600 tokens (>512)
                mock_tokenizer.return_value = mock_encoded

                with patch(
                    "common.predict_distilbert.get_thread_tokenizer",
                    return_value=mock_tokenizer,
                ):
                    compiler = ASTCompiler("python")
                    code_objects = compiler.process_file(Path(f.name))

                    # Find the large function
                    large_function = None
                    for obj in code_objects:
                        if obj.name == "large_function":
                            large_function = obj
                            break

                    assert large_function is not None, "large_function not found"

                    # Check if it would exceed DistilBERT's window
                    embedding_count = large_function.embedding_count
                    distilbert_max_length = 512  # Standard DistilBERT max length

                    # With our mock, should exceed the window
                    assert embedding_count > distilbert_max_length, (
                        f"Large function should exceed window, got {embedding_count}"
                    )
                    print(
                        f"✅ Large function ({embedding_count} tokens) would trigger windowing"
                    )

            finally:
                os.unlink(f.name)

    def test_embedding_count_without_ast_object(self):
        """Test embedding_count behavior when no bytecode is available."""
        # Create a MalwiObject without bytecode
        malwi_obj = MalwiObject(
            name="test_object",
            language="python",
            file_path="/test/path.py",
            file_source_code="print('test')",
            byte_code=None,  # No bytecode
            source_code=None,  # No source code
        )

        # Should return 0 when no bytecode is available
        count = malwi_obj.embedding_count
        assert count == 0, f"Should return 0 when no bytecode, got {count}"
