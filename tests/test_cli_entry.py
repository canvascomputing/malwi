import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import os

# Add src to path to import from source
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cli.entry import main
from cli.scan import process_batch_mode, run_batch_scan


class TestCLIEntry:
    """Minimal tests for CLI entry point"""

    def test_help_message(self, capsys):
        """Test that help message displays properly"""
        with patch.object(sys, "argv", ["malwi", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "malwi - AI Python Malware Scanner" in captured.out
        assert "scan" in captured.out  # Check for scan subcommand
        assert "pypi" in captured.out  # Check for pypi subcommand

    def test_no_arguments_shows_error(self, capsys):
        """Test that running without arguments shows help"""
        with patch.object(sys, "argv", ["malwi"]):
            # Should show help and exit normally (not with error)
            result = main()
            assert result is None
        captured = capsys.readouterr()
        # Should show help output (not error since we just display help)

    def test_invalid_path_logs_error(self):
        """Test that invalid path logs error and exits"""
        with patch.object(sys, "argv", ["malwi", "scan", "/non/existent/path"]):
            # The function logs error and returns without exception
            result = main()
            assert result is None

    @patch("cli.scan.Path")
    @patch("cli.scan.MalwiReport.create")
    def test_basic_cli_flow(self, mock_create, mock_path, tmp_path):
        """Test basic CLI flow with all necessary mocks"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        # Mock Path to return our test file
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Mock the report
        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = "Demo output"
        mock_create.return_value = mock_report

        with patch.object(sys, "argv", ["malwi", "scan", str(test_file)]):
            with patch("cli.scan.result") as mock_result:
                main()
                mock_result.assert_called_with("Demo output", force=True)

    @patch("cli.scan.MalwiReport.create")
    def test_save_to_file(self, mock_create, tmp_path):
        """Test saving output to file"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        output_file = tmp_path / "output.txt"

        # Mock report
        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = "Saved content"
        mock_create.return_value = mock_report

        # Mock the path existence check for input file
        with patch("cli.scan.Path") as mock_path:

            def path_side_effect(path_str):
                if str(path_str) == str(test_file):
                    mock_input_path = MagicMock()
                    mock_input_path.exists.return_value = True
                    return mock_input_path
                else:
                    # For save path, return real Path so file actually gets created
                    return Path(path_str)

            mock_path.side_effect = path_side_effect

            with patch.object(
                sys,
                "argv",
                [
                    "malwi",
                    "scan",
                    str(test_file),
                    "--save",
                    str(output_file),
                    "--quiet",
                ],
            ):
                main()

        assert output_file.exists()
        assert output_file.read_text() == "Saved content"

    @patch("cli.scan.Path")
    @patch("cli.scan.MalwiReport.create")
    def test_output_formats(self, mock_create, mock_path, tmp_path):
        """Test different output format options"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        # Mock Path
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Mock report with all format methods
        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = "Demo"
        mock_report.to_markdown.return_value = "Markdown"
        mock_report.to_json.return_value = "JSON"
        mock_report.to_yaml.return_value = "YAML"
        mock_report.to_code_text.return_value = (
            "Code/Tokens"  # Used for both code and tokens formats
        )
        mock_create.return_value = mock_report

        # Test each format
        for fmt, expected_output in [
            ("demo", "Demo"),
            ("markdown", "Markdown"),
            ("json", "JSON"),
            ("yaml", "YAML"),
            ("tokens", "Code/Tokens"),  # tokens format now uses to_code_text
            ("code", "Code/Tokens"),  # code format also uses to_code_text
        ]:
            with patch.object(
                sys,
                "argv",
                ["malwi", "scan", str(test_file), "--format", fmt, "--quiet"],
            ):
                with patch("cli.scan.result") as mock_result:
                    main()
                    mock_result.assert_called_with(expected_output, force=True)

    @patch("cli.scan.Path")
    def test_model_loading_error_continues(self, mock_path, tmp_path):
        """Test that model loading errors are handled gracefully"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        # Mock Path
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Make model loading fail

        with patch.object(sys, "argv", ["malwi", "scan", str(test_file)]):
            with patch("cli.scan.MalwiReport.create") as mock_process:
                mock_report = MagicMock()
                mock_report.to_demo_text.return_value = "Output"
                mock_process.return_value = mock_report

                with patch("cli.scan.result"):
                    # Should not crash
                    main()

    @patch("cli.scan.Path")
    @patch("cli.scan.MalwiReport.create")
    def test_cli_parameters_passed_correctly(self, mock_create, mock_path, tmp_path):
        """Test that CLI parameters are passed correctly to MalwiReport.create"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        # Mock Path
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = test_file
        mock_path.side_effect = lambda x: (
            test_file if str(x) == str(test_file) else mock_path_instance
        )

        # Mock report
        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = ""
        mock_create.return_value = mock_report

        # Test with various parameters
        with patch.object(
            sys,
            "argv",
            [
                "malwi",
                "scan",
                str(test_file),
                "--threshold",
                "0.9",
                "--extensions",
                "py",
                "pyw",
                "--quiet",
            ],
        ):
            with patch("cli.scan.result"):
                main()

        # Verify MalwiReport.create was called with correct arguments
        mock_create.assert_called_once()
        call_args = mock_create.call_args[1]
        assert call_args["malicious_threshold"] == 0.9
        assert call_args["accepted_extensions"] == ["py", "pyw"]
        assert call_args["silent"]


class TestBatchMode:
    """Tests for batch processing functionality"""

    def test_batch_and_save_mutually_exclusive(self, capsys):
        """Test that --batch and --save flags are mutually exclusive"""
        with patch.object(
            sys,
            "argv",
            ["malwi", "scan", "/some/path", "--batch", "--save", "test.json"],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "not allowed with argument --batch" in captured.err

    def test_batch_mode_requires_directory(self, tmp_path):
        """Test that batch mode requires a directory path"""
        # Create a file instead of directory
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        # Create mock args
        args = MagicMock()
        args.format = "json"
        args.threshold = 0.7
        args.extensions = ["py"]
        args.quiet = True
        args.model_path = None
        args.tokenizer_path = None
        args.triage = False
        args.triage_mcp = False

        with patch("cli.scan.path_error") as mock_path_error:
            process_batch_mode(test_file, args)
            mock_path_error.assert_called_once_with(
                "Batch mode requires a directory path"
            )

    def test_batch_mode_no_child_directories(self, tmp_path):
        """Test batch mode when no child directories exist"""
        # Create a directory with only files, no subdirectories
        (tmp_path / "file1.py").write_text("print('hello')")
        (tmp_path / "file2.py").write_text("print('world')")

        args = MagicMock()

        with patch("cli.scan.info") as mock_info:
            process_batch_mode(tmp_path, args)
            mock_info.assert_called_with(
                "No child directories found for batch processing"
            )

    @patch("cli.scan.tqdm")
    @patch("cli.scan.ThreadPoolExecutor")
    @patch("cli.scan.run_batch_scan")
    def test_process_batch_mode_success(
        self, mock_run_batch_scan, mock_executor, mock_tqdm, tmp_path
    ):
        """Test successful batch processing"""
        # Create test directory structure
        (tmp_path / "folder1").mkdir()
        (tmp_path / "folder2").mkdir()
        (tmp_path / "folder3").mkdir()

        # Create args mock
        args = MagicMock()
        args.format = "json"
        args.quiet = False

        # Mock tqdm progress bar
        mock_pbar = MagicMock()
        mock_tqdm.return_value.__enter__.return_value = mock_pbar

        # Mock executor and futures
        mock_executor_instance = MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance

        # Mock futures and results
        mock_future1 = MagicMock()
        mock_future2 = MagicMock()
        mock_future3 = MagicMock()

        mock_future1.result.return_value = {
            "folder": "folder1",
            "success": True,
            "skipped": False,
        }
        mock_future2.result.return_value = {
            "folder": "folder2",
            "success": True,
            "skipped": False,
        }
        mock_future3.result.return_value = {
            "folder": "folder3",
            "success": False,
            "error": "error message",
            "skipped": False,
        }

        # Futures will be submitted in order

        mock_executor_instance.submit.side_effect = [
            mock_future1,
            mock_future2,
            mock_future3,
        ]

        with patch("cli.scan.as_completed") as mock_as_completed:
            mock_as_completed.return_value = [mock_future1, mock_future2, mock_future3]

            with patch("cli.scan.info") as mock_info:
                process_batch_mode(tmp_path, args)

                # Verify model loading was called

                # Verify info calls
                mock_info.assert_any_call("🚀 Starting batch scan of 3 folders")
                mock_info.assert_any_call(
                    "🎯 Batch scan complete: 2 successful, 1 failed, 0 skipped"
                )

                # Verify tqdm progress bar was used (includes disable parameter)
                mock_tqdm.assert_called_once_with(
                    total=3, desc="📈 Scanning folders", unit="folder", disable=False
                )

                # Verify progress bar updates
                assert mock_pbar.update.call_count == 3
                mock_pbar.set_postfix_str.assert_any_call("✅ folder1")
                mock_pbar.set_postfix_str.assert_any_call("✅ folder2")
                mock_pbar.set_postfix_str.assert_any_call("❌ folder3")

    def test_run_batch_scan_success(self, tmp_path):
        """Test successful single folder batch scan"""
        test_folder = tmp_path / "test_folder"
        test_folder.mkdir()

        # Create args mock
        args = MagicMock()
        args.format = "json"
        args.threshold = 0.7
        args.extensions = ["py"]
        args.quiet = True
        args.model_path = None
        args.tokenizer_path = None
        args.triage = False
        args.triage_mcp = False

        # Mock the process_files function and report
        mock_report = MagicMock()
        mock_report.to_json.return_value = '{"test": "data"}'

        with patch(
            "cli.scan.MalwiReport.create", return_value=mock_report
        ) as mock_process:
            with patch("cli.scan.Path.cwd", return_value=tmp_path):
                result = run_batch_scan(test_folder, args)

                # Verify MalwiReport.create was called with correct arguments
                mock_process.assert_called_once_with(
                    input_path=test_folder,
                    accepted_extensions=["py"],
                    silent=True,
                    malicious_threshold=0.7,
                    triage=args.triage,
                    triage_provider=None,
                )

                # Verify result
                assert result["folder"] == "test_folder"
                assert result["success"] is True
                assert result["skipped"] is False

                # Verify file was created
                output_file = tmp_path / "malwi_test_folder.json"
                assert output_file.exists()
                assert output_file.read_text() == '{"test": "data"}'

    def test_run_batch_scan_exception(self, tmp_path):
        """Test batch scan with general exception"""
        test_folder = tmp_path / "test_folder"
        test_folder.mkdir()

        args = MagicMock()
        args.format = "json"
        args.threshold = 0.7
        args.extensions = ["py"]
        args.quiet = True
        args.model_path = None
        args.tokenizer_path = None
        args.triage = False
        args.triage_mcp = False

        # Mock MalwiReport.create to raise exception
        with patch("cli.scan.MalwiReport.create", side_effect=Exception("Test error")):
            with patch("cli.scan.Path.cwd", return_value=tmp_path):
                result = run_batch_scan(test_folder, args)

                assert result["folder"] == "test_folder"
                assert result["success"] is False
                assert result["error"] == "Test error"
                assert result["skipped"] is False

    def test_batch_file_extensions(self, tmp_path):
        """Test that batch mode creates files with correct extensions"""
        test_folder = tmp_path / "test_folder"
        test_folder.mkdir()

        format_extensions = [
            ("json", ".json", "to_json"),
            ("yaml", ".yaml", "to_yaml"),
            ("markdown", ".md", "to_markdown"),
            ("demo", ".txt", "to_demo_text"),
            (
                "tokens",
                ".txt",
                "to_code_text",
            ),  # tokens format now uses to_code_text with include_tokens=True
        ]

        for fmt, expected_ext, method_name in format_extensions:
            args = MagicMock()
            args.format = fmt
            args.threshold = 0.7
            args.extensions = ["py"]
            args.quiet = True
            args.model_path = None
            args.tokenizer_path = None
            args.triage = False
            args.triage_mcp = False

            # Mock report with the appropriate method
            mock_report = MagicMock()
            getattr(mock_report, method_name).return_value = "test output"

            with patch("cli.scan.MalwiReport.create", return_value=mock_report):
                with patch("cli.scan.Path.cwd", return_value=tmp_path):
                    run_batch_scan(test_folder, args)

                    # Check that the file was created with correct extension
                    expected_file = tmp_path / f"malwi_test_folder{expected_ext}"
                    assert expected_file.exists()
                    assert expected_file.read_text() == "test output"

                    # Clean up for next iteration
                    expected_file.unlink()

    @patch("cli.scan.Path")
    def test_batch_mode_integration_with_main(self, mock_path, tmp_path):
        """Test batch mode integration with main function"""
        # Create test directory structure
        test_dir = tmp_path / "batch_test"
        test_dir.mkdir()
        (test_dir / "folder1").mkdir()
        (test_dir / "folder2").mkdir()

        # Mock Path to return our test directory
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.is_dir.return_value = True
        mock_path_instance.iterdir.return_value = [
            test_dir / "folder1",
            test_dir / "folder2",
        ]
        mock_path.return_value = mock_path_instance

        with patch.object(
            sys, "argv", ["malwi", "scan", str(test_dir), "--batch", "--quiet"]
        ):
            with patch("cli.scan.process_batch_mode") as mock_batch_mode:
                main()
                mock_batch_mode.assert_called_once()

                # Verify that process_batch_mode was called with correct args
                call_args = mock_batch_mode.call_args
                assert call_args[0][0] == mock_path_instance  # input_path
                batch_args = call_args[0][1]  # args
                assert batch_args.batch is True
                assert batch_args.quiet is True

    def test_batch_mode_loads_models_in_batch_function(self, tmp_path):
        """Test that batch mode loads models within the batch processing function"""
        test_dir = tmp_path / "batch_test"
        test_dir.mkdir()

        with patch("cli.scan.Path") as mock_path:
            mock_path_instance = MagicMock()
            mock_path_instance.exists.return_value = True
            mock_path.return_value = mock_path_instance

            with patch.object(sys, "argv", ["malwi", "scan", str(test_dir), "--batch"]):
                with patch("cli.scan.process_batch_mode") as mock_batch_mode:
                    main()

                    # Verify that model loading was NOT called in main (skipped for batch mode)

                    # Verify that batch mode was called
                    mock_batch_mode.assert_called_once()

    def test_skip_existing_files(self, tmp_path):
        """Test that existing malwi files are skipped"""
        test_folder = tmp_path / "test_folder"
        test_folder.mkdir()

        # Create existing output file
        existing_file = tmp_path / "malwi_test_folder.json"
        existing_file.write_text('{"existing": "data"}')

        args = MagicMock()
        args.format = "json"
        args.threshold = 0.7
        args.extensions = ["py"]
        args.quiet = True
        args.model_path = None
        args.tokenizer_path = None
        args.triage = False
        args.triage_mcp = False

        with patch("cli.scan.Path.cwd", return_value=tmp_path):
            result = run_batch_scan(test_folder, args)

            # Verify the folder was skipped
            assert result["folder"] == "test_folder"
            assert result["success"] is True
            assert result["skipped"] is True

    @patch("cli.scan.tqdm")
    @patch("cli.scan.ThreadPoolExecutor")
    def test_mixed_skip_and_process(self, mock_executor, mock_tqdm, tmp_path):
        """Test batch mode with mixed skipped and processed folders"""
        # Create test directory structure
        (tmp_path / "folder1").mkdir()  # Will be skipped
        (tmp_path / "folder2").mkdir()  # Will be processed

        # Create existing file for folder1
        (tmp_path / "malwi_folder1.json").write_text('{"existing": "data"}')

        args = MagicMock()
        args.format = "json"
        args.quiet = False

        # Mock tqdm progress bar
        mock_pbar = MagicMock()
        mock_tqdm.return_value.__enter__.return_value = mock_pbar

        # Mock executor
        mock_executor_instance = MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance

        # Mock futures and results
        mock_future1 = MagicMock()
        mock_future2 = MagicMock()

        mock_future1.result.return_value = {
            "folder": "folder1",
            "success": True,
            "skipped": True,
        }
        mock_future2.result.return_value = {
            "folder": "folder2",
            "success": True,
            "skipped": False,
        }

        mock_executor_instance.submit.side_effect = [mock_future1, mock_future2]

        with patch("cli.scan.as_completed") as mock_as_completed:
            mock_as_completed.return_value = [mock_future1, mock_future2]

            with patch("cli.scan.info") as mock_info:
                process_batch_mode(tmp_path, args)

                # Verify summary includes skip count
                mock_info.assert_any_call(
                    "🎯 Batch scan complete: 1 successful, 0 failed, 1 skipped"
                )

                # Verify progress bar postfix shows skip and success
                mock_pbar.set_postfix_str.assert_any_call("⏭️ folder1")
                mock_pbar.set_postfix_str.assert_any_call("✅ folder2")


class TestPyPICommand:
    """Tests for PyPI subcommand functionality"""

    def test_pypi_help_message(self, capsys):
        """Test that PyPI help message displays properly"""
        with patch.object(sys, "argv", ["malwi", "pypi", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "PyPI package name to scan" in captured.out
        assert "--folder" in captured.out
        assert "--format" in captured.out
        assert "--threshold" in captured.out
        assert "--save" in captured.out

    @patch("cli.pypi.scan_pypi_package")
    @patch("cli.scan.MalwiReport.create")
    def test_pypi_basic_scan(self, mock_create, mock_scan_pypi, tmp_path):
        """Test basic PyPI package scanning"""
        # Mock extracted directory
        extracted_dir = tmp_path / "test_package"
        extracted_dir.mkdir()

        # Mock scan_pypi_package return
        mock_scan_pypi.return_value = (tmp_path, [extracted_dir])

        # Mock report
        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = "Demo output"
        mock_create.return_value = mock_report

        with patch.object(sys, "argv", ["malwi", "pypi", "test-package", "--quiet"]):
            with patch("cli.pypi.result") as mock_result:
                main()

                # Verify scan_pypi_package was called
                mock_scan_pypi.assert_called_once_with(
                    "test-package", None, Path("downloads"), show_progress=False
                )

                # Verify MalwiReport.create was called
                mock_create.assert_called_once_with(
                    input_path=extracted_dir,
                    accepted_extensions=[".py"],
                    silent=True,
                    malicious_threshold=0.7,
                    on_finding=None,
                    triage=False,
                    triage_provider=None,
                )

                # Verify result output
                mock_result.assert_called_with("Demo output", force=True)

    @patch("cli.pypi.scan_pypi_package")
    @patch("cli.scan.MalwiReport.create")
    def test_pypi_with_version(self, mock_create, mock_scan_pypi, tmp_path):
        """Test PyPI scanning with specific version"""
        extracted_dir = tmp_path / "package"
        extracted_dir.mkdir()
        mock_scan_pypi.return_value = (tmp_path, [extracted_dir])

        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = "Output"
        mock_create.return_value = mock_report

        with patch.object(
            sys, "argv", ["malwi", "pypi", "requests", "2.31.0", "--quiet"]
        ):
            with patch("cli.pypi.result"):
                main()

                # Verify version was passed
                mock_scan_pypi.assert_called_once_with(
                    "requests", "2.31.0", Path("downloads"), show_progress=False
                )

    @patch("cli.pypi.scan_pypi_package")
    @patch("cli.scan.MalwiReport.create")
    def test_pypi_custom_folder(self, mock_create, mock_scan_pypi, tmp_path):
        """Test PyPI scanning with custom download folder"""
        extracted_dir = tmp_path / "package"
        extracted_dir.mkdir()
        mock_scan_pypi.return_value = (tmp_path, [extracted_dir])

        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = "Output"
        mock_create.return_value = mock_report

        with patch.object(
            sys,
            "argv",
            ["malwi", "pypi", "numpy", "--folder", "custom_folder", "--quiet"],
        ):
            with patch("cli.pypi.result"):
                main()

                # Verify custom folder was used
                mock_scan_pypi.assert_called_once_with(
                    "numpy", None, Path("custom_folder"), show_progress=False
                )

    @patch("cli.pypi.scan_pypi_package")
    @patch("cli.scan.MalwiReport.create")
    def test_pypi_different_formats(self, mock_create, mock_scan_pypi, tmp_path):
        """Test PyPI scanning with different output formats"""
        extracted_dir = tmp_path / "package"
        extracted_dir.mkdir()
        mock_scan_pypi.return_value = (tmp_path, [extracted_dir])

        # Test different formats
        formats_to_test = [
            ("json", "to_json", '{"result": "test"}'),
            ("yaml", "to_yaml", "result: test"),
            ("markdown", "to_markdown", "# Test Result"),
            (
                "tokens",
                "to_code_text",
                "tokens output",
            ),  # tokens format now uses to_code_text
            ("code", "to_code_text", "code output"),
        ]

        for fmt, method_name, expected_output in formats_to_test:
            mock_report = MagicMock()
            getattr(mock_report, method_name).return_value = expected_output
            mock_create.return_value = mock_report

            with patch.object(
                sys, "argv", ["malwi", "pypi", "test-pkg", "--format", fmt, "--quiet"]
            ):
                with patch("cli.pypi.result") as mock_result:
                    main()

                    # Verify correct format method was called
                    mock_result.assert_called_with(expected_output, force=True)

    @patch("cli.pypi.scan_pypi_package")
    @patch("cli.scan.MalwiReport.create")
    def test_pypi_save_output(self, mock_create, mock_scan_pypi, tmp_path):
        """Test PyPI scanning with save output option"""
        extracted_dir = tmp_path / "package"
        extracted_dir.mkdir()
        output_file = tmp_path / "pypi_output.json"

        mock_scan_pypi.return_value = (tmp_path, [extracted_dir])

        mock_report = MagicMock()
        mock_report.to_json.return_value = '{"saved": "output"}'
        mock_create.return_value = mock_report

        with patch.object(
            sys,
            "argv",
            [
                "malwi",
                "pypi",
                "test-pkg",
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
                assert output_file.read_text() == '{"saved": "output"}'

    @patch("cli.pypi.scan_pypi_package")
    def test_pypi_scan_failure(self, mock_scan_pypi):
        """Test PyPI scanning when package download fails"""
        # Mock failed package download
        mock_scan_pypi.return_value = (None, [])

        with patch.object(sys, "argv", ["malwi", "pypi", "nonexistent-package"]):
            with patch("cli.pypi.error") as mock_error:
                result = main()

                # Verify error was logged and function returned
                mock_error.assert_called_with("Failed to download or extract package")
                assert result is None

    @patch("cli.pypi.scan_pypi_package")
    @patch("cli.scan.MalwiReport.create")
    def test_pypi_custom_threshold(self, mock_create, mock_scan_pypi, tmp_path):
        """Test PyPI scanning with custom maliciousness threshold"""
        extracted_dir = tmp_path / "package"
        extracted_dir.mkdir()
        mock_scan_pypi.return_value = (tmp_path, [extracted_dir])

        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = "Output"
        mock_create.return_value = mock_report

        with patch.object(
            sys, "argv", ["malwi", "pypi", "test-pkg", "--threshold", "0.9", "--quiet"]
        ):
            with patch("cli.pypi.result"):
                main()

                # Verify custom threshold was used
                mock_create.assert_called_once_with(
                    input_path=extracted_dir,
                    accepted_extensions=[".py"],
                    silent=True,
                    malicious_threshold=0.9,
                    on_finding=None,
                    triage=False,
                    triage_provider=None,
                )

    @patch("cli.pypi.scan_pypi_package")
    def test_pypi_model_loading_error(self, mock_scan_pypi, tmp_path):
        """Test PyPI scanning continues when model loading fails"""
        extracted_dir = tmp_path / "package"
        extracted_dir.mkdir()
        mock_scan_pypi.return_value = (tmp_path, [extracted_dir])

        # Make model loading fail
        with patch(
            "cli.scan.MalwiReport.load_models_into_memory",
            side_effect=Exception("Model error"),
        ):
            with patch("cli.scan.MalwiReport.create") as mock_create:
                mock_report = MagicMock()
                mock_report.to_demo_text.return_value = "Output"
                mock_create.return_value = mock_report

                with patch.object(
                    sys, "argv", ["malwi", "pypi", "test-pkg", "--quiet"]
                ):
                    with patch("cli.pypi.result"):
                        # Should not crash
                        main()

                        # Verify processing continued despite model error
                        mock_create.assert_called_once()

    @patch("cli.pypi.scan_pypi_package")
    @patch("cli.scan.MalwiReport.create")
    def test_pypi_with_progress(self, mock_create, mock_scan_pypi, tmp_path):
        """Test PyPI scanning shows progress when not in quiet mode"""
        extracted_dir = tmp_path / "package"
        extracted_dir.mkdir()
        mock_scan_pypi.return_value = (tmp_path, [extracted_dir])

        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = "Output"
        mock_create.return_value = mock_report

        with patch.object(sys, "argv", ["malwi", "pypi", "test-pkg"]):
            with patch("cli.pypi.result"):
                main()

                # Verify show_progress=True when not quiet
                mock_scan_pypi.assert_called_once_with(
                    "test-pkg", None, Path("downloads"), show_progress=True
                )
