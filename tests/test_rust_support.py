import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from common.files import collect_files_by_extension
from common.malwi_report import MalwiReport


def test_collect_files_accepts_rust():
    sample_dir = Path(__file__).parent / "source_samples" / "rust"
    accepted, skipped = collect_files_by_extension(sample_dir)
    rust_file = sample_dir / "hello.rs"
    assert rust_file in accepted
    assert rust_file.suffix.lstrip(".") == "rs"


@patch("common.malwi_report.process_single_file")
def test_malwi_report_handles_rust(mock_process):
    rust_file = Path(__file__).parent / "source_samples" / "rust" / "hello.rs"
    mock_obj = MagicMock(maliciousness=0.0, language="rust")
    mock_process.return_value = ([mock_obj], [])
    report = MalwiReport.create(rust_file, silent=True)
    mock_process.assert_called_once()
    assert rust_file in report.all_files
    assert report.processed_files == 1
