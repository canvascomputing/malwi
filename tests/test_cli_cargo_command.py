import sys
import os
import tarfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cli.entry import main
from cli.cargo import CargoScanner


def create_crate_tarball(src_dir: Path, tar_path: Path) -> None:
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(src_dir, arcname="testcrate-0.1.0")


def test_cargo_cli_downloads_and_scans(tmp_path):
    crate_src = Path(__file__).parent / "source_samples" / "rust_crate"
    crate_tar = tmp_path / "testcrate-0.1.0.crate"
    create_crate_tarball(crate_src, crate_tar)

    def mock_get_crate_info(self, name):
        return {"crate": {"newest_version": "0.1.0"}}

    def mock_download_crate(self, name, version, show_progress=True):
        return crate_tar

    mock_report = MagicMock()
    mock_report.to_demo_text.return_value = "scan complete"

    with patch.object(CargoScanner, "get_crate_info", mock_get_crate_info), \
         patch.object(CargoScanner, "download_crate", mock_download_crate), \
         patch("cli.cargo.MalwiReport.create", return_value=mock_report) as mock_create, \
         patch("cli.cargo.MalwiReport.load_models_into_memory"), \
         patch("cli.cargo.banner"), \
         patch("cli.cargo.configure_messaging"), \
         patch("cli.cargo.result") as mock_result:
        with patch.object(sys, "argv", ["malwi", "cargo", "testcrate", "--folder", str(tmp_path), "--quiet"]):
            main()

    mock_result.assert_called_with("scan complete", force=True)
    args, kwargs = mock_create.call_args
    assert kwargs["input_path"].name.startswith("testcrate-0.1.0")
