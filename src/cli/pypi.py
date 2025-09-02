#!/usr/bin/env python3
"""
PyPI package scanner for malwi.
Downloads and scans PyPI packages for malicious content.
"""

import json
import tempfile
import tarfile
import zipfile
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import urllib.request
import urllib.error
from tqdm import tqdm

from common.malwi_report import MalwiReport
from common.files import copy_file
from common.cache import MalwiCache
from common.messaging import (
    configure_messaging,
    banner,
    model_warning,
    info,
    error,
    result,
)


class PyPIScanner:
    """Scanner for PyPI packages."""

    def __init__(self, temp_dir: Optional[Path] = None):
        """
        Initialize PyPI scanner.

        Args:
            temp_dir: Directory for downloading packages. If None, creates a temp dir.
        """
        if temp_dir is None:
            # Create temp directory that won't be auto-deleted for triaging
            self.temp_dir = Path(tempfile.mkdtemp(prefix="malwi_pypi_"))
        else:
            self.temp_dir = Path(temp_dir)
            self.temp_dir.mkdir(parents=True, exist_ok=True)

        self.host = "https://files.pythonhosted.org"

    def get_package_info(self, package_name: str) -> Optional[Dict]:
        """
        Get package information from PyPI JSON API.

        Args:
            package_name: Name of the package

        Returns:
            Package information dict or None if failed
        """
        url = f"https://pypi.org/pypi/{package_name}/json"

        try:
            with urllib.request.urlopen(url) as response:
                data = json.loads(response.read().decode())
                return data
        except urllib.error.HTTPError as e:
            if e.code == 404:
                error(f"Package '{package_name}' not found on PyPI")
            else:
                error(f"HTTP error {e.code} while fetching package info")
            return None
        except Exception as e:
            error(f"Error fetching package info: {e}")
            return None

    def get_latest_version(self, package_info: Dict) -> Optional[str]:
        """
        Get the latest version from package info.

        Args:
            package_info: Package information from PyPI API

        Returns:
            Latest version string or None
        """
        try:
            return package_info["info"]["version"]
        except KeyError:
            error("Could not determine latest version")
            return None

    def get_download_urls(self, package_info: Dict, version: str) -> List[Dict]:
        """
        Get download URLs for a specific version.

        Args:
            package_info: Package information from PyPI API
            version: Specific version to get URLs for

        Returns:
            List of download URL dictionaries
        """
        try:
            releases = package_info["releases"].get(version, [])
            if not releases:
                error(f"No releases found for version {version}")
                return []

            # Filter for source distributions and wheels
            download_urls = []
            for release in releases:
                if release["packagetype"] in ["sdist", "bdist_wheel"]:
                    download_urls.append(
                        {
                            "url": release["url"],
                            "filename": release["filename"],
                            "packagetype": release["packagetype"],
                            "size": release["size"],
                        }
                    )

            return download_urls
        except KeyError as e:
            error(f"Error parsing release information: {e}")
            return []

    def download_file(
        self, url: str, filename: str, show_progress: bool = True
    ) -> Optional[Path]:
        """
        Download a file from URL to temp directory.

        Args:
            url: URL to download from
            filename: Local filename to save as
            show_progress: Whether to show download progress

        Returns:
            Path to downloaded file or None if failed
        """
        file_path = self.temp_dir / filename

        try:
            if show_progress:
                # Get file size for progress bar
                response = urllib.request.urlopen(url)
                total_size = int(response.headers.get("content-length", 0))
                response.close()

                # Download with progress bar
                with tqdm(
                    total=total_size,
                    unit="B",
                    unit_scale=True,
                    desc=f"Downloading {filename}",
                    leave=False,
                ) as pbar:

                    def progress_hook(block_num, block_size, total_size):
                        pbar.update(block_size)

                    urllib.request.urlretrieve(url, file_path, reporthook=progress_hook)
            else:
                urllib.request.urlretrieve(url, file_path)

            return file_path
        except Exception as e:
            error(f"Failed to download {filename}: {e}")
            return None

    def extract_package(self, file_path: Path) -> Optional[Path]:
        """
        Extract downloaded package file.

        Args:
            file_path: Path to the downloaded package file

        Returns:
            Path to extracted directory or None if failed
        """
        extract_dir = self.temp_dir / file_path.stem
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            if file_path.suffix == ".whl" or file_path.name.endswith(".whl"):
                # Handle wheel files (they're zip files)
                with zipfile.ZipFile(file_path, "r") as zip_ref:
                    zip_ref.extractall(extract_dir)
            elif file_path.suffix in [".gz", ".tgz"] or ".tar." in file_path.name:
                # Handle tar.gz files
                with tarfile.open(file_path, "r:gz") as tar_ref:
                    tar_ref.extractall(extract_dir)
            elif file_path.suffix == ".zip":
                # Handle zip files
                with zipfile.ZipFile(file_path, "r") as zip_ref:
                    zip_ref.extractall(extract_dir)
            else:
                error(f"Unsupported file format: {file_path}")
                return None

            return extract_dir

        except Exception as e:
            error(f"Failed to extract {file_path}: {e}")
            return None

    def scan_package(
        self,
        package_name: str,
        version: Optional[str] = None,
        show_progress: bool = True,
    ) -> Tuple[Optional[Path], List[Path]]:
        """
        Download and extract a PyPI package for scanning.

        Args:
            package_name: Name of the package to scan
            version: Specific version to scan (if None, uses latest)
            show_progress: Whether to show download progress

        Returns:
            Tuple of (temp_dir_path, list_of_extracted_dirs)
        """
        # Get package information
        package_info = self.get_package_info(package_name)
        if not package_info:
            return None, []

        # Determine version to download
        if version is None:
            version = self.get_latest_version(package_info)
            if not version:
                return None, []

        # Get download URLs
        download_urls = self.get_download_urls(package_info, version)
        if not download_urls:
            return None, []

        # Prefer source distribution over wheels for scanning
        source_dist = next(
            (url for url in download_urls if url["packagetype"] == "sdist"), None
        )
        if source_dist:
            url_to_download = source_dist
        else:
            url_to_download = download_urls[0]

        # Download the package
        downloaded_file = self.download_file(
            url_to_download["url"], url_to_download["filename"], show_progress
        )
        if not downloaded_file:
            return None, []

        # Extract the package
        extracted_dir = self.extract_package(downloaded_file)
        if not extracted_dir:
            return None, []

        return self.temp_dir, [extracted_dir]


def scan_pypi_package(
    package_name: str,
    version: Optional[str] = None,
    temp_dir: Optional[Path] = None,
    show_progress: bool = True,
) -> Tuple[Optional[Path], List[Path]]:
    """
    Convenience function to scan a PyPI package.

    Args:
        package_name: Name of the package to scan
        version: Specific version to scan (if None, uses latest)
        temp_dir: Directory for downloading packages
        show_progress: Whether to show download progress

    Returns:
        Tuple of (temp_dir_path, list_of_extracted_dirs)
    """
    scanner = PyPIScanner(temp_dir)
    return scanner.scan_package(package_name, version, show_progress)


def pypi_command(args):
    """Execute the pypi subcommand."""
    # Configure unified messaging system
    configure_messaging(quiet=args.quiet)

    banner()

    # Create cache if specified
    cache = None
    if args.cache:
        cache = MalwiCache(Path(args.cache))

    # Use specified download folder
    download_path = Path(args.folder)

    # Download and extract the package
    temp_dir, extracted_dirs = scan_pypi_package(
        args.package, args.version, download_path, show_progress=not args.quiet
    )

    if not extracted_dirs:
        error("Failed to download or extract package")
        return

    # Load ML models for scanning
    try:
        MalwiReport.load_models_into_memory(
            distilbert_model_path=args.model_path,
            tokenizer_path=args.tokenizer_path,
        )
    except Exception as e:
        model_warning("ML", e)

    # Create triage provider if needed
    triage_provider = None
    use_triage = args.triage or args.triage_llm or args.triage_ui
    if use_triage:
        from common.triage import create_triage_provider

        try:
            if args.triage_ui:
                from common.triage import UITriageProvider

                triage_provider = UITriageProvider()
            else:
                triage_provider = create_triage_provider(use_llm=args.triage_llm)
        except ValueError as e:
            if args.triage_llm or args.triage_ui:
                error(f"Triage failed: {e}")
                return
            else:
                # Fallback to interactive for --triage
                triage_provider = create_triage_provider(use_llm=False)

    # Set up move directory if specified
    move_dir = None
    file_copy_callback = None
    if args.move:
        move_dir = Path(args.move)
        move_dir.mkdir(parents=True, exist_ok=True)

    # Scan each extracted directory
    all_reports = []
    for extracted_dir in extracted_dirs:
        # Create file copy callback for this extracted directory
        if move_dir:

            def file_copy_callback(file_path: Path, malicious_objects):
                copy_file(file_path, extracted_dir, move_dir)

        report: MalwiReport = MalwiReport.create(
            input_path=extracted_dir,
            accepted_extensions=[".py"],  # Focus on Python files for PyPI packages
            silent=args.quiet,
            malicious_threshold=args.threshold,
            on_finding=file_copy_callback,
            triage=use_triage,
            triage_provider=triage_provider,
            cache=cache,
        )
        all_reports.append(report)

    # Combine reports and show results
    if all_reports:
        # For now, use the first report (could be enhanced to merge multiple)
        main_report = all_reports[0]

        # Generate output based on format
        if args.format == "yaml":
            output = main_report.to_yaml()
        elif args.format == "json":
            output = main_report.to_json()
        elif args.format == "markdown":
            output = main_report.to_markdown()
        elif args.format == "tokens":
            output = main_report.to_code_text(include_tokens=True)
        elif args.format == "code":
            output = main_report.to_code_text()
        else:
            output = main_report.to_demo_text()

        if args.save:
            save_path = Path(args.save)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            save_path.write_text(output, encoding="utf-8")
            if not args.quiet:
                info(f"Output saved to {args.save}")
        else:
            result(output, force=True)

    else:
        info("No files were processed")


def setup_pypi_parser(subparsers):
    """Set up the pypi subcommand parser."""
    pypi_parser = subparsers.add_parser("pypi", help="Scan PyPI packages")
    pypi_parser.add_argument("package", help="PyPI package name to scan")
    pypi_parser.add_argument(
        "version",
        nargs="?",
        default=None,
        help="Package version (optional, defaults to latest)",
    )
    pypi_parser.add_argument(
        "--folder",
        "-d",
        metavar="FOLDER",
        default="downloads",
        help="Folder to download packages to (default: downloads)",
    )
    pypi_parser.add_argument(
        "--format",
        "-f",
        choices=["demo", "markdown", "json", "yaml", "tokens", "code"],
        default="demo",
        help="Specify the output format.",
    )
    pypi_parser.add_argument(
        "--threshold",
        "-mt",
        metavar="FLOAT",
        type=float,
        default=0.7,
        help="Specify the threshold for classifying code objects as malicious (default: 0.7).",
    )
    pypi_parser.add_argument(
        "--save",
        "-s",
        metavar="FILE",
        help="Specify a file path to save the output.",
        default=None,
    )
    # Create mutually exclusive group for triage options
    triage_group = pypi_parser.add_mutually_exclusive_group()
    triage_group.add_argument(
        "--triage",
        action="store_true",
        help="Interactively review and confirm each malicious finding. Prompts user to classify each finding as 'Suspicious', 'Benign (false positive)', 'Skip', or 'Quit'. Benign findings are automatically commented out in source files.",
    )
    triage_group.add_argument(
        "--triage-llm",
        action="store_true",
        help="Use AI-powered triage for automatic malicious finding classification. Requires OPENAI_API_KEY, MISTRAL_API_KEY or GEMINI_API_KEY environment variable. AI analyzes each finding and automatically comments out benign false positives while preserving genuine threats.",
    )
    triage_group.add_argument(
        "--triage-ui",
        action="store_true",
        help="Interactive triage using a graphical user interface. Opens a window showing code with buttons for classification decisions. Similar to --triage but with a visual interface.",
    )
    pypi_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress logging output.",
    )
    pypi_parser.add_argument(
        "--move",
        nargs="?",
        const="findings",
        metavar="DIR",
        default=None,
        help="Copy files with malicious findings to the specified directory, preserving folder structure (default: findings).",
    )

    pypi_developer_group = pypi_parser.add_argument_group("Developer Options")
    pypi_developer_group.add_argument(
        "--tokenizer-path",
        "-t",
        metavar="PATH",
        help="Specify the tokenizer path",
        default=None,
    )
    pypi_developer_group.add_argument(
        "--model-path",
        "-m",
        metavar="PATH",
        help="Specify the DistilBert model path",
        default=None,
    )
    pypi_developer_group.add_argument(
        "--cache",
        "-c",
        metavar="FILE",
        help="Enable caching of prediction results to specified CSV file. Results are looked up by SHA512 hash of source code.",
        default=None,
    )

    # Set the command handler
    pypi_parser.set_defaults(func=pypi_command)
