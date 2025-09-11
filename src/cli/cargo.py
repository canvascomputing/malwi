#!/usr/bin/env python3
"""
Crates.io package scanner for malwi.
Downloads and scans Rust crates for malicious content.
"""

import json
import tempfile
import tarfile
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import urllib.request
import urllib.error
from tqdm import tqdm
import tomllib

from common.malwi_report import MalwiReport
from common.files import copy_file
from common.messaging import (
    configure_messaging,
    banner,
    model_warning,
    info,
    error,
    result,
)


class CargoScanner:
    """Scanner for crates.io packages."""

    def __init__(self, temp_dir: Optional[Path] = None):
        """Initialize Cargo scanner.

        Args:
            temp_dir: Directory for downloading packages. If None, creates a temp dir.
        """
        if temp_dir is None:
            self.temp_dir = Path(tempfile.mkdtemp(prefix="malwi_cargo_"))
        else:
            self.temp_dir = Path(temp_dir)
            self.temp_dir.mkdir(parents=True, exist_ok=True)

        self.api_host = "https://crates.io/api/v1"
        self.user_agent = "malwi-bot/1.0 (https://github.com)"

    def get_crate_info(self, crate_name: str) -> Optional[Dict]:
        """Get crate information from crates.io API."""
        url = f"{self.api_host}/crates/{crate_name}"
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                return data
        except urllib.error.HTTPError as e:
            if e.code == 404:
                error(f"Crate '{crate_name}' not found on crates.io")
            else:
                error(f"HTTP error {e.code} while fetching crate info")
            return None
        except Exception as e:
            error(f"Error fetching crate info: {e}")
            return None

    def get_latest_version(self, crate_info: Dict) -> Optional[str]:
        """Get the latest version from crate info."""
        try:
            crate = crate_info["crate"]
            return crate.get("newest_version") or crate.get("max_stable_version")
        except KeyError:
            error("Could not determine latest version")
            return None

    def download_file(self, url: str, filename: str, show_progress: bool = True) -> Optional[Path]:
        """Download a file from URL to temp directory."""
        file_path = self.temp_dir / filename
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            if show_progress:
                response = urllib.request.urlopen(req)
                total_size = int(response.headers.get("content-length", 0))
                response.close()
                with tqdm(
                    total=total_size,
                    unit="B",
                    unit_scale=True,
                    desc=f"Downloading {filename}",
                    leave=False,
                ) as pbar:
                    def progress_hook(block_num, block_size, total_size):
                        pbar.update(block_size)
                    urllib.request.urlretrieve(req, file_path, reporthook=progress_hook)
            else:
                urllib.request.urlretrieve(req, file_path)
            return file_path
        except Exception as e:
            error(f"Failed to download {filename}: {e}")
            return None

    def extract_crate(self, file_path: Path) -> Optional[Path]:
        """Extract downloaded crate file."""
        extract_dir = self.temp_dir / file_path.stem
        extract_dir.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(file_path, "r:gz") as tar_ref:
                tar_ref.extractall(extract_dir)
            return extract_dir
        except Exception as e:
            error(f"Failed to extract {file_path}: {e}")
            return None

    def parse_dependencies(self, extracted_dir: Path) -> List[str]:
        """Parse dependencies from Cargo.lock or Cargo.toml."""
        dependencies: List[str] = []
        lock_file = extracted_dir / "Cargo.lock"
        toml_file = extracted_dir / "Cargo.toml"
        try:
            if lock_file.exists():
                data = tomllib.loads(lock_file.read_text(encoding="utf-8"))
                for pkg in data.get("package", []):
                    name = pkg.get("name")
                    version = pkg.get("version")
                    if name:
                        dependencies.append(f"{name} {version}" if version else name)
            elif toml_file.exists():
                data = tomllib.loads(toml_file.read_text(encoding="utf-8"))
                deps = data.get("dependencies", {})
                for name, spec in deps.items():
                    if isinstance(spec, dict):
                        version = spec.get("version")
                        dependencies.append(f"{name} {version}" if version else name)
                    else:
                        dependencies.append(f"{name} {spec}")
        except Exception as e:
            error(f"Failed to parse dependencies: {e}")
        return dependencies

    def download_crate(self, crate_name: str, version: str, show_progress: bool = True) -> Optional[Path]:
        """Download the specified crate version."""
        url = f"{self.api_host}/crates/{crate_name}/{version}/download"
        filename = f"{crate_name}-{version}.crate"
        return self.download_file(url, filename, show_progress)

    def scan_crate(
        self,
        crate_name: str,
        version: Optional[str] = None,
        show_progress: bool = True,
    ) -> Tuple[Optional[Path], List[Path], List[str]]:
        """Download and extract a crates.io package for scanning."""
        crate_info = self.get_crate_info(crate_name)
        if not crate_info:
            return None, [], []
        if version is None:
            version = self.get_latest_version(crate_info)
            if not version:
                return None, [], []
        downloaded_file = self.download_crate(crate_name, version, show_progress)
        if not downloaded_file:
            return None, [], []
        extracted_dir = self.extract_crate(downloaded_file)
        if not extracted_dir:
            return None, [], []
        dependencies = self.parse_dependencies(extracted_dir)
        return self.temp_dir, [extracted_dir], dependencies


def scan_cargo_crate(
    crate_name: str,
    version: Optional[str] = None,
    temp_dir: Optional[Path] = None,
    show_progress: bool = True,
) -> Tuple[Optional[Path], List[Path], List[str]]:
    """Convenience function to scan a crates.io package."""
    scanner = CargoScanner(temp_dir)
    return scanner.scan_crate(crate_name, version, show_progress)


def cargo_command(args):
    """Execute the cargo subcommand."""
    configure_messaging(quiet=args.quiet)
    banner()
    download_path = Path(args.folder)
    temp_dir, extracted_dirs, dependencies = scan_cargo_crate(
        args.crate, args.version, download_path, show_progress=not args.quiet
    )
    if not extracted_dirs:
        error("Failed to download or extract crate")
        return
    if dependencies:
        info("Dependencies: " + ", ".join(dependencies))
    try:
        MalwiReport.load_models_into_memory(
            distilbert_model_path=args.model_path,
            tokenizer_path=args.tokenizer_path,
        )
    except Exception as e:
        model_warning("ML", e)
    triage_provider = None
    use_triage = args.triage or args.triage_llm
    if use_triage:
        from common.triage import create_triage_provider
        try:
            triage_provider = create_triage_provider(use_llm=args.triage_llm)
        except ValueError as e:
            if args.triage_llm:
                error(f"MCP triage failed: {e}")
                return
            else:
                triage_provider = create_triage_provider(use_mcp=False)
    move_dir = None
    file_copy_callback = None
    if args.move:
        move_dir = Path(args.move)
        move_dir.mkdir(parents=True, exist_ok=True)
    all_reports = []
    for extracted_dir in extracted_dirs:
        if move_dir:
            def file_copy_callback(file_path: Path, malicious_objects):
                copy_file(file_path, extracted_dir, move_dir)
        report: MalwiReport = MalwiReport.create(
            input_path=extracted_dir,
            accepted_extensions=[".rs"],
            silent=args.quiet,
            malicious_threshold=args.threshold,
            on_finding=file_copy_callback,
            triage=use_triage,
            triage_provider=triage_provider,
        )
        all_reports.append(report)
    if all_reports:
        main_report = all_reports[0]
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


def setup_cargo_parser(subparsers):
    """Set up the cargo subcommand parser."""
    cargo_parser = subparsers.add_parser("cargo", help="Scan crates.io packages")
    cargo_parser.add_argument("crate", help="Crate name to scan")
    cargo_parser.add_argument(
        "version",
        nargs="?",
        default=None,
        help="Crate version (optional, defaults to latest)",
    )
    cargo_parser.add_argument(
        "--folder",
        "-d",
        metavar="FOLDER",
        default="downloads",
        help="Folder to download packages to (default: downloads)",
    )
    cargo_parser.add_argument(
        "--format",
        "-f",
        choices=["demo", "markdown", "json", "yaml", "tokens", "code"],
        default="demo",
        help="Specify the output format.",
    )
    cargo_parser.add_argument(
        "--threshold",
        "-mt",
        metavar="FLOAT",
        type=float,
        default=0.7,
        help="Specify the threshold for classifying code objects as malicious (default: 0.7).",
    )
    cargo_parser.add_argument(
        "--save",
        "-s",
        metavar="FILE",
        help="Specify a file path to save the output.",
        default=None,
    )
    triage_group = cargo_parser.add_mutually_exclusive_group()
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
    cargo_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress logging output.",
    )
    cargo_parser.add_argument(
        "--move",
        nargs="?",
        const="findings",
        metavar="DIR",
        default=None,
        help="Copy files with malicious findings to the specified directory, preserving folder structure (default: findings).",
    )
    cargo_developer_group = cargo_parser.add_argument_group("Developer Options")
    cargo_developer_group.add_argument(
        "--tokenizer-path",
        "-t",
        metavar="PATH",
        help="Specify the tokenizer path",
        default=None,
    )
    cargo_developer_group.add_argument(
        "--model-path",
        "-m",
        metavar="PATH",
        help="Specify the DistilBert model path",
        default=None,
    )
    cargo_parser.set_defaults(func=cargo_command)
