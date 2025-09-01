"""
Scan functionality for malwi CLI.
"""

import os
import sys
from pathlib import Path
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

from common.malwi_report import MalwiReport
from common.files import copy_file
from common.config import SUPPORTED_EXTENSIONS
from common.messaging import (
    configure_messaging,
    banner,
    model_warning,
    path_error,
    info,
    result,
    error,
)


def create_real_time_findings_display(silent: bool = False):
    """Create a callback function for real-time malicious findings display."""
    if silent:
        return None, None

    # Keep track of findings count and whether we've displayed before
    findings_state = {"count": 0, "lines_displayed": 0}

    def display_malicious_finding(file_path: Path, malicious_objects):
        """Display malicious findings in real-time using demo-like format."""
        # Clear previous lines if any
        if findings_state["lines_displayed"] > 0:
            # Move cursor up and clear lines
            for _ in range(findings_state["lines_displayed"]):
                tqdm.write("\033[1A\033[2K", file=sys.stderr, end="")

        # Increment counter
        findings_state["count"] += 1

        # Display count header
        count_display = f"- 👹 suspicious files: {findings_state['count']}"
        tqdm.write(count_display, file=sys.stderr)

        # Display latest finding with first object name
        lines_written = 1
        if malicious_objects:
            obj_display = f"     └── {file_path}, {malicious_objects[0].name}"
            tqdm.write(obj_display, file=sys.stderr)
            lines_written = 2

        # Update lines displayed count
        findings_state["lines_displayed"] = lines_written

        # Force flush to ensure immediate display
        sys.stderr.flush()

    def cleanup_display():
        """Clear the real-time display after scan completes."""
        if findings_state["lines_displayed"] > 0:
            # Move cursor up and clear lines
            for _ in range(findings_state["lines_displayed"]):
                tqdm.write("\033[1A\033[2K", file=sys.stderr, end="")
            sys.stderr.flush()

    return display_malicious_finding, cleanup_display


def run_batch_scan(child_folder: Path, args) -> dict:
    """Run a single scan on a child folder and return results."""
    # Check if output file already exists
    format_ext = {
        "demo": ".txt",
        "markdown": ".md",
        "json": ".json",
        "yaml": ".yaml",
        "tokens": ".txt",
        "code": ".txt",
    }
    extension = format_ext.get(args.format, ".txt")
    output_file = Path.cwd() / f"malwi_{child_folder.name}{extension}"

    if output_file.exists():
        return {"folder": child_folder.name, "success": True, "skipped": True}

    try:
        # Create triage provider for batch processing if needed
        triage_provider = None
        use_triage = args.triage or args.triage_mcp
        if use_triage:
            from common.triage import create_triage_provider

            try:
                triage_provider = create_triage_provider(use_mcp=args.triage_mcp)
            except ValueError as e:
                if args.triage_mcp:
                    return {
                        "folder": child_folder.name,
                        "success": False,
                        "error": f"MCP triage failed: {e}",
                    }
                else:
                    triage_provider = create_triage_provider(use_mcp=False)

        report: MalwiReport = MalwiReport.create(
            input_path=child_folder,
            accepted_extensions=args.extensions,
            silent=True,  # Silent for individual folder processing in batch mode
            malicious_threshold=args.threshold,
            triage=use_triage,
            triage_provider=triage_provider,
        )

        # Generate output based on format
        if args.format == "yaml":
            output = report.to_yaml()
        elif args.format == "json":
            output = report.to_json()
        elif args.format == "markdown":
            output = report.to_markdown()
        elif args.format == "tokens":
            output = report.to_code_text(include_tokens=True)
        elif args.format == "code":
            output = report.to_code_text()
        else:
            output = report.to_demo_text()

        # Save the output
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(output, encoding="utf-8")

        return {"folder": child_folder.name, "success": True, "skipped": False}

    except Exception as e:
        return {
            "folder": child_folder.name,
            "success": False,
            "error": str(e),
            "skipped": False,
        }


def process_batch_mode(input_path: Path, args) -> None:
    """Process multiple child folders in batch mode."""
    if not input_path.is_dir():
        path_error("Batch mode requires a directory path")
        return

    # Get all child directories
    child_folders = [p for p in input_path.iterdir() if p.is_dir()]

    if not child_folders:
        info("No child directories found for batch processing")
        return

    # Load ML models once for batch processing
    try:
        MalwiReport.load_models_into_memory(
            distilbert_model_path=args.model_path,
            tokenizer_path=args.tokenizer_path,
        )
    except Exception as e:
        model_warning("ML", e)

    info(f"🚀 Starting batch scan of {len(child_folders)} folders")

    # Use ThreadPoolExecutor for parallel processing (shares memory space for models)
    max_workers = min(4, len(child_folders))  # Restore parallel processing

    failed = 0
    skipped = 0
    failed_folders = []

    # Create progress bar (disable if quiet mode)
    with tqdm(
        total=len(child_folders),
        desc="📈 Scanning folders",
        unit="folder",
        disable=args.quiet,
    ) as pbar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            try:
                # Submit all jobs
                future_to_folder = {
                    executor.submit(run_batch_scan, folder, args): folder
                    for folder in child_folders
                }

                # Process completed jobs
                for future in as_completed(future_to_folder):
                    folder = future_to_folder[future]
                    try:
                        batch_result = future.result()

                        if batch_result.get("skipped", False):
                            skipped += 1
                            pbar.set_postfix_str(f"⏭️ {batch_result['folder']}")
                        elif batch_result["success"]:
                            pbar.set_postfix_str(f"✅ {batch_result['folder']}")
                        else:
                            failed += 1
                            error_msg = batch_result.get("error", "Unknown error")
                            failed_folders.append(
                                f"{batch_result['folder']}: {error_msg}"
                            )
                            pbar.set_postfix_str(f"❌ {batch_result['folder']}")

                    except Exception as e:
                        failed += 1
                        failed_folders.append(f"{folder.name}: {str(e)}")
                        pbar.set_postfix_str(f"❌ {folder.name}")

                    pbar.update(1)

            except KeyboardInterrupt:
                info("\n🛑 Interrupt received. Shutting down...")
                # Force immediate exit to avoid thread cleanup issues
                os._exit(130)

    # Summary
    processed = len(child_folders) - skipped
    success_count = processed - failed
    info(
        f"🎯 Batch scan complete: {success_count} successful, {failed} failed, {skipped} skipped"
    )

    # Show failed folders if any
    if failed_folders and not args.quiet:
        info("Failed folders:")
        for failure in failed_folders:
            info(f"  - {failure}")


def scan_command(args):
    """Execute the scan subcommand."""
    # Configure unified messaging system
    configure_messaging(quiet=args.quiet)

    banner()

    # Process files using the consolidated function
    input_path = Path(args.path)
    if not input_path.exists():
        path_error(input_path)
        return

    # Handle batch mode - run independent scans on child folders
    if args.batch:
        process_batch_mode(input_path, args)
        return

    # Load ML models (only for non-batch mode)
    try:
        MalwiReport.load_models_into_memory(
            distilbert_model_path=args.model_path,
            tokenizer_path=args.tokenizer_path,
        )
    except Exception as e:
        model_warning("ML", e)

    # Create callbacks for real-time display and file copying
    real_time_callback = None
    cleanup_callback = None
    file_copy_callback = None

    # Set up move directory if specified
    move_dir = None
    if args.move:
        move_dir = Path(args.move)
        move_dir.mkdir(parents=True, exist_ok=True)

        def file_copy_callback(file_path: Path, malicious_objects):
            copy_file(file_path, input_path, move_dir)

    # Enable real-time display for directories when not in quiet mode
    if input_path.is_dir() and not args.quiet:
        real_time_callback, cleanup_callback = create_real_time_findings_display(
            silent=args.quiet
        )

    # Combine callbacks if both exist
    combined_callback = None
    if real_time_callback and file_copy_callback:

        def combined_callback(file_path: Path, malicious_objects):
            real_time_callback(file_path, malicious_objects)
            file_copy_callback(file_path, malicious_objects)
    elif real_time_callback:
        combined_callback = real_time_callback
    elif file_copy_callback:
        combined_callback = file_copy_callback

    # Create triage provider if needed
    triage_provider = None
    use_triage = args.triage or args.triage_mcp
    if use_triage:
        from common.triage import create_triage_provider

        try:
            triage_provider = create_triage_provider(use_mcp=args.triage_mcp)
        except ValueError as e:
            if args.triage_mcp:
                error(f"MCP triage failed: {e}")
                return
            else:
                # Fallback to interactive for --triage
                triage_provider = create_triage_provider(use_mcp=False)

    report: MalwiReport = MalwiReport.create(
        input_path=input_path,
        accepted_extensions=args.extensions,
        silent=args.quiet,
        malicious_threshold=args.threshold,
        on_finding=combined_callback,
        triage=use_triage,
        triage_provider=triage_provider,
    )

    # Clean up the real-time display
    if cleanup_callback:
        cleanup_callback()

    output = ""

    if args.format == "yaml":
        output = report.to_yaml()
    elif args.format == "json":
        output = report.to_json()
    elif args.format == "markdown":
        output = report.to_markdown()
    elif args.format == "tokens":
        output = report.to_code_text(include_tokens=True)
    elif args.format == "code":
        output = report.to_code_text()
    else:
        output = report.to_demo_text()

    if args.save:
        save_path = Path(args.save)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(output, encoding="utf-8")
        info(f"Output saved to {args.save}")
    else:
        # Ensure all streams are flushed before final output
        import sys

        sys.stdout.flush()
        sys.stderr.flush()

        # Use result() for consistent output handling
        result(output, force=True)


def setup_scan_parser(subparsers):
    """Set up the scan subcommand parser."""
    scan_parser = subparsers.add_parser("scan", help="Scan local files or directories")
    scan_parser.add_argument(
        "path", metavar="PATH", help="Specify the package file or folder path."
    )
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["demo", "markdown", "json", "yaml", "tokens", "code"],
        default="demo",
        help="Specify the output format.",
    )
    # Create mutually exclusive group for batch and save modes
    output_group = scan_parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--save",
        "-s",
        metavar="FILE",
        help="Specify a file path to save the output.",
        default=None,
    )
    output_group.add_argument(
        "--batch",
        action="store_true",
        help="Run independent scans on each child folder and save results to current directory as malwi_<foldername>.<format>.",
    )
    scan_parser.add_argument(
        "--threshold",
        "-mt",
        metavar="FLOAT",
        type=float,
        default=0.7,
        help="Specify the threshold for classifying code objects as malicious (default: 0.7).",
    )
    scan_parser.add_argument(
        "--extensions",
        "-e",
        nargs="+",
        default=SUPPORTED_EXTENSIONS,
        help=f"Specify file extensions to process (default: {', '.join(SUPPORTED_EXTENSIONS)}).",
    )
    scan_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress logging output and progress bar.",
    )
    scan_parser.add_argument(
        "--triage",
        action="store_true",
        help="Interactively review and confirm each malicious finding. Prompts user to classify each finding as 'Suspicious', 'Benign (false positive)', 'Skip', or 'Quit'. Benign findings are automatically commented out in source files.",
    )
    scan_parser.add_argument(
        "--triage-mcp",
        action="store_true",
        help="Use AI-powered triage for automatic malicious finding classification. Requires MISTRAL_API_KEY or GEMINI_API_KEY environment variable. AI analyzes each finding and automatically comments out benign false positives while preserving genuine threats.",
    )
    scan_parser.add_argument(
        "--move",
        nargs="?",
        const="findings",
        metavar="DIR",
        default=None,
        help="Copy files with malicious findings to the specified directory, preserving folder structure (default: findings).",
    )

    developer_group = scan_parser.add_argument_group("Developer Options")
    developer_group.add_argument(
        "--tokenizer-path",
        "-t",
        metavar="PATH",
        help="Specify the tokenizer path",
        default=None,
    )
    developer_group.add_argument(
        "--model-path",
        "-m",
        metavar="PATH",
        help="Specify the DistilBert model path",
        default=None,
    )

    # Set the command handler
    scan_parser.set_defaults(func=scan_command)
