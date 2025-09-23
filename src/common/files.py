import json
import logging
import pathlib
import sys
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from .config import SUPPORTED_EXTENSIONS
from .messaging import path_error


def read_json_from_file(filepath: pathlib.Path) -> Dict[str, Any]:
    """Reads and parses JSON data from a file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except FileNotFoundError:
        logging.error(f"Mapping file not found: {filepath}")
    except json.JSONDecodeError:
        logging.error(f"Could not decode JSON from file {filepath}. Check format.")
    except Exception as e:
        logging.error(f"An unexpected error occurred reading {filepath}: {e}")
    # Return empty dict on error to allow script to potentially continue with defaults/empty mappings
    return {}


def copy_file(file_path: Path, base_input_path: Path, move_dir: Path) -> None:
    """
    Copy a file to the move directory while preserving folder structure.

    Args:
        file_path: Path to the file to copy
        base_input_path: Base input path that was scanned (to calculate relative path)
        move_dir: Directory to copy files to
    """
    try:
        # Calculate relative path from the base input path
        if base_input_path.is_file():
            # If scanning a single file, just use the filename
            relative_path = file_path.name
        else:
            # If scanning a directory, preserve the folder structure
            relative_path = file_path.relative_to(base_input_path)

        # Create the destination path
        dest_path = move_dir / relative_path

        # Create parent directories if they don't exist
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy the file
        shutil.copy2(file_path, dest_path)

    except Exception as e:
        # Don't fail the operation if copying fails, just log it
        print(f"Warning: Failed to copy {file_path}: {e}", file=sys.stderr)


def collect_files_by_extension(
    input_path: Path,
    accepted_extensions: Optional[List[str]] = None,
    silent: bool = False,
) -> Tuple[List[Path], List[Path]]:
    """
    Collect files from the input path, filtering by accepted extensions.
    Args:
        input_path: Path to file or directory
        accepted_extensions: List of file extensions to accept (without dots)
        silent: If True, suppress error messages
    Returns:
        Tuple of (accepted_files, skipped_files)
    """
    if accepted_extensions is None:
        accepted_extensions = SUPPORTED_EXTENSIONS
    normalized_extensions = [ext.lower().lstrip(".") for ext in accepted_extensions]
    accepted_files = []
    skipped_files = []
    if not input_path.exists():
        if not silent:
            path_error(input_path)
        return accepted_files, skipped_files
    if input_path.is_file():
        file_extension = input_path.suffix.lstrip(".").lower()
        if file_extension in normalized_extensions:
            accepted_files.append(input_path)
        else:
            skipped_files.append(input_path)
    elif input_path.is_dir():
        for file_path in input_path.rglob("*"):
            if file_path.is_file():
                file_extension = file_path.suffix.lstrip(".").lower()
                if file_extension in normalized_extensions:
                    accepted_files.append(file_path)
                else:
                    skipped_files.append(file_path)
    else:
        skipped_files.append(input_path)
    return accepted_files, skipped_files


def concatenate_files(malicious_objects, scan_target: Path, threshold: float) -> str:
    """
    Concatenate malicious file contents into a single string for LLM processing.

    Args:
        malicious_objects: List of MalwiObject instances that are malicious
        scan_target: Path that was scanned (for header info)
        threshold: Maliciousness threshold used

    Returns:
        String containing concatenated file contents with headers
    """
    content_parts = []
    content_parts.append("# Malicious Files Found by malwi Scanner\n")
    content_parts.append(f"# Scan target: {scan_target}\n")
    content_parts.append(f"# Total malicious files: {len(malicious_objects)}\n")
    content_parts.append(f"# Threshold: {threshold}\n\n")

    for malwi_obj in malicious_objects:
        try:
            source_file = Path(malwi_obj.file_path)

            # Add file header
            content_parts.append(f"# File: {source_file}\n")
            if hasattr(malwi_obj, "activities") and malwi_obj.activities:
                content_parts.append(
                    f"# Detected Activities: {', '.join(malwi_obj.activities)}\n"
                )
            content_parts.append(f"# {'=' * 60}\n\n")

            # Read and add file content
            try:
                file_content = source_file.read_text(encoding="utf-8", errors="ignore")
                content_parts.append(file_content)
                content_parts.append(f"\n\n# End of {source_file}\n")
                content_parts.append("#" * 80 + "\n\n")
            except Exception as read_error:
                content_parts.append(
                    f"# ERROR: Could not read file content: {read_error}\n"
                )
                content_parts.append("#" * 80 + "\n\n")

        except Exception as e:
            content_parts.append(f"# ERROR: Failed to process file: {e}\n")
            content_parts.append("#" * 80 + "\n\n")

    return "".join(content_parts)
