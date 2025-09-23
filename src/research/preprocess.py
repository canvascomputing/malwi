#!/usr/bin/env python3
"""
Parallel preprocessing with proper resource management and error handling.
Fixed serialization, resource leak, and timeout issues for reliable multiprocessing.
"""

import argparse
import csv
import gc
import logging
import multiprocessing as mp
import os
import signal
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError, as_completed
from pathlib import Path
from typing import Dict, List

import tqdm

from common.messaging import (
    info,
    success,
    warning,
    error,
    progress,
    configure_messaging,
)


def _process_single_file_with_compiler(
    file_path: Path, compiler, label: str = None, timeout: int = 30
) -> Dict:
    """
    Process a single file with an existing compiler and timeout protection.
    Returns serializable result dictionary.
    """
    result = {
        "file_path": str(file_path),
        "success": False,
        "error": None,
        "code_objects": [],
    }

    def timeout_handler(signum, frame):
        raise TimeoutError(f"File processing timeout after {timeout}s")

    # Set up timeout signal (Unix only)
    if hasattr(signal, "SIGALRM"):
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)

    try:
        # Safety check: ensure we're processing a file, not a directory
        if not file_path.is_file():
            result["error"] = f"Path is not a file: {file_path}"
            return result

        # Process the file with existing compiler
        code_objects = compiler.process_file(file_path)

        # Convert to serializable format immediately
        serializable_objects = []
        for obj in code_objects:
            try:
                obj_data = {
                    "tokens": obj.to_string(one_line=True),
                    "hash": obj.to_hash(),
                    "language": obj.language,
                    "filepath": str(obj.file_path),
                    "label": label or "",
                }
                serializable_objects.append(obj_data)
            except Exception as e:
                logging.warning(f"Failed to serialize object from {file_path}: {e}")
                continue

        result["success"] = True
        result["code_objects"] = serializable_objects

    except TimeoutError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = f"Processing error: {str(e)}"
    finally:
        # Clean up timeout signal
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    return result


def process_file_chunk(chunk_data: Dict) -> Dict:
    """
    Process a chunk of files in a separate process with proper resource management.
    Args:
        chunk_data: Dictionary containing:
            - files: List of file path strings (serializable)
            - language: Language type string
            - chunk_id: Identifier for this chunk
            - temp_dir: Temporary directory path string
            - label: Label for these files (optional)
    Returns:
        Dictionary with processing results
    """
    try:
        # Extract data (all should be serializable strings/primitives)
        file_paths = [Path(fp) for fp in chunk_data["files"]]
        language = chunk_data["language"]
        chunk_id = chunk_data["chunk_id"]
        temp_dir = Path(chunk_data["temp_dir"])
        label = chunk_data.get("label", "")

        # Create ONE compiler instance per chunk (not per file!)
        # Import inside worker to avoid serialization issues
        from common.bytecode import ASTCompiler

        try:
            compiler = ASTCompiler(language)
        except ValueError as e:
            return {
                "chunk_id": chunk_id,
                "success": False,
                "error": f"Compiler initialization failed: {str(e)}",
                "processed_count": 0,
                "code_objects_count": 0,
                "total_files": len(file_paths),
            }

        # Create output file
        chunk_output = temp_dir / f"chunk_{chunk_id}.csv"
        processed_count = 0
        total_code_objects = 0

        # Use context manager for file handling
        with open(chunk_output, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["tokens", "hash", "language", "filepath", "label"])

            # Process each file with shared compiler and individual timeout protection
            for file_path in file_paths:
                try:
                    file_result = _process_single_file_with_compiler(
                        file_path, compiler, label=label, timeout=30
                    )

                    if file_result["success"]:
                        # Write code objects to CSV
                        for obj_data in file_result["code_objects"]:
                            writer.writerow(
                                [
                                    obj_data["tokens"],
                                    obj_data["hash"],
                                    obj_data["language"],
                                    obj_data["filepath"],
                                    obj_data["label"],
                                ]
                            )
                            total_code_objects += 1
                        processed_count += 1
                    else:
                        logging.warning(
                            f"Chunk {chunk_id}: Failed to process {file_path.name}: {file_result['error']}"
                        )

                except Exception as e:
                    logging.warning(
                        f"Chunk {chunk_id}: Unexpected error processing {file_path.name}: {e}"
                    )
                    continue

                # Periodic cleanup to prevent memory buildup
                if processed_count % 50 == 0:
                    gc.collect()

        # Explicit cleanup
        del compiler
        gc.collect()

        return {
            "chunk_id": chunk_id,
            "success": True,
            "output_file": str(chunk_output),
            "processed_count": processed_count,
            "code_objects_count": total_code_objects,
            "total_files": len(file_paths),
        }

    except Exception as e:
        return {
            "chunk_id": chunk_data.get("chunk_id", "unknown"),
            "success": False,
            "error": f"Chunk processing failed: {str(e)}",
            "processed_count": 0,
            "code_objects_count": 0,
            "total_files": len(chunk_data.get("files", [])),
        }


def split_files_into_chunks(files: List[Path], chunk_size: int) -> List[List[str]]:
    """
    Split files into chunks for parallel processing.
    Returns chunks as lists of string paths (serializable).
    """
    if not files:
        return []

    chunks = []
    for i in range(0, len(files), chunk_size):
        chunk = files[i : i + chunk_size]
        # Convert to strings for serialization
        chunk_strings = [str(f) for f in chunk]
        chunks.append(chunk_strings)

    return chunks


def combine_csv_chunks(chunk_files: List[str], output_path: Path) -> int:
    """Combine multiple CSV chunk files into a single output file."""
    total_rows = 0

    # Increase CSV field size limit to handle very large token strings
    csv.field_size_limit(10 * 1024 * 1024)  # 10MB limit instead of default 131KB

    with open(output_path, "w", encoding="utf-8", newline="") as output_file:
        writer = csv.writer(output_file)
        # Write header
        writer.writerow(["tokens", "hash", "language", "filepath", "label"])

        for chunk_file in chunk_files:
            chunk_path = Path(chunk_file)
            if not chunk_path.exists():
                logging.warning(f"Chunk file missing: {chunk_file}")
                continue

            try:
                with open(chunk_path, "r", encoding="utf-8") as f:
                    reader = csv.reader(f)
                    next(reader)  # Skip header
                    for row in reader:
                        writer.writerow(row)
                        total_rows += 1
            except Exception as e:
                logging.warning(f"Failed to read chunk file {chunk_file}: {e}")
                continue

    return total_rows


def preprocess_data(
    input_path: Path,
    output_path: Path,
    extensions: List[str] = [".py"],
    num_processes: int = None,
    chunk_size: int = 100,
    use_parallel: bool = True,
    timeout_minutes: int = 120,
    label: str = None,
) -> None:
    """
    Preprocess source files for malwi training pipeline with proper resource management.
    """
    # Collect files
    info(f"🔍 Collecting files from {input_path}...")
    files = []
    for ext in extensions:
        # Filter to only include actual files, not directories
        pattern_matches = input_path.rglob(f"*{ext}")
        files.extend([p for p in pattern_matches if p.is_file()])

    if not files:
        info("No files found to process")
        return

    info(f"Found {len(files)} files to process")

    # Determine label from path if not explicitly provided
    if label is None:
        # Try to infer label from path (e.g., ../malwi-samples/python/malicious -> "malicious")
        path_parts = input_path.parts
        for part in path_parts:
            if part in ["malicious", "benign", "suspicious", "telemetry"]:
                label = part
                break

    # Check if we should use parallel processing
    if not use_parallel or len(files) <= 10:
        info("Using sequential processing...")
        _process_sequential(files, output_path, label=label)
        return

    # Use all available CPUs by default
    if num_processes is None:
        num_processes = mp.cpu_count()

    info(f"Using parallel processing...")
    info(f"Using {num_processes} processes with {chunk_size} chunk size")

    # Group files by language
    files_by_language = {}
    for file_path in files:
        if file_path.suffix == ".py":
            lang = "python"
        elif file_path.suffix == ".js":
            lang = "javascript"
        else:
            continue

        if lang not in files_by_language:
            files_by_language[lang] = []
        files_by_language[lang].append(file_path)

    # Create small chunks for better fault tolerance
    all_chunk_tasks = []
    chunk_id = 0

    for language, lang_files in files_by_language.items():
        file_chunks = split_files_into_chunks(lang_files, chunk_size)

        for chunk_files in file_chunks:
            if chunk_files:
                all_chunk_tasks.append(
                    {
                        "files": chunk_files,  # Already converted to strings
                        "language": language,
                        "chunk_id": chunk_id,
                        "label": label or "",
                    }
                )
                chunk_id += 1

    if not all_chunk_tasks:
        print("No valid chunks to process")
        return

    info(f"Created {len(all_chunk_tasks)} processing tasks")
    total_input_files = sum(len(task["files"]) for task in all_chunk_tasks)
    info(f"Total files to process: {total_input_files}")

    # Process chunks with robust error handling
    with tempfile.TemporaryDirectory() as temp_dir:
        # Add temp_dir to each task
        for task in all_chunk_tasks:
            task["temp_dir"] = temp_dir

        successful_results = []
        failed_results = []

        with ProcessPoolExecutor(max_workers=num_processes) as executor:
            # Submit all tasks
            future_to_chunk = {
                executor.submit(process_file_chunk, task): task["chunk_id"]
                for task in all_chunk_tasks
            }

            progress("Processing chunks...")

            # Collect results with timeout
            timeout_seconds = timeout_minutes * 60

            with tqdm.tqdm(
                total=len(all_chunk_tasks), desc="Processing chunks"
            ) as pbar:
                try:
                    for future in as_completed(
                        future_to_chunk, timeout=timeout_seconds
                    ):
                        chunk_id = future_to_chunk[future]

                        try:
                            result = future.result(timeout=60)  # 1 minute to get result

                            if result["success"]:
                                successful_results.append(result)
                                pbar.set_postfix(
                                    processed=result["processed_count"],
                                    chunk=chunk_id,
                                    status="OK",
                                )
                            else:
                                failed_results.append(result)
                                pbar.set_postfix(chunk=chunk_id, status="FAILED")

                        except TimeoutError:
                            failed_results.append(
                                {
                                    "chunk_id": chunk_id,
                                    "success": False,
                                    "error": "Result retrieval timeout",
                                    "processed_count": 0,
                                }
                            )
                            pbar.set_postfix(chunk=chunk_id, status="TIMEOUT")

                        except Exception as e:
                            failed_results.append(
                                {
                                    "chunk_id": chunk_id,
                                    "success": False,
                                    "error": f"Future exception: {str(e)}",
                                    "processed_count": 0,
                                }
                            )
                            pbar.set_postfix(chunk=chunk_id, status="ERROR")

                        pbar.update(1)

                except TimeoutError:
                    warning(f"Overall timeout reached after {timeout_minutes} minutes")

        # Report results
        total_processed = sum(r["processed_count"] for r in successful_results)
        total_code_objects = sum(
            r.get("code_objects_count", 0) for r in successful_results
        )

        info(f"\n📊 Processing Summary:")
        info(f"   Successful chunks: {len(successful_results)}")
        info(f"   Failed chunks: {len(failed_results)}")
        info(f"   Files processed: {total_processed}")
        info(f"   Code objects: {total_code_objects}")

        if failed_results:
            warning(f"Failed chunks details:")
            for failed in failed_results[:5]:  # Show first 5 failures
                info(
                    f"   Chunk {failed['chunk_id']}: {failed.get('error', 'Unknown error')}"
                )

        # Combine successful results
        if successful_results:
            chunk_files = [r["output_file"] for r in successful_results]
            output_path.parent.mkdir(parents=True, exist_ok=True)

            total_rows = combine_csv_chunks(chunk_files, output_path)
            success(f"Output saved to: {output_path.resolve()}")
            info(f"📊 Generated {total_code_objects} code objects")
            info(f"📊 CSV rows written: {total_rows}")

            if total_code_objects != total_rows:
                warning(
                    f"Code objects ({total_code_objects}) != CSV rows ({total_rows})"
                )
        else:
            error("No successful chunks - no output generated")


def _process_sequential(
    files: List[Path], output_path: Path, label: str = None
) -> None:
    """Process files sequentially with optional label."""
    from research.csv_writer import CSVWriter

    # Create compilers
    compilers = {}
    if any(f.suffix == ".py" for f in files):
        from common.bytecode import ASTCompiler

        compilers["python"] = ASTCompiler("python")
    if any(f.suffix == ".js" for f in files):
        from common.bytecode import ASTCompiler

        compilers["javascript"] = ASTCompiler("javascript")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    csv_writer = CSVWriter(output_path)

    try:
        for file_path in tqdm.tqdm(files, desc="Processing files", unit="file"):
            # Safety check: ensure we're processing a file, not a directory
            if not file_path.is_file():
                logging.warning(f"Skipping non-file path: {file_path}")
                continue

            if file_path.suffix == ".py":
                compiler = compilers.get("python")
            elif file_path.suffix == ".js":
                compiler = compilers.get("javascript")
            else:
                continue

            if compiler:
                try:
                    code_objects = compiler.process_file(file_path)
                    csv_writer.write_code_objects(code_objects, label=label)
                except Exception as e:
                    logging.warning(f"Failed to process {file_path}: {e}")
                    continue

        csv_writer.close()
        success(f"Output saved to: {output_path.resolve()}")

    except Exception as e:
        csv_writer.close()
        raise e


def main():
    """Main entry point for preprocessing script."""
    parser = argparse.ArgumentParser(
        description="Preprocess source files for malwi training pipeline"
    )
    parser.add_argument(
        "input_path", type=Path, help="Directory containing source files"
    )
    parser.add_argument("output_path", type=Path, help="Path to save CSV output file")
    parser.add_argument(
        "--extensions", nargs="+", default=[".py"], help="File extensions to process"
    )
    parser.add_argument(
        "--num-processes",
        type=int,
        default=None,
        help="Number of parallel processes (default: CPU count)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=100,
        help="Approximate files per chunk (default: 100)",
    )
    parser.add_argument(
        "--no-parallel", action="store_true", help="Disable parallel processing"
    )

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(level=logging.WARNING)

    # Configure messaging
    configure_messaging(quiet=False)

    try:
        preprocess_data(
            input_path=args.input_path,
            output_path=args.output_path,
            extensions=args.extensions,
            num_processes=args.num_processes,
            chunk_size=args.chunk_size,
            use_parallel=not args.no_parallel,
        )

    except KeyboardInterrupt:
        warning("Processing interrupted by user")
    except Exception as e:
        error(f"Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()
