#!/usr/bin/env python

import sys
import yaml
import json
import time
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict

from tqdm import tqdm

from common.mapping import FUNCTION_MAPPING
from common.predict_distilbert import get_model_version_string
from common.messaging import get_message_manager, file_error
from common.files import collect_files_by_extension
from common.config import EXTENSION_COMMENT_PREFIX, EXTENSION_TO_LANGUAGE
from common.malwi_object import MalwiObject, disassemble_file_ast
from malwi._version import __version__


def process_single_file(
    file_path: Path,
    maliciousness_threshold: Optional[float] = None,
) -> tuple[List[MalwiObject], List[MalwiObject]]:
    """
    Process a single file and return all objects and malicious objects.

    Args:
        file_path: Path to the file to process
        maliciousness_threshold: Threshold for classifying objects as malicious

    Returns:
        Tuple of (all_objects, malicious_objects)
    """
    try:
        source_code = file_path.read_text(encoding="utf-8", errors="replace")

        # Detect language based on file extension
        file_extension = file_path.suffix.lower()
        language = EXTENSION_TO_LANGUAGE.get(
            file_extension, "python"
        )  # Default to Python

        objects: List[MalwiObject] = disassemble_file_ast(
            source_code, file_path=str(file_path), language=language
        )

        all_objects = []
        malicious_objects = []

        for obj in objects:
            all_objects.append(obj)
            obj.predict()
            if (
                maliciousness_threshold
                and obj.maliciousness
                and obj.maliciousness > maliciousness_threshold
            ):
                malicious_objects.append(obj)

        return all_objects, malicious_objects

    except Exception as e:
        file_error(file_path, e, "processing")
        return [], []


def format_object_for_display(obj: MalwiObject, comment_prefix: str = "#") -> str:
    """
    Format a MalwiObject for display, reusing the logic from to_code_text.

    Args:
        obj: The MalwiObject to format
        comment_prefix: Comment prefix for the language (default "#")

    Returns:
        Formatted string representation of the object
    """
    output_parts = []

    # Format maliciousness score
    if obj.maliciousness is not None:
        score_text = f"Maliciousness: {obj.maliciousness:.3f}"
    else:
        score_text = "Maliciousness: not analyzed"

    # Add file path comment with embedding count info and maliciousness score
    output_parts.append(f"{comment_prefix} {'=' * 70}")
    output_parts.append(f"{comment_prefix} File: {obj.file_path}")
    output_parts.append(f"{comment_prefix} Object: {obj.name}")
    output_parts.append(f"{comment_prefix} {score_text}")
    output_parts.append(
        f"{comment_prefix} Embedding count: {obj.embedding_count} tokens"
    )

    # Add warning if it exceeds DistilBERT window
    if obj.embedding_count > 512:
        output_parts.append(
            f"{comment_prefix} ⚠️  WOULD TRIGGER DISTILBERT WINDOWING (>512 tokens)"
        )

    output_parts.append(f"{comment_prefix} {'=' * 70}")
    output_parts.append("")

    # Add the source code
    if (
        obj.source_code
        and obj.source_code.strip()
        and obj.source_code != "<source not available>"
    ):
        output_parts.append(obj.source_code)
    else:
        output_parts.append(f"{comment_prefix} <source code not available>")

    return "\n".join(output_parts)


class TriageQuitException(Exception):
    """Exception raised when user quits during triage."""

    pass


def comment_out_benign_objects(
    file_path: Path, benign_objects: List[MalwiObject]
) -> bool:
    """
    Comment out benign objects in a file using their source_code property to find matching lines.

    Args:
        file_path: Path to the file to modify
        benign_objects: Objects classified as benign that should be commented out

    Returns:
        True if successfully commented, False otherwise
    """
    if not benign_objects:
        return True

    try:
        # Read the current file content
        file_content = file_path.read_text(encoding="utf-8", errors="replace")
        lines = file_content.split("\n")
        total_lines = len(lines)

        # Get comment prefix for this file type
        file_extension = file_path.suffix.lower()
        comment_prefix = EXTENSION_COMMENT_PREFIX.get(file_extension, "#")

        # Track which lines to comment out
        lines_to_comment = set()

        for obj in benign_objects:
            # Use source_code to find matching lines to comment
            source_code = obj.source_code or obj.file_source_code
            if source_code and source_code.strip():
                # Split the source code into individual lines to match
                source_lines = [
                    line.strip() for line in source_code.split("\n") if line.strip()
                ]

                # Find lines in the file that match the source code
                for i, file_line in enumerate(lines):
                    file_line_stripped = file_line.strip()
                    if file_line_stripped and any(
                        source_line in file_line_stripped
                        or file_line_stripped in source_line
                        for source_line in source_lines
                    ):
                        lines_to_comment.add(i)

        # Apply comments to the marked lines
        if lines_to_comment:
            for i in lines_to_comment:
                if not lines[i].strip().startswith(comment_prefix):
                    lines[i] = f"{comment_prefix} {lines[i]}"

            # Write back to file
            modified_content = "\n".join(lines)
            file_path.write_text(modified_content, encoding="utf-8")
            return True

        return True

    except Exception:
        return False


def triage_malicious_objects(
    file_path: Path,
    malicious_objects: List[MalwiObject],
    all_objects: List[MalwiObject] = None,
) -> List[MalwiObject]:
    """
    Interactively review malicious objects and let user classify them.
    Files are modified based on classification: benign findings are commented out.

    Args:
        file_path: Path to the file containing the objects
        malicious_objects: List of MalwiObject instances flagged as malicious

    Returns:
        List of MalwiObject instances confirmed as malicious by the user

    Raises:
        TriageQuitException: When user selects quit option
    """
    import questionary

    triaged_objects = []
    benign_objects = []  # Track objects classified as benign for file modification

    for obj in malicious_objects:
        # Get appropriate comment prefix for the file extension
        file_extension = Path(obj.file_path).suffix.lower()
        comment_prefix = EXTENSION_COMMENT_PREFIX.get(file_extension, "#")

        # Display formatted object using the same format as --format code
        print()
        print(format_object_for_display(obj, comment_prefix))
        print()

        # Ask user to classify
        maliciousness_str = (
            f"{obj.maliciousness:.2f}" if obj.maliciousness is not None else "N/A"
        )
        classification = questionary.select(
            f"How would you classify this code (AI score: {maliciousness_str})?",
            choices=[
                "Suspicious (keep as malicious)",
                "Benign (false positive)",
                "Skip (unsure)",
                "Quit (stop triaging)",
            ],
        ).ask()

        if classification == "Suspicious (keep as malicious)":
            triaged_objects.append(obj)
        elif classification == "Benign (false positive)":
            benign_objects.append(obj)
        elif classification == "Quit (stop triaging)":
            raise TriageQuitException("User quit triage")
        # For 'Skip', we don't add to either list

    # Comment out benign findings in the file
    if benign_objects:
        comment_out_benign_objects(file_path, benign_objects)

    return triaged_objects


@dataclass
class MalwiReport:
    """Result of processing files from a path."""

    all_objects: List[MalwiObject]
    malicious_objects: List[MalwiObject]
    threshold: float
    all_files: List[Path]
    skipped_files: List[Path]
    processed_files: int
    malicious: bool
    confidence: float
    activities: List[str]
    input_path: str  # The targeted folder/file path
    start_time: str  # ISO 8601 timestamp when scan started
    duration: float  # Duration in seconds
    all_file_types: List[str]  # All file extensions found in the scanned package
    version: str = field(
        default_factory=lambda: get_model_version_string(__version__)
    )  # Malwi version with model hash

    def _generate_report_data(self) -> Dict[str, Any]:
        processed_objects_count = len(self.all_objects)

        summary_statistics = {
            "total_files": len(self.all_files),
            "skipped_files": len(self.skipped_files),
            "processed_files": len(self.all_files) - len(self.skipped_files),
            "processed_objects": processed_objects_count,
            "malicious_objects": len(self.malicious_objects),
            "start": self.start_time,
            "duration": self.duration,
            "file_types": self.all_file_types,
        }

        # Determine the result based on malicious flag and malicious objects count
        if self.malicious:
            result = "malicious"
        elif len(self.malicious_objects) > 0:
            result = "suspicious"
        else:
            result = "good"

        report_data = {
            "version": self.version,
            "input": self.input_path,
            "result": result,
            "statistics": summary_statistics,
            "details": [],
        }

        for obj in self.all_objects:
            is_malicious = (
                obj.maliciousness is not None and obj.maliciousness > self.threshold
            )

            if is_malicious:
                report_data["details"].append(obj.to_dict())

        return report_data

    def to_json(self) -> str:
        report_data = self._generate_report_data()
        return json.dumps(report_data, indent=4)

    def to_yaml(self) -> str:
        report_data = self._generate_report_data()
        return yaml.dump(
            report_data, sort_keys=False, width=float("inf"), default_flow_style=False
        )

    def to_demo_text(self) -> str:
        report_data = self._generate_report_data()
        stats = report_data["statistics"]
        result = report_data["result"]

        # Calculate file types for processed and skipped files
        processed_files = [f for f in self.all_files if f not in self.skipped_files]
        processed_types = list(
            set(f.suffix.lower() for f in processed_files if f.suffix)
        )
        skipped_types = list(
            set(f.suffix.lower() for f in self.skipped_files if f.suffix)
        )
        processed_types.sort()
        skipped_types.sort()

        # Format file type strings
        processed_types_str = (
            f" ({', '.join(processed_types)})" if processed_types else ""
        )
        skipped_types_str = f" ({', '.join(skipped_types)})" if skipped_types else ""

        txt = f"- target: {report_data['input']}\n"
        txt += f"- seconds: {stats['duration']:.2f}\n"
        txt += f"- files: {stats['total_files']}\n"
        txt += f"  ├── scanned: {stats['processed_files']}{processed_types_str}\n"

        if result == "malicious" or result == "suspicious":
            txt += f"  ├── skipped: {stats['skipped_files']}{skipped_types_str}\n"
            txt += "  └── suspicious:\n"

            # Group malicious objects by file path
            files_with_objects = {}
            for obj in self.malicious_objects:
                if obj.file_path not in files_with_objects:
                    files_with_objects[obj.file_path] = []
                files_with_objects[obj.file_path].append(obj)

            malicious_files = sorted(files_with_objects.keys())
            for i, file_path in enumerate(malicious_files):
                is_last_file = i == len(malicious_files) - 1
                if is_last_file:
                    txt += f"      └── {file_path}\n"
                    file_prefix = "          "
                else:
                    txt += f"      ├── {file_path}\n"
                    file_prefix = "      │   "

                # List objects in this file
                objects_in_file = files_with_objects[file_path]
                for j, obj in enumerate(objects_in_file):
                    is_last_object = j == len(objects_in_file) - 1
                    if is_last_object:
                        txt += f"{file_prefix}└── {obj.name}\n"
                        object_prefix = file_prefix + "    "
                    else:
                        txt += f"{file_prefix}├── {obj.name}\n"
                        object_prefix = file_prefix + "│   "

                    # List activities for this object
                    if result == "malicious":
                        # Get tokens for this specific object
                        obj_tokens = obj.to_tokens(map_special_tokens=True)
                        obj_activities = []
                        # Collect tokens from all languages represented in malicious objects
                        languages_in_objects = set(
                            o.language for o in self.malicious_objects
                        )
                        all_filter_values = set()
                        for lang in languages_in_objects:
                            all_filter_values.update(
                                FUNCTION_MAPPING.get(lang, {}).values()
                            )

                        obj_activities = list(
                            set(
                                [
                                    token
                                    for token in obj_tokens
                                    if token in all_filter_values
                                ]
                            )
                        )

                        for k, activity in enumerate(obj_activities):
                            is_last_activity = k == len(obj_activities) - 1
                            if is_last_activity:
                                txt += f"{object_prefix}└── {activity.lower().replace('_', ' ')}\n"
                            else:
                                txt += f"{object_prefix}├── {activity.lower().replace('_', ' ')}\n"
        else:
            txt += f"  └── skipped: {stats['skipped_files']}{skipped_types_str}\n"

        txt += "\n"

        # Final result
        if result == "malicious":
            txt += f"=> 👹 malicious {self.confidence:.2f}\n"
        elif result == "suspicious":
            txt += f"=> ⚠️ suspicious {self.confidence:.2f}\n"
        else:  # result == "good"
            txt += "=> 🟢 good\n"

        return txt

    def to_markdown(self) -> str:
        report_data = self._generate_report_data()

        stats = report_data["statistics"]

        txt = "# Malwi Report\n\n"
        txt += f"*Generated by malwi v{self.version}*\n\n"
        txt += f"**Target:** `{report_data['input']}`\n\n"
        txt += "## Summary\n\n"
        txt += "Based on the analyzed patterns, the code is evaluated as:\n\n"

        # Use the same result classification
        result = report_data["result"]
        if result == "malicious":
            txt += f"> 👹 **Malicious**: `{self.confidence}`\n\n"
        elif result == "suspicious":
            txt += f"> ⚠️  **Suspicious**: `{self.confidence}`\n\n"
            txt += f"> *Found {stats['malicious_objects']} malicious objects but overall classification is not malicious*\n\n"
        else:  # good
            txt += f"> 🟢 **Good**: `{self.confidence}`\n\n"

        txt += f"- Files: {stats['total_files']}\n"
        txt += f"- Skipped: {stats['skipped_files']}\n"
        txt += f"- Processed Objects: {stats['processed_objects']}\n"
        txt += f"- Malicious Objects: {stats['malicious_objects']}\n\n"

        txt += "## Token Statistics\n\n"
        for activity in self.activities:
            txt += f"- {activity.lower().replace('_', ' ')}\n"
        txt += "\n"

        for file in report_data["details"]:
            txt += f"## {file['path']}\n\n"

            for object in file["contents"]:
                name = object["name"] if object["name"] else "<object>"
                score = object["score"]
                if score > self.threshold:
                    maliciousness = f"👹 `{round(score, 2)}`"
                else:
                    maliciousness = f"🟢 `{round(score, 2)}`"

                txt += f"- Object: `{name if name else 'Not defined'}`\n"
                txt += f"- Maliciousness: {maliciousness}\n\n"
                txt += "### Code\n\n"
                txt += f"```\n{object['code']}\n```\n\n"
                txt += "### Tokens\n\n"
                txt += f"```\n{object['tokens']}\n```\n"
            txt += "\n\n"

        return txt

    def to_code_text(self, include_tokens: bool = False) -> str:
        """Generate code output format: concatenated code segments grouped by extension with path comments.

        Args:
            include_tokens: If True, also include token information for each object
        """
        # Group ALL objects by file extension (not just malicious ones)
        objects_by_extension = {}
        for obj in self.all_objects:
            # Get file extension
            file_path = Path(obj.file_path)
            extension = file_path.suffix.lower()

            if extension not in objects_by_extension:
                objects_by_extension[extension] = []
            objects_by_extension[extension].append(obj)

        # Build output for each extension group
        output_parts = []

        for extension in sorted(objects_by_extension.keys()):
            if not extension:  # Skip files without extension
                continue

            objects = objects_by_extension[extension]

            # Add header for this extension group
            output_parts.append(f"{'=' * 80}")
            output_parts.append(f"# Files with extension: {extension}")
            output_parts.append(f"{'=' * 80}")
            output_parts.append("")

            # Get comment style based on extension
            comment_prefix = EXTENSION_COMMENT_PREFIX.get(
                extension, "#"
            )  # Default to hash comments

            # Process each file's objects
            for obj in objects:
                # Only show objects that have actual source code (not bytecode fallback)
                if (
                    obj.source_code
                    and obj.source_code.strip()
                    and obj.source_code != "<source not available>"
                ):
                    # Use the helper function to format the object
                    output_parts.append(format_object_for_display(obj, comment_prefix))
                    output_parts.append("")

                    # Add tokens if requested
                    if include_tokens:
                        output_parts.append(f"{comment_prefix} {'─' * 70}")
                        output_parts.append(f"{comment_prefix} TOKENS")
                        output_parts.append(f"{comment_prefix} {'─' * 70}")

                        token_string = obj.to_token_string(map_special_tokens=True)

                        # Try to get DistilBERT tokens
                        try:
                            from common.predict_distilbert import get_thread_tokenizer

                            tokenizer = get_thread_tokenizer()
                            distilbert_tokens = tokenizer.tokenize(token_string)
                            output_parts.append(
                                f"{comment_prefix} DistilBERT tokens ({len(distilbert_tokens)} tokens):"
                            )

                            # Format DistilBERT tokens with wrapping
                            token_lines = []
                            current_line = []
                            current_length = 0

                            for token in distilbert_tokens:
                                token_with_sep = (
                                    token + " | "
                                    if token != distilbert_tokens[-1]
                                    else token
                                )
                                if (
                                    current_length + len(token_with_sep) > 100
                                    and current_line
                                ):
                                    token_lines.append(" | ".join(current_line) + " |")
                                    current_line = [token]
                                    current_length = len(token)
                                else:
                                    current_line.append(token)
                                    current_length += len(token_with_sep)

                            if current_line:
                                token_lines.append(" | ".join(current_line))

                            for line in token_lines:
                                output_parts.append(f"{comment_prefix} {line}")
                        except Exception:
                            output_parts.append(
                                f"{comment_prefix} DistilBERT tokens: not available"
                            )

                        output_parts.append(f"{comment_prefix} {'─' * 70}")
                        output_parts.append("")

                    output_parts.append("")

        return "\n".join(output_parts)

    @classmethod
    def load_models_into_memory(
        cls,
        distilbert_model_path: Optional[str] = None,
        tokenizer_path: Optional[str] = None,
    ) -> None:
        """Load ML models into memory for batch processing."""
        from common.predict_distilbert import initialize_models

        initialize_models(
            model_path=distilbert_model_path,
            tokenizer_path=tokenizer_path,
        )

    @classmethod
    def create(
        cls,
        input_path,
        accepted_extensions: Optional[List[str]] = None,
        silent: bool = False,
        malicious_threshold: float = 0.7,
        on_finding: Optional[callable] = None,
        triage: bool = False,
    ) -> "MalwiReport":
        """
        Create a MalwiReport by processing files from the given input path.

        Args:
            input_path: Path to file or directory to process (str or Path object)
            accepted_extensions: List of file extensions to accept (without dots)
            silent: If True, suppress progress messages
            malicious_threshold: Threshold for classifying objects as malicious
            on_finding: Optional callback function called when malicious objects are found
                        Function signature: callback(file_path: Path, malicious_objects: List[MalwiObject])
            triage: If True, interactively review each finding before reporting

        Returns:
            MalwiReport containing analysis results
        """
        # Convert input_path to Path object if it's a string
        if isinstance(input_path, str):
            input_path = Path(input_path)
        elif not isinstance(input_path, Path):
            input_path = Path(str(input_path))

        # Track timing and timestamp
        start_time = time.time()
        start_timestamp = datetime.now().isoformat()

        # Configure messaging to respect silent mode
        msg = get_message_manager()
        msg.set_quiet(silent)

        accepted_files, skipped_files = collect_files_by_extension(
            input_path=input_path,
            accepted_extensions=accepted_extensions,
            silent=silent,
        )

        all_files = accepted_files + skipped_files

        # Extract all unique file extensions found in the package
        all_file_types = list(
            set(
                file_path.suffix.lower()
                for file_path in all_files
                if file_path.suffix  # Only include files with extensions
            )
        )
        all_file_types.sort()  # Sort for consistent ordering

        all_objects: List[MalwiObject] = []
        malicious_objects: List[MalwiObject] = []

        files_processed_count = 0

        if not accepted_files:
            duration = time.time() - start_time
            return cls(
                all_objects=[],
                malicious_objects=[],
                threshold=malicious_threshold,
                all_files=all_files,
                skipped_files=skipped_files,
                processed_files=files_processed_count,
                malicious=False,
                confidence=1.0,
                activities=[],
                input_path=str(input_path),
                start_time=start_timestamp,
                duration=duration,
                all_file_types=all_file_types,
            )

        # Configure progress bar
        tqdm_desc = (
            f"Analyzing '{input_path.name}'"
            if input_path.is_dir() and len(accepted_files) > 1
            else f"Processing '{input_path.name}'"
        )

        disable_tqdm = silent or (len(accepted_files) <= 1 and input_path.is_file())

        for file_path in tqdm(
            accepted_files,
            desc=tqdm_desc,
            unit="file",
            ncols=100,
            disable=disable_tqdm,
            leave=False,
            file=sys.stderr,  # Explicitly set stderr
            dynamic_ncols=True,  # Better terminal handling
            miniters=1,  # Force updates
            mininterval=0.1,  # Minimum update interval
        ):
            try:
                file_all_objects, file_malicious_objects = process_single_file(
                    file_path,
                    maliciousness_threshold=malicious_threshold,
                )
                all_objects.extend(file_all_objects)

                # Triage malicious findings if enabled
                if file_malicious_objects and triage:
                    try:
                        triaged_malicious_objects = triage_malicious_objects(
                            file_path, file_malicious_objects, file_all_objects
                        )
                    except TriageQuitException:
                        # User quit triage - stop processing entirely
                        break
                else:
                    triaged_malicious_objects = file_malicious_objects

                malicious_objects.extend(triaged_malicious_objects)
                files_processed_count += 1

                # Call callback if malicious objects found and callback provided
                if triaged_malicious_objects and on_finding:
                    on_finding(file_path, triaged_malicious_objects)

            except Exception as e:
                if not silent:
                    file_error(file_path, e, "critical processing")

        # Determine maliciousness based on DistilBERT predictions only
        malicious = len(malicious_objects) > 0

        # Calculate confidence based on average maliciousness score of detected objects
        if malicious_objects:
            confidence = sum(
                obj.maliciousness for obj in malicious_objects if obj.maliciousness
            ) / len(malicious_objects)
        else:
            confidence = 1.0  # High confidence for clean files

        # Generate activity list from malicious objects for reporting
        activities = []
        if malicious_objects:
            # Extract function tokens from malicious objects for activity reporting
            function_tokens = set()
            # Collect tokens from all languages represented in malicious objects
            languages_in_objects = set(obj.language for obj in malicious_objects)
            all_filter_values = set()
            for lang in languages_in_objects:
                all_filter_values.update(FUNCTION_MAPPING.get(lang, {}).values())

            for obj in malicious_objects:
                tokens = obj.to_tokens(map_special_tokens=True)
                function_tokens.update(
                    token for token in tokens if token in all_filter_values
                )
            activities = list(function_tokens)

        duration = time.time() - start_time
        return cls(
            all_objects=all_objects,
            malicious_objects=malicious_objects,
            threshold=malicious_threshold,
            all_files=all_files,
            skipped_files=skipped_files,
            processed_files=files_processed_count,
            malicious=malicious,
            confidence=confidence,
            activities=activities,
            input_path=str(input_path),
            start_time=start_timestamp,
            duration=duration,
            all_file_types=all_file_types,
        )
