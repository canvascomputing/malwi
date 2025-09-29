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
from common.messaging import get_message_manager, file_error, warning, info, progress
from common.files import collect_files_by_extension
from common.config import EXTENSION_COMMENT_PREFIX, EXTENSION_TO_LANGUAGE
from common.malwi_object import MalwiObject, disassemble_file_ast
from malwi._version import __version__


def process_single_file(
    file_path: Path,
    maliciousness_threshold: Optional[float] = None,
    cache=None,
    triage_mode: bool = False,
) -> tuple[List[MalwiObject], List[MalwiObject]]:
    """
    Process a single file and return all objects and malicious objects.

    Args:
        file_path: Path to the file to process
        maliciousness_threshold: Threshold for classifying objects as malicious
        cache: Cache instance for storing/retrieving prediction results
        triage_mode: If True, don't write to cache yet (wait for triage decision)

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
            # In triage mode, don't write to cache yet
            obj.predict(cache=cache, write_to_cache=not triage_mode)
            # Check if object has any threatening label above threshold
            if maliciousness_threshold is not None and obj.labels:
                # Only include objects with harmful labels in labelled_objects
                has_harmful_label = any(
                    confidence > maliciousness_threshold and label not in ["benign"]
                    for label, confidence in obj.labels.items()
                )

                if has_harmful_label:
                    # Check if this object was previously triaged as benign
                    if cache is not None:
                        cached_triage_decision = cache.get_cached_triage_decision(obj)
                        if cached_triage_decision == "benign":
                            # Skip objects that were previously triaged as benign (false positives)
                            continue

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

    # Format label scores
    if obj.labels:
        # Show all labels with their confidence scores
        label_parts = []
        for label, confidence in sorted(obj.labels.items(), key=lambda x: -x[1]):
            label_parts.append(f"{label}: {confidence:.3f}")
        score_text = "Labels: " + ", ".join(label_parts)
    else:
        score_text = "Labels: not analyzed"

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


def comment_out_code_sections(
    file_path: Path,
    all_objects: List[MalwiObject],
    objects_to_comment: List[MalwiObject] = None,
) -> bool:
    """
    Rewrite file by iterating through all objects and commenting out specified ones.

    Args:
        file_path: Path to the file to modify
        all_objects: All MalwiObject instances for this file
        objects_to_comment: Objects that should be commented out (defaults to all_objects for backward compatibility)

    Returns:
        True if successfully written, False otherwise
    """
    if not all_objects:
        # Write empty file if no objects provided
        try:
            file_path.write_text("", encoding="utf-8")
            return True
        except Exception:
            return False

    # For backward compatibility - if objects_to_comment not provided, use all_objects
    if objects_to_comment is None:
        objects_to_comment = all_objects

    try:
        # Get comment prefix for this file type
        file_extension = file_path.suffix.lower()
        comment_prefix = EXTENSION_COMMENT_PREFIX.get(file_extension, "#")

        # Create set of objects to comment for fast lookup
        objects_to_comment_set = set(id(obj) for obj in objects_to_comment)

        # Rewrite file by iterating through all objects
        new_content_parts = []

        for obj in all_objects:
            source_code = obj.source_code
            if not source_code:
                continue

            should_comment = id(obj) in objects_to_comment_set

            if should_comment:
                # Comment out each line
                commented_lines = []
                for line in source_code.split("\n"):
                    if line.strip():  # Non-empty line
                        if not line.strip().startswith(comment_prefix):
                            commented_lines.append(f"{comment_prefix} {line}")
                        else:
                            commented_lines.append(line)
                    else:  # Empty line
                        commented_lines.append(f"{comment_prefix}")
                new_content_parts.append("\n".join(commented_lines))
            else:
                # Keep as-is
                new_content_parts.append(source_code)

        # Write the new file content
        new_content = "\n\n".join(new_content_parts)
        file_path.write_text(new_content, encoding="utf-8")
        return True

    except Exception:
        return False


def triage_malicious_objects(
    file_path: Path,
    malicious_objects: List[MalwiObject],
    all_objects: List[MalwiObject] = None,
    triage_provider=None,
    cache=None,
    file_progress: tuple[int, int] = None,
) -> List[MalwiObject]:
    """
    Review malicious objects and let user or AI classify them.
    Files are modified based on classification: benign findings are commented out.

    Args:
        file_path: Path to the file containing the objects
        malicious_objects: List of MalwiObject instances flagged as malicious
        all_objects: List of all objects (unused, kept for compatibility)
        triage_provider: TriageProvider instance (defaults to interactive)
        cache: Cache instance for storing triaged results

    Returns:
        List of MalwiObject instances confirmed as malicious by the user/AI

    Raises:
        TriageQuitException: When user selects quit option
    """
    # Import here to avoid circular imports
    if triage_provider is None:
        from common.triage import create_triage_provider

        triage_provider = create_triage_provider(use_mcp=False)

    triaged_objects = []
    benign_objects = []  # Track objects classified as benign for file modification

    # Read file content once for all objects
    try:
        file_content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"Warning: Could not read file content: {e}")
        file_content = ""

    # Import triage constants once
    from common.triage import (
        TRIAGE_MALICIOUS,
        TRIAGE_SUSPICIOUS,
        TRIAGE_TELEMETRY,
        TRIAGE_BENIGN,
        TRIAGE_SKIP,
        TRIAGE_QUIT,
    )

    total_objects = len(malicious_objects)
    for current_index, obj in enumerate(malicious_objects, 1):
        # Check if we already have a triage decision cached for this object
        cached_decision = None
        if cache is not None:
            cached_decision = cache.get_cached_triage_decision(obj)

        if cached_decision:
            # Use cached triage decision
            classification = cached_decision
            print(f"Using cached triage decision for {obj.name}: {classification}")
        else:
            # Get appropriate comment prefix for the file extension
            file_extension = Path(obj.file_path).suffix.lower()
            comment_prefix = EXTENSION_COMMENT_PREFIX.get(file_extension, "#")

            # Display formatted object using the same format as --format code (only for interactive)
            if (
                hasattr(triage_provider, "__class__")
                and "Interactive" in triage_provider.__class__.__name__
            ):
                print()
                print(format_object_for_display(obj, comment_prefix))
                print()

            # Get classification from triage provider
            classification_successful = False
            try:
                # Use file progress if available, otherwise use object progress
                if file_progress:
                    progress = file_progress
                else:
                    progress = (current_index, total_objects)
                classification = triage_provider.classify_object(
                    obj, file_content, progress
                )
                classification_successful = True
            except Exception as e:
                print(f"Error during triage classification: {e}")
                classification = TRIAGE_SKIP

            # Only cache definitive decisions from successful user interactions (not errors, quits, or skips)
            if (
                cache is not None
                and classification_successful
                and classification != TRIAGE_QUIT
                and classification != TRIAGE_SKIP
            ):
                cache.cache_triage_decision(obj, classification)

        if classification in [TRIAGE_MALICIOUS, TRIAGE_SUSPICIOUS, TRIAGE_TELEMETRY]:
            triaged_objects.append(obj)
            # Cache the confirmed threat object labels
            if cache is not None and obj.labels:
                cache.cache_labels(obj, obj.labels)
        elif classification == TRIAGE_BENIGN:
            benign_objects.append(obj)
            # Cache the confirmed benign object labels
            if cache is not None and obj.labels:
                cache.cache_labels(obj, obj.labels)
        elif classification == TRIAGE_QUIT:
            raise TriageQuitException("User quit triage")
        # For 'Skip', we don't add to either list

    # Comment out benign findings in the file
    if benign_objects:
        comment_out_code_sections(
            file_path, all_objects or malicious_objects, benign_objects
        )

    return triaged_objects


@dataclass
class MalwiReport:
    """Result of processing files from a path."""

    all_objects: List[MalwiObject]
    labelled_objects: List[
        MalwiObject
    ]  # Objects with detected labels (previously malicious_objects)
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
    lstm_analysis: Optional[Dict] = None  # LSTM sequence analysis results if performed

    def _generate_report_data(self) -> Dict[str, Any]:
        processed_objects_count = len(self.all_objects)

        summary_statistics = {
            "total_files": len(self.all_files),
            "skipped_files": len(self.skipped_files),
            "processed_files": len(self.all_files) - len(self.skipped_files),
            "processed_objects": processed_objects_count,
            "malicious_objects": len(
                self.labelled_objects
            ),  # Keep key name for backward compatibility
            "start": self.start_time,
            "duration": self.duration,
            "file_types": self.all_file_types,
        }

        # Determine the result based on malicious flag and labelled objects count
        if self.malicious:
            result = "malicious"
        elif len(self.labelled_objects) > 0:
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

        # Add LSTM analysis if available
        if self.lstm_analysis:
            report_data["lstm_analysis"] = {
                "overall_prediction": self.lstm_analysis.get("overall", {}).get(
                    "prediction", "unknown"
                ),
                "overall_confidence": self.lstm_analysis.get("overall", {}).get(
                    "confidence", 0.0
                ),
                "files_analyzed": self.lstm_analysis.get("overall", {}).get(
                    "total_sequences", 0
                ),
                "malicious_sequences": self.lstm_analysis.get("overall", {}).get(
                    "malicious_sequences", 0
                ),
            }

        # Only show objects that are in labelled_objects (harmful labels above threshold)
        for obj in self.labelled_objects:
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

            # Group objects by category and file path
            categories_with_files = {}
            for obj in self.labelled_objects:
                if obj.labels:
                    for label, confidence in obj.labels.items():
                        if confidence > self.threshold and label != "benign":
                            if label not in categories_with_files:
                                categories_with_files[label] = {}
                            if obj.file_path not in categories_with_files[label]:
                                categories_with_files[label][obj.file_path] = []
                            categories_with_files[label][obj.file_path].append(obj)

            # Display each category as a separate tree branch
            sorted_categories = sorted(categories_with_files.keys())
            for i, category in enumerate(sorted_categories):
                is_last_category = i == len(sorted_categories) - 1
                if is_last_category:
                    txt += f"  └── {category}:\n"
                    category_prefix = "      "
                else:
                    txt += f"  ├── {category}:\n"
                    category_prefix = "  │   "

                # Display files for this category
                files_with_objects = categories_with_files[category]

                malicious_files = sorted(files_with_objects.keys())
                for j, file_path in enumerate(malicious_files):
                    is_last_file = j == len(malicious_files) - 1
                    if is_last_file:
                        txt += f"{category_prefix}└── {file_path}\n"
                        file_prefix = category_prefix + "    "
                    else:
                        txt += f"{category_prefix}├── {file_path}\n"
                        file_prefix = category_prefix + "│   "

                    # List objects in this file
                    objects_in_file = files_with_objects[file_path]
                    for k, obj in enumerate(objects_in_file):
                        is_last_object = k == len(objects_in_file) - 1
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
                            # Collect tokens from all languages represented in labelled objects
                            languages_in_objects = set(
                                o.language for o in self.labelled_objects
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

                            for l, activity in enumerate(obj_activities):
                                is_last_activity = l == len(obj_activities) - 1
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
                labels = object.get("labels", {})

                # Check if malicious label exists and is above threshold
                if "malicious" in labels and labels["malicious"] > self.threshold:
                    label_display = f"👹 malicious: `{round(labels['malicious'], 2)}`"
                else:
                    # Show highest confidence label
                    if labels:
                        top_label = max(labels.items(), key=lambda x: x[1])
                        label_display = f"🟢 {top_label[0]}: `{round(top_label[1], 2)}`"
                    else:
                        label_display = "🟢 no labels"

                txt += f"- Object: `{name if name else 'Not defined'}`\n"
                txt += f"- Labels: {label_display}\n\n"
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
        lstm_model_path: Optional[str] = None,
    ) -> None:
        """Load ML models into memory for batch processing.

        Args:
            distilbert_model_path: Path to DistilBERT model
            tokenizer_path: Path to tokenizer
            lstm_model_path: Optional path to LSTM model for sequence analysis
        """
        from common.predict_distilbert import initialize_models

        # Load DistilBERT model
        initialize_models(
            model_path=distilbert_model_path,
            tokenizer_path=tokenizer_path,
        )

        # Optionally pre-load LSTM model if path provided
        if lstm_model_path and Path(lstm_model_path).exists():
            try:
                from common.predict_lstm import initialize_lstm_model

                initialize_lstm_model(lstm_model_path)
                info(f"Pre-loaded LSTM model from {lstm_model_path}")
            except Exception as e:
                warning(f"Could not pre-load LSTM model: {e}")

    @classmethod
    def create(
        cls,
        input_path,
        accepted_extensions: Optional[List[str]] = None,
        silent: bool = False,
        malicious_threshold: float = 0.7,
        on_finding: Optional[callable] = None,
        triage: bool = False,
        triage_provider=None,
        cache=None,
        lstm_analysis: bool = False,
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
            triage_provider: TriageProvider instance for classification decisions
            cache: Cache instance for storing/retrieving prediction results
            lstm_analysis: If True, run LSTM sequence analysis on malicious findings

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
                labelled_objects=[],
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

        for file_idx, file_path in enumerate(
            tqdm(
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
            ),
            1,
        ):
            try:
                file_all_objects, file_malicious_objects = process_single_file(
                    file_path,
                    maliciousness_threshold=malicious_threshold,
                    cache=cache,
                    triage_mode=triage,
                )
                all_objects.extend(file_all_objects)

                # Triage malicious findings if enabled
                if file_malicious_objects and triage:
                    try:
                        file_progress = (file_idx, len(accepted_files))
                        triaged_malicious_objects = triage_malicious_objects(
                            file_path,
                            file_malicious_objects,
                            file_all_objects,
                            triage_provider,
                            cache,
                            file_progress=file_progress,
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

        # Calculate confidence based on average confidence score of detected objects
        if malicious_objects:
            # Get highest confidence from any malicious label
            malicious_confidences = []
            for obj in malicious_objects:
                if obj.labels and "malicious" in obj.labels:
                    malicious_confidences.append(obj.labels["malicious"])
            confidence = max(malicious_confidences) if malicious_confidences else 0.5
        else:
            confidence = 1.0  # High confidence for clean files

        # Generate activity list from labelled objects for reporting
        activities = []
        if malicious_objects:
            # Extract function tokens from labelled objects for activity reporting
            function_tokens = set()
            # Collect tokens from all languages represented in labelled objects
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

        # Run LSTM sequence analysis if requested and there are malicious findings
        lstm_results = None
        if lstm_analysis and malicious_objects:
            try:
                from common.predict_lstm import (
                    run_lstm_sequence_analysis,
                    initialize_lstm_model,
                )

                if not silent:
                    progress("Running LSTM sequence analysis...")

                # LSTM model should already be pre-loaded if path was provided
                # Only initialize if not already loaded
                from common.predict_lstm import _lstm_model

                if _lstm_model is None:
                    initialize_lstm_model()

                # Run LSTM analysis on all malicious objects
                # Objects should now have embeddings stored from DistilBERT predictions
                lstm_results = run_lstm_sequence_analysis(
                    objects=malicious_objects,
                )

                # Update confidence if LSTM provides higher confidence
                if lstm_results and "overall" in lstm_results:
                    lstm_confidence = lstm_results["overall"].get("confidence", 0.0)
                    if lstm_results["overall"]["prediction"] == "malicious":
                        # Use LSTM confidence if it's higher
                        confidence = max(confidence, lstm_confidence)
                        if not silent:
                            info(
                                f"LSTM confidence: {lstm_confidence:.2f} (using: {confidence:.2f})"
                            )
                    elif not silent:
                        # LSTM disagrees - log for informational purposes
                        warning(
                            f"LSTM prediction differs: {lstm_results['overall']['prediction']}"
                        )

            except Exception as e:
                if not silent:
                    warning(f"LSTM analysis failed: {e}")
                lstm_results = None

        duration = time.time() - start_time

        # Store LSTM results in the report if available
        report = cls(
            all_objects=all_objects,
            labelled_objects=malicious_objects,
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

        # Store LSTM results as an attribute if available
        if lstm_results:
            report.lstm_analysis = lstm_results

        return report
