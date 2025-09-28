"""
CSV Writer module for AST to Malwicode compilation output.
"""

import csv
from pathlib import Path
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from common.malwi_object import MalwiObject


class CSVWriter:
    """Handles CSV output operations for AST to Malwicode compilation."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.file_handle = None
        self.writer = None
        self._initialize_file()

    def _initialize_file(self):
        """Initialize CSV file with headers if needed."""
        file_exists_before_open = self.file_path.is_file()
        is_empty = not file_exists_before_open or self.file_path.stat().st_size == 0

        self.file_handle = open(
            self.file_path, "a", newline="", encoding="utf-8", errors="replace"
        )
        self.writer = csv.writer(self.file_handle)

        if is_empty:
            self.writer.writerow(
                ["tokens", "hash", "language", "filepath", "label", "package"]
            )

    def write_code_objects(
        self, code_objects: List["MalwiObject"], label: str = None, package: str = None
    ) -> None:
        """Write MalwiObject data to CSV with label and package.

        Args:
            code_objects: List of MalwiObject instances
            label: Label for these objects (e.g., 'malicious', 'benign', 'suspicious', 'telemetry')
            package: Package name for grouping files from the same malware sample
        """
        for obj in code_objects:
            self.writer.writerow(
                [
                    obj.to_string(one_line=True, mapped=True),
                    obj.to_hash(),
                    obj.language,
                    obj.file_path,
                    label or "",
                    package or "",
                ]
            )

    def close(self):
        """Close the CSV file."""
        if self.file_handle:
            self.file_handle.close()
