import io
import json
import yaml
import unittest

from typing import List, Dict
from pathlib import Path
from dataclasses import dataclass, field

from common.malwi_report import MalwiReport


# Mock CodeObject no longer needed after merger


@dataclass
class MockMalwiObject:
    """A simplified mock of the MalwiObject for testing purposes."""

    name: str
    file_path: str
    labels: Dict[str, float] = field(default_factory=dict)
    file_source_code: str = ""
    _code_text: str = ""
    warnings: List[str] = field(default_factory=list)
    language: str = "python"
    # Mock the merged MalwiObject properties
    byte_code: List = None
    source_code: str = ""
    location: tuple = None

    def __post_init__(self):
        # Set source_code from _code_text if provided
        if self._code_text:
            self.source_code = self._code_text
        # Mock bytecode with simple instruction for testing
        from unittest.mock import MagicMock

        mock_instruction = MagicMock()
        mock_instruction.to_string.return_value = "LOAD_CONST test"
        self.byte_code = [mock_instruction]

    def to_tokens(self, map_special_tokens: bool = True) -> List[str]:
        if "system" in self.source_code.lower():
            return [
                f"TOKEN_{self.name.upper()}",
                "SYSTEM_INTERACTION",
                "FILESYSTEM_ACCESS",
            ]
        else:
            return [f"TOKEN_{self.name.upper()}", "SAFE_TOKEN"]

    def to_token_string(self, map_special_tokens: bool = True) -> str:
        return " ".join(self.to_tokens(map_special_tokens))

    def to_hash(self) -> str:
        return f"hash_for_{self.name}"

    def to_string(
        self, mapped: bool = True, one_line: bool = True, for_hashing: bool = False
    ) -> str:
        return f"bytecode_for_{self.name}"

    @property
    def embedding_count(self) -> int:
        return 0

    def populate_source_code(self):
        """Simulate source code population."""
        # This is now handled by the merged properties and __post_init__
        pass

    def predict(self):
        pass

    def to_dict(self) -> dict:
        # Get code from merged properties like real MalwiObject
        code_display_value = (
            self.source_code or self._code_text or "<source not available>"
        )
        if "\n" in code_display_value:
            final_code_value = code_display_value.strip()
        else:
            final_code_value = code_display_value

        return {
            "path": str(self.file_path),
            "contents": [
                {
                    "name": self.name,
                    "labels": self.labels if self.labels else {},
                    "code": final_code_value,
                    "tokens": f"TOKEN_{self.name.upper()}",
                    "hash": f"hash_for_{self.name}",
                    "embedding_count": 0,  # Add missing field
                }
            ],
        }


class TestMalwiReport(unittest.TestCase):
    def setUp(self):
        """Set up common mock objects and reports for tests."""
        self.malicious_obj = MockMalwiObject(
            name="evil_func",
            file_path="/tmp/malware.py",
            labels={"malicious": 0.95},
            file_source_code="import os; os.system('rm -rf /')",
            _code_text="os.system('rm -rf /')",
        )
        self.benign_obj = MockMalwiObject(
            name="safe_func",
            file_path="/tmp/script.py",
            labels={"benign": 0.90},
            file_source_code="print('hello')",
            _code_text="print('hello')",
        )
        self.all_objects = [self.malicious_obj, self.benign_obj]

        self.malicious_report = MalwiReport(
            all_objects=self.all_objects,
            labelled_objects=[self.malicious_obj],
            threshold=0.7,
            all_files=[Path("/tmp/malware.py"), Path("/tmp/script.py")],
            skipped_files=[],
            processed_files=2,
            malicious=True,
            confidence=0.88,
            activities=["SYSTEM_CALL", "FILE_OPERATION"],
            input_path="/tmp",
            start_time="2024-01-01T12:00:00",
            duration=2.5,
            all_file_types=[".py"],
        )

        self.benign_report = MalwiReport(
            all_objects=[self.benign_obj],
            labelled_objects=[],
            threshold=0.7,
            all_files=[Path("/tmp/script.py")],
            skipped_files=[],
            processed_files=1,
            malicious=False,
            confidence=0.99,
            activities=[],
            input_path="/tmp/script.py",
            start_time="2024-01-01T12:00:00",
            duration=1.0,
            all_file_types=[".py"],
        )

    def test_generate_report_data(self):
        """Test the internal data generation logic."""
        data = self.malicious_report._generate_report_data()

        # Check input field is at top level
        self.assertEqual(data["input"], "/tmp")

        stats = data["statistics"]
        self.assertEqual(stats["total_files"], 2)
        self.assertEqual(stats["processed_objects"], 2)
        self.assertEqual(stats["malicious_objects"], 1)
        self.assertEqual(stats["start"], "2024-01-01T12:00:00")
        self.assertEqual(stats["duration"], 2.5)

        self.assertEqual(len(data["details"]), 1)
        self.assertEqual(data["details"][0]["path"], self.malicious_obj.file_path)
        self.assertEqual(
            data["details"][0]["contents"][0]["name"], self.malicious_obj.name
        )

    def test_to_report_csv_not_available(self):
        """Test that CSV report generation is no longer available."""
        # CSV generation has been removed in favor of other formats
        assert not hasattr(self.malicious_report, "to_report_csv")

    def test_to_json(self):
        """Test JSON report generation."""
        json_str = self.malicious_report.to_json()
        data = json.loads(json_str)

        self.assertEqual(data["statistics"]["malicious_objects"], 1)
        self.assertEqual(len(data["details"]), 1)
        self.assertEqual(data["details"][0]["contents"][0]["name"], "evil_func")

    def test_to_yaml(self):
        """Test YAML report generation."""
        yaml_str = self.malicious_report.to_yaml()
        data = yaml.safe_load(yaml_str)

        self.assertEqual(data["statistics"]["malicious_objects"], 1)
        self.assertEqual(len(data["details"]), 1)
        self.assertEqual(data["details"][0]["contents"][0]["name"], "evil_func")

    def test_to_demo_text_malicious(self):
        """Test the simple text output for a malicious report."""
        text = self.malicious_report.to_demo_text()
        self.assertIn("- files: 2", text)
        self.assertIn("malicious:", text)
        self.assertIn("system interaction", text)
        self.assertIn("=> 👹 malicious 0.88", text)
        self.assertIn("/tmp/malware.py", text)  # Check file path is included

    def test_to_demo_text_benign(self):
        """Test the simple text output for a benign report."""
        text = self.benign_report.to_demo_text()
        self.assertIn("- files: 1", text)
        self.assertIn("=> 🟢 good", text)

    def test_to_markdown(self):
        """Test Markdown report generation."""
        md = self.malicious_report.to_markdown()

        self.assertIn("# Malwi Report", md)
        self.assertIn("> 👹 **Malicious**: `0.88`", md)
        self.assertIn("- Malicious Objects: 1", md)

        self.assertIn("## Token Statistics", md)
        self.assertIn("- system call", md)

        self.assertIn("## /tmp/malware.py", md)
        self.assertIn("- Object: `evil_func`", md)
        self.assertIn("- Labels: 👹 malicious: `0.95`", md)
        self.assertIn("```\nos.system('rm -rf /')\n```", md)

        self.assertNotIn("## /tmp/script.py", md)
        self.assertNotIn("safe_func", md)


if __name__ == "__main__":
    unittest.main(argv=["first-arg-is-ignored"], exit=False)
