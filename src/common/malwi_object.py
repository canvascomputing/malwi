#!/usr/bin/env python


import yaml
import json

import hashlib


from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict

from .mapping import (
    SpecialCases,
    FUNCTION_MAPPING,
    IMPORT_MAPPING,
    COMMON_TARGET_FILES,
)
from .config import FILE_LARGE_THRESHOLD, FILE_PATHOLOGICAL_THRESHOLD

# Import moved to avoid circular dependency and optional heavy deps
try:  # pragma: no cover - fallback when optional deps missing
    from .predict_distilbert import (
        get_node_text_prediction,
    )
except Exception:  # pragma: no cover - executed when dependency missing
    def get_node_text_prediction(*args, **kwargs):  # type: ignore
        """Fallback used when prediction dependencies are unavailable."""
        raise ImportError("predict_distilbert dependency is not installed")

from .files import read_json_from_file


SCRIPT_DIR = Path(__file__).resolve().parent

SPECIAL_TOKENS: Dict[str, Dict] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "function_mapping.json"
)


def disassemble_file_ast(
    source_code: str,
    file_path: str,
    language: str,
    target_object_name: Optional[str] = None,
) -> List["MalwiObject"]:
    """
    Language-independent implementation using AST-to-malwicode API.
    Converts CodeObject instances from the AST compiler to MalwiObject instances.
    Supports both Python and JavaScript files.
    """
    all_objects: List[MalwiObject] = []
    current_file_errors: List[str] = []

    try:
        # Import here to avoid circular dependency
        from .bytecode import ASTCompiler

        # Use the AST compiler with the detected language
        ast_compiler = ASTCompiler(language)
        malwi_objects = ast_compiler.process_file(Path(file_path))

        # ASTCompiler now returns MalwiObject instances directly
        for malwi_obj in malwi_objects:
            # Handle target filtering if specified
            if target_object_name and malwi_obj.name != target_object_name:
                continue

            # MalwiObject is already created by ASTCompiler, just add it
            all_objects.append(malwi_obj)

        if target_object_name and all_objects:
            return [all_objects[0]]  # Return only the targeted object

    except UnicodeDecodeError:
        current_file_errors.append(SpecialCases.MALFORMED_FILE.value)
    except SyntaxError:
        current_file_errors.append(SpecialCases.MALFORMED_SYNTAX.value)
    except Exception:
        current_file_errors.append(SpecialCases.MALFORMED_FILE.value)

    # If compilation failed, create an error object
    if not all_objects and current_file_errors:
        all_objects.append(
            MalwiObject(
                name=SpecialCases.MALFORMED_FILE.value,
                language=language,
                file_path=file_path,
                file_source_code=source_code,
                warnings=current_file_errors,
            )
        )

    return all_objects


class LiteralStr(str):
    pass


def literal_str_representer(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(LiteralStr, literal_str_representer)


@dataclass
class MalwiObject:
    name: str
    file_path: str
    warnings: List[str]
    file_source_code: str
    language: str
    maliciousness: Optional[float] = None
    byte_code: Optional[List] = None  # List of Instructions from AST compilation
    source_code: Optional[str] = None  # Specific source code for this object
    location: Optional[Tuple[int, int]] = None  # Start and end line numbers
    _embedding_count: Optional[int] = None  # Cached embedding count

    def __init__(
        self,
        name: str,
        language: str,
        file_path: str,
        file_source_code: str,
        byte_code: Optional[List] = None,
        source_code: Optional[str] = None,
        location: Optional[Tuple[int, int]] = None,
        warnings: List[str] = [],
    ):
        self.name = name
        self.language = language
        self.file_path = file_path
        self.warnings = list(warnings)
        self.maliciousness = None
        self.file_source_code = file_source_code
        self._embedding_count = None
        self.byte_code = byte_code
        self.source_code = source_code
        self.location = location

    @classmethod
    def all_tokens(cls, language: str = "python") -> List[str]:
        """Get all possible tokens for a language."""
        tokens = set()
        tokens.update([member.value for member in SpecialCases])
        tokens.update(FUNCTION_MAPPING.get(language, {}).values())
        tokens.update(IMPORT_MAPPING.get(language, {}).values())
        unique = list(tokens)
        unique.sort()
        return unique

    def to_tokens(self, map_special_tokens: bool = True) -> List[str]:
        """Get list of tokens from the bytecode instructions."""
        tokens = []

        # Add warnings first
        tokens.extend(self.warnings)

        # Add large file warning if applicable
        if self.file_path and Path(self.file_path).exists():
            file_size = Path(self.file_path).stat().st_size
            if file_size > FILE_LARGE_THRESHOLD:
                tokens.append(SpecialCases.LARGE_FILE.value)

            # Add pathological file warning for extremely large files
            # These often contain obfuscated payloads that cause processing timeouts
            if file_size > FILE_PATHOLOGICAL_THRESHOLD:
                tokens.append(SpecialCases.PATHOLOGICAL_FILE.value)

        # Add file targeting warning if applicable
        if self.file_path and Path(self.file_path).name in COMMON_TARGET_FILES.get(
            self.language, []
        ):
            tokens.append(SpecialCases.TARGETED_FILE.value)

        # Extract tokens from each instruction if we have bytecode
        if self.byte_code:
            for instruction in self.byte_code:
                instruction_str = instruction.to_string(
                    mapped=map_special_tokens, for_hashing=False
                )
                # Split instruction into opcode and argument tokens
                parts = instruction_str.split(" ", 1)
                tokens.append(
                    parts[0].upper()
                )  # Convert opcode to uppercase to match tokenizer vocabulary
                if len(parts) > 1 and parts[1]:
                    tokens.append(parts[1])
        else:
            # Fallback for error cases
            tokens.append(SpecialCases.MALFORMED_FILE.value)

        return tokens

    def to_token_string(self, map_special_tokens: bool = True) -> str:
        """Get space-separated token string."""
        return " ".join(self.to_tokens(map_special_tokens))

    def to_string(
        self, mapped: bool = True, one_line: bool = True, for_hashing: bool = False
    ) -> str:
        """Get bytecode representation as string."""
        instructions = []

        # Add file targeting warning if applicable
        if self.file_path and Path(self.file_path).name in COMMON_TARGET_FILES.get(
            self.language, []
        ):
            instructions.append(SpecialCases.TARGETED_FILE.value)

        # Process bytecode instructions if available
        if self.byte_code:
            for instruction in self.byte_code:
                instructions.append(
                    instruction.to_string(mapped=mapped, for_hashing=for_hashing)
                )

        return (" " if one_line else "\n").join(instructions)

    def to_hash(self) -> str:
        """Generate SHA256 hash of the bytecode representation."""
        if not self.byte_code:
            # Generate hash from token string for consistency
            token_string = self.to_token_string(map_special_tokens=True)
        else:
            token_string = self.to_string(mapped=True, for_hashing=True, one_line=True)

        encoded_string = token_string.encode("utf-8", errors="replace")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()

    @property
    def embedding_count(self) -> int:
        """
        Get the number of embeddings (tokens) this object would create when processed
        by the DistilBERT tokenizer.

        This helps identify when bytecode streams exceed DistilBERT's context window
        (typically 512 tokens), which causes windowing and can affect model performance.

        Returns:
            Number of tokens this object creates when tokenized for DistilBERT
        """
        if self._embedding_count is None:
            self._embedding_count = self._calculate_embedding_count()
        return self._embedding_count

    def _calculate_embedding_count(self) -> int:
        """Calculate embedding count by tokenizing the token string representation."""
        if not self.byte_code:
            return 0

        try:
            # Import here to avoid circular dependencies
            from .predict_distilbert import get_thread_tokenizer

            # Get the token string (same format used for prediction)
            token_string = self.to_token_string(map_special_tokens=True)

            # Use the same tokenizer that DistilBERT uses
            tokenizer = get_thread_tokenizer()

            # Tokenize without padding to get actual token count
            encoded = tokenizer(
                token_string,
                return_tensors="pt",
                padding=False,
                truncation=False,  # Don't truncate to see full size
            )

            # Return the number of tokens
            return encoded["input_ids"].shape[1]
        except (RuntimeError, ImportError, Exception):
            # Tokenizer not available or other error - return 0
            return 0

    def predict(self) -> Optional[dict]:
        # Use the merged to_token_string method which includes warnings and handles all cases
        token_string = self.to_token_string(map_special_tokens=True)
        prediction = None
        if any(
            token in token_string
            for token in SPECIAL_TOKENS.get(self.language, {}).values()
        ):
            prediction = get_node_text_prediction(token_string)
        else:
            self.maliciousness = None
        if prediction and "probabilities" in prediction:
            self.maliciousness = prediction["probabilities"][1]
        return prediction

    def to_dict(self) -> dict:
        # Get code from merged properties
        code_display_value = None
        if self.source_code:
            code_display_value = self.source_code
        elif self.byte_code:
            # Use the bytecode representation as fallback
            code_display_value = self.to_string(mapped=False, one_line=False)

        if code_display_value is None:
            code_display_value = "<source not available>"

        # Normalize line endings for better YAML display
        if isinstance(code_display_value, str):
            # Convert \r\n and \r to \n for consistent line endings
            code_display_value = code_display_value.replace("\r\n", "\n").replace(
                "\r", "\n"
            )

            if "\n" in code_display_value:
                final_code_value = LiteralStr(code_display_value.strip())
            else:
                final_code_value = code_display_value
        else:
            final_code_value = code_display_value

        # Get tokens and hash using merged methods
        token_string = self.to_token_string(map_special_tokens=True)
        content_hash = self.to_hash()

        return {
            "path": str(self.file_path),
            "contents": [
                {
                    "name": self.name,
                    "score": self.maliciousness,
                    "code": final_code_value,
                    "tokens": token_string,
                    "hash": content_hash,
                    "embedding_count": self.embedding_count,
                }
            ],
        }

    def to_yaml(self) -> str:
        return yaml.dump(
            self.to_dict(),
            sort_keys=False,
            width=float("inf"),
            default_flow_style=False,
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=4)
