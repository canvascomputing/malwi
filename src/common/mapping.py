import re
from functools import lru_cache

import socket
import urllib
import codecs
import pathlib
from enum import Enum
from packaging.version import Version, InvalidVersion
from typing import Any, Dict, Set

from .files import read_json_from_file
from .config import (
    STRING_MAX_LENGTH,
    STRING_REGEX_SIZE_LIMIT,
    STRING_LARGE_PAYLOAD_THRESHOLD,
    STRING_SIZE_BUCKET_SMALL_MAX,
    STRING_SIZE_BUCKET_MEDIUM_MAX,
)


class SpecialCases(Enum):
    # String content classifications
    STRING_SENSITIVE_FILE_PATH = (
        "STRING_SENSITIVE_FILE_PATH"  # Paths to sensitive locations (/etc, /sys, etc.)
    )
    STRING_URL = "STRING_URL"  # Valid HTTP/HTTPS URLs
    STRING_CONTAINS_URL = "STRING_CONTAINS_URL"  # Text containing URLs
    STRING_VERSION = "STRING_VERSION"  # Version strings (1.2.3, v2.0, etc.)
    STRING_ENCODING = "STRING_ENCODING"  # Character encoding names (utf-8, ascii, etc.)
    STRING_LOCALHOST = "STRING_LOCALHOST"  # Localhost references (127.0.0.1, localhost)
    STRING_FILE_PATH = "STRING_FILE_PATH"  # Generic file paths
    STRING_IP = "STRING_IP"  # IP addresses
    STRING_BASE64 = "STRING_BASE64"  # Base64 encoded content
    STRING_HEX = "STRING_HEX"  # Hexadecimal encoded content
    STRING_BASH = "STRING_BASH"  # Shell/bash command strings
    STRING_SQL = "STRING_SQL"  # SQL query strings
    STRING_CODE = "STRING_CODE"  # Code-like strings (function calls, imports)
    STRING = "STRING"  # Generic string fallback

    # String size bucket tokens (for strings >20 chars)
    STRING_SIZE_S = "STRING_SIZE_S"  # Small: 21-100 characters
    STRING_SIZE_M = "STRING_SIZE_M"  # Medium: 101-1000 characters
    STRING_SIZE_L = "STRING_SIZE_L"  # Large: >1000 characters

    # File-level classifications
    MALFORMED_FILE = "MALFORMED_FILE"  # Files with parsing/syntax errors
    MALFORMED_SYNTAX = "MALFORMED_SYNTAX"  # Files with syntax errors
    LARGE_FILE = "LARGE_FILE"  # Files exceeding size thresholds (>500KB)
    PATHOLOGICAL_FILE = "PATHOLOGICAL_FILE"  # Extremely large files (>1MB) with likely obfuscated payloads
    TARGETED_FILE = "TARGETED_FILE"  # Files matching specific targeting criteria

    # Data type classifications
    BOOLEAN = "BOOLEAN"  # Boolean values (True/False)
    INTEGER = "INTEGER"  # Integer numbers
    FLOAT = "FLOAT"  # Floating point numbers
    OBJECT = "OBJECT"  # Complex objects


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
SENSITIVE_PATHS: Set[str] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "sensitive_files.json"
)
FUNCTION_MAPPING: Dict[str, Any] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "function_mapping.json"
)
IMPORT_MAPPING: Dict[str, Any] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "import_mapping.json"
)
COMMON_TARGET_FILES: Dict[str, Set[str]] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "target_files.json"
)

# Fast, lightweight patterns for scalable code detection
# Priority: Speed over perfect accuracy for millions of files

# Pre-filters - require code-like patterns but not too restrictive
# Look for common syntactical elements that indicate code
# fmt: off
_CODE_SYNTACTICAL_ELEMENTS = frozenset({
    # Basic syntax symbols
    '(', ')', '{', '}', '[', ']', '=>', '->', '==', '!=', '&&', '||', ':', ';',
    # Programming keywords
    'return', 'import', 'function', 'def', 'class', 'print(', 'console.',
    'if ', 'for ', 'while ', 'else', 'break', 'continue',
    # HTML/XML tags
    '<html', '<body', '<div', '<script', '</',
    # Comments
    '/*', '*/',
    # Variable types
    'int ', 'var ',
})
# fmt: on

# Data exfiltration focused bash patterns for malware detection
# fmt: off
_BASH_SYNTACTICAL_ELEMENTS = frozenset({
    # Core bash syntax
    '#!/bin/', '$(' ,'${', '&&', '||', '2>&1', '|', '>>', '> ',
    'if [', 'then', 'fi', 'do', 'done', 'bash', '.sh', '$PATH',
    # Network exfiltration (primary threat)
    'curl ', 'wget ', 'nc ', 'netcat', 'ssh ', 'scp ', 'rsync ',
    # File operations for data theft  
    'cp ', 'mv ', 'rm ', 'find ', 'locate ',
    # Archive operations (compress stolen data)
    'tar ', 'gzip ', 'zip ', 'unzip ',
    # Text extraction from files
    'grep ', 'sed ', 'awk ',
    # Data encoding for obfuscation
    'base64', 'openssl',
    # Basic commands (keep for test compatibility)
    'echo ', 'ls ', 'cd ', 'cat ', 'chmod', 'sudo', 'export ',
})
# fmt: on

# SQL patterns - focus on what malware would use
# fmt: off
_SQL_SYNTACTICAL_PATTERNS = frozenset({
    # Data extraction (most common in malware)
    'SELECT ', 'FROM ', 'WHERE ',
    # Data manipulation
    'INSERT INTO', 'UPDATE ', 'SET ', 'DELETE FROM',
    # Destructive operations
    'DROP TABLE', 'DROP DATABASE', 'TRUNCATE TABLE',
    # Query modifiers and injection patterns
    'ORDER BY', 'UNION SELECT',
})
# fmt: on

# Code detection - balanced patterns to avoid false positives while catching real code
# Requires actual code structure, not just keywords
CODE_PATTERN = re.compile(
    r"("
    # Python/JS function definitions
    r"\bdef\s+\w+|\bfunction\s+\w+|\bclass\s+\w+|"
    # Lambda/arrow functions
    r"\blambda\s+.*:|\w+\s*=>|"
    # Control flow
    r"\bif\s+|\bfor\s+|\bwhile\s+|\breturn\s+|\bbreak\b|\bcontinue\b|"
    # Import statements
    r"\bimport\s+|\bfrom\s+.*\s+import|\brequire\s*\(|"
    # Variable declarations (JavaScript and C-style)
    r"\b(const|let|var|int|float|double|char|void)\s+\w+|\b(public|private)\s+|"
    # Function calls
    r"\bconsole\.\w+|\bprint\s*\(|"
    # Programming operators and C-style comments
    r"==|!=|&&|\|\||/\*[\s\S]*?\*/|//.*$|"
    # HTML/XML tags
    r"<(html|body|head|div|script|style|\?xml)[^>]*>|"
    # JSON/Object literals
    r'\{\s*["\w]+\s*:|\[\s*[\{"\d]|'
    # CSS selectors with braces
    r"\.[\w-]+\s*\{|#[\w-]+\s*\{|\w+\s*\{.*:\s*[\w#]"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

# Bash detection - balanced patterns for actual bash syntax
BASH_PATTERN = re.compile(
    r"("
    # Shebang lines
    r"^#!/(usr/)?bin/(bash|sh|zsh)|"
    # Data exfiltration and theft commands
    r"\b(curl|wget|nc|netcat|ssh|scp|rsync|cp|mv|rm|find|locate|tar|gzip|zip|unzip|grep|sed|awk|base64|openssl|echo|ls|cd|cat|chmod|sudo|export)\s+|"
    # Variable expansions including PATH
    r"\$\{\w+|\$\(|\$PATH|\$HOME|\$USER|\$\w+|"
    # Command chaining and pipes
    r"&&|\|\||\||"
    # Bash conditionals
    r"if\s+\[|\];\s*then|\bdo\b|\bdone\b|\bfi\b"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

# SQL detection - focus on SQL that malware would actually use
# Malware typically extracts data or drops tables, not complex DDL
SQL_PATTERN = re.compile(
    r"\b("
    # Data extraction (most common in malware)
    r"SELECT\s+.*\s+FROM\s+|"
    # Data modification
    r"INSERT\s+INTO\s+|"
    r"UPDATE\s+\w+\s+SET\s+|"
    r"DELETE\s+FROM\s+|"
    # Destructive operations
    r"DROP\s+(TABLE|DATABASE)\s+|"
    r"TRUNCATE\s+TABLE\s+|"
    # Common SQL clauses
    r"WHERE\s+\w+\s*=|"
    r"ORDER\s+BY\s+|"
    r"UNION\s+SELECT"  # SQL injection pattern
    r")\b",
    re.IGNORECASE,
)


def is_valid_ip(content: str) -> bool:
    if not content or "%" in content:
        return False
    try:
        socket.inet_pton(socket.AF_INET, content)
        return True
    except (socket.error, OSError):
        try:
            socket.inet_pton(socket.AF_INET6, content)
            return True
        except (socket.error, OSError):
            return False
    except Exception:
        return False


def is_version(version_string):
    """
    Checks if a given string is a valid version string according to PEP 440.
    Requires at least one dot to distinguish from simple numbers.

    Args:
        version_string (str): The string to check.

    Returns:
        bool: True if the string is a valid version, False otherwise.
    """
    # Require at least one dot to distinguish from simple numbers like "1"
    if not isinstance(version_string, str) or "." not in version_string:
        return False

    try:
        # Attempt to parse the string as a Version object.
        # If it's not a valid version, InvalidVersion will be raised.
        Version(version_string)
        return True
    except InvalidVersion:
        return False


def is_valid_encoding_name(encoding_name):
    """
    Checks if a given string is a recognized Python encoding name.

    Args:
        encoding_name (str): The string to check (e.g., 'utf-8', 'latin-1').

    Returns:
        bool: True if the encoding name is recognized, False otherwise.
    """
    try:
        # Attempt to get an encoder for the given name.
        # If the name is not recognized, a LookupError will be raised.
        codecs.lookup(encoding_name)
        return True
    except LookupError:
        return False


def is_valid_url(content: str) -> bool:
    if not content or (":" not in content and "." not in content):
        return False

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", content):
        if content.startswith(("www.", "http.", "https.")):
            content_with_scheme = "http://" + content
        else:
            return False
    else:
        content_with_scheme = content

    try:
        result = urllib.parse.urlparse(content_with_scheme)
        return bool(result.scheme and result.netloc)
    except Exception:
        return False


def is_escaped_hex(s: str) -> bool:
    pattern = re.compile(r"^(?:\\x[0-9a-fA-F]{2})+$")
    return bool(pattern.match(s))


def is_base64(s: str) -> bool:
    base64_char_pattern = re.compile(r"^[A-Za-z0-9+/]*(={0,2})$")
    if not s:
        return False
    return bool(base64_char_pattern.match(s)) and len(s) % 4 == 0


def is_hex(text: str) -> bool:
    """
    Checks if a given string is a valid hexadecimal value.

    A string is considered hexadecimal if it optionally starts with '0x',
    has an even number of characters, and contains only valid hex digits
    (0-9 and A-F, case-insensitive).

    Args:
        text (str): The input string to check.

    Returns:
        bool: True if the string is a valid hex value, False otherwise.
    """
    if not isinstance(text, str) or not text.strip():
        return False

    # Handle the optional '0x' prefix
    if text.lower().startswith("0x"):
        text = text[2:]

    # After stripping the prefix, the string can't be empty.
    if not text:
        return False

    # A hex string representing bytes must have an even number of digits.
    if len(text) % 2 != 0:
        return False

    # The most robust way to check for hex characters is to try conversion.
    try:
        # Convert the string to an integer from base 16.
        int(text, 16)
        return True
    except ValueError:
        # The conversion failed, so it's not a valid hex string.
        return False


def contains_url(text: str) -> bool:
    """Check if a string contains a URL pattern."""
    if not text or len(text) < 8:  # Minimum URL length
        return False

    # Simple pattern to detect URLs within text
    url_patterns = [
        "http://",
        "https://",
        "ftp://",
        "ftps://",
        "ssh://",
        "telnet://",
        "file://",
        "data:",
        "javascript:",
        "vbscript:",
    ]

    for pattern in url_patterns:
        if pattern in text.lower():
            return True

    return False


def is_localhost(text: str) -> bool:
    """Check if a string represents localhost or local network addresses."""
    if not text:
        return False

    text_lower = text.lower().strip()

    # Direct localhost patterns
    localhost_patterns = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "local",
        "loopback",
    ]

    # Check if text is exactly one of these patterns
    if text_lower in localhost_patterns:
        return True

    # Check for localhost with port
    if text_lower.startswith("localhost:") or text_lower.startswith("127.0.0.1:"):
        return True

    # Check for localhost in URLs
    if ("localhost" in text_lower or "127.0.0.1" in text_lower) and (
        "http" in text_lower or "ftp" in text_lower
    ):
        return True

    # Check for private network ranges (RFC 1918)
    import re

    # Match 192.168.x.x, 10.x.x.x, 172.16-31.x.x
    private_ip_patterns = [
        r"^192\.168\.\d{1,3}\.\d{1,3}",
        r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}",
    ]

    for pattern in private_ip_patterns:
        if re.match(pattern, text_lower):
            return True

    return False


def is_file_path(text: str) -> bool:
    if not text or len(text) < 2:
        return False

    # Exclude URLs and other non-file patterns first
    is_common_non_file_url = text.startswith(
        (
            "http://",
            "https://",
            "ftp://",
            "sftp://",
            "ws://",
            "wss://",
            "mailto:",
            "tel:",
            "data:",
        )
    )
    if is_common_non_file_url:
        return False

    # Check for common file extensions
    common_extensions = (
        ".py",
        ".js",
        ".txt",
        ".json",
        ".xml",
        ".html",
        ".css",
        ".java",
        ".cpp",
        ".c",
        ".h",
        ".hpp",
        ".sh",
        ".bat",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".zip",
        ".tar",
        ".gz",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".csv",
        ".log",
        ".conf",
        ".cfg",
        ".ini",
        ".yaml",
        ".yml",
        ".md",
        ".rst",
        ".tex",
        ".tmp",
        ".bak",
    )
    has_file_extension = any(text.lower().endswith(ext) for ext in common_extensions)

    # Specific file path patterns
    is_unix_like_start = text.startswith(("/", "~", "./", "../"))
    is_win_drive_start = (
        len(text) > 2
        and text[1] == ":"
        and text[0].isalpha()
        and text[2] in ("\\", "/")
    )
    is_win_unc_start = text.startswith("\\\\")

    # Must either:
    # 1. Start with a clear path pattern (absolute or relative)
    # 2. Have a file extension
    # 3. Match specific path patterns (but not generic strings with slashes)
    if is_unix_like_start or is_win_drive_start or is_win_unc_start:
        return True

    # For other cases, require both a separator and a file extension
    # or a very specific path pattern
    has_separator = "/" in text or "\\" in text
    if has_separator and has_file_extension:
        return True

    # Simple filename with extension (no path separators)
    if not has_separator and has_file_extension and "." in text:
        # Make sure it's not something like "example.com"
        # by checking it doesn't look like a domain
        if not (
            text.count(".") == 1
            and text.split(".")[1]
            in ("com", "org", "net", "edu", "gov", "io", "co", "uk")
        ):
            return True

    # Check for specific path patterns without extensions
    # (like bin paths or specific directories)
    specific_patterns = (
        "/bin/",
        "/usr/",
        "/etc/",
        "/var/",
        "/tmp/",
        "/home/",
        "/opt/",
        "/dev/",
        "/proc/",
        "/sys/",
        "C:\\Windows",
        "C:\\Program",
        "/Applications/",
        "/Library/",
        "/System/",
    )
    if any(pattern in text for pattern in specific_patterns):
        return True

    return False


def remove_newlines(text: str) -> str:
    return text.replace("\n", "").replace("\r", "")


def reduce_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def clean_string_literal(url_string):
    """
    Cleans a URL string by removing various forms of quotation marks and
    the 'f' prefix from f-string literals, ensuring matching quotes.

    Args:
        url_string (str): The input string potentially containing a URL.

    Returns:
        str: The cleaned URL string.
    """

    # --- Handle f-string literal representations ---
    # Case: f"..."
    if url_string.startswith('f"') and url_string.endswith('"'):
        # Remove 'f' and the outer double quotes
        return url_string[2:-1]  # Slice off 'f"' and '"'
    # Case: f'...'
    elif url_string.startswith("f'") and url_string.endswith("'"):
        # Remove 'f' and the outer single quotes
        return url_string[2:-1]  # Slice off "f'" and "'"
    # Case: f"""...""" (less common but possible)
    elif url_string.startswith('f"""') and url_string.endswith('"""'):
        return url_string[4:-3]  # Slice off 'f"""' and '"""'
    # Case: f'''...''' (less common but possible)
    elif url_string.startswith("f'''") and url_string.endswith("'''"):
        return url_string[4:-3]  # Slice off "f'''" and "'''"

    # --- Handle standard string literal representations (after f-string checks) ---
    # Case: "..."
    if url_string.startswith('"') and url_string.endswith('"'):
        return url_string[1:-1]
    # Case: '...'
    elif url_string.startswith("'") and url_string.endswith("'"):
        return url_string[1:-1]
    # Case: """..."""
    elif url_string.startswith('"""') and url_string.endswith('"""'):
        return url_string[3:-3]
    # Case: '''...'''
    elif url_string.startswith("'''") and url_string.endswith("'''"):
        return url_string[3:-3]

    # If no matching quotes or f-string patterns are found, return the original string
    return url_string


def map_tuple_arg(argval: tuple, original_argrepr: str) -> str:
    result = set()
    for item in argval:
        if isinstance(item, str):
            result.add(str(item))
        elif isinstance(item, int):
            result.add(SpecialCases.INTEGER.value)
        elif isinstance(item, float):
            result.add(SpecialCases.FLOAT.value)
    if not result:
        return ""
    ordered = list(result)
    ordered.sort()
    return " ".join(ordered)


@lru_cache(maxsize=8192)
def _is_bash_code_cached(text: str) -> bool:
    """
    Fast bash code detection for high-volume processing.
    Uses syntactical element pre-filter before expensive regex.
    Trades accuracy for speed - optimized for millions of files.
    """
    if not text or len(text) < 2:
        return False

    # Skip pathologically large strings that cause regex timeouts
    # These are typically obfuscated payloads, not legitimate bash code
    if len(text) > STRING_REGEX_SIZE_LIMIT:
        return False

    # Check for bash syntactical elements
    if not any(syntax in text for syntax in _BASH_SYNTACTICAL_ELEMENTS):
        return False

    # Only run expensive regex if bash syntax found
    return bool(BASH_PATTERN.search(text))


def is_bash_code(text: str, threshold: int = 3) -> bool:
    """
    Fast function to determine if text is likely bash code.
    Simplified for scalable preprocessing of large datasets.
    """
    if not isinstance(text, str):
        return False
    return _is_bash_code_cached(text)


@lru_cache(maxsize=8192)
def _is_code_cached(text: str) -> bool:
    """
    Fast code detection for high-volume processing.
    Requires BOTH keywords and syntactical elements.
    Trades accuracy for speed - optimized for millions of files.
    """
    if not text or len(text) < 3:
        return False

    # Skip pathologically large strings that cause regex timeouts
    # These are typically obfuscated payloads, not legitimate code
    if len(text) > STRING_REGEX_SIZE_LIMIT:
        return False

    # Check for code syntactical elements
    if not any(syntax in text for syntax in _CODE_SYNTACTICAL_ELEMENTS):
        return False

    # Only run expensive regex if both syntax and keywords found
    return bool(CODE_PATTERN.search(text))


def is_code(text: str, threshold: float = 0.3) -> bool:
    """
    Fast function to determine if text likely contains code.
    Simplified for scalable preprocessing of large datasets.
    """
    if not isinstance(text, str):
        return False
    return _is_code_cached(text)


@lru_cache(maxsize=8192)
def _is_sql_cached(text: str) -> bool:
    """
    Fast SQL detection for high-volume processing.
    Uses SQL pattern pre-filter before expensive regex.
    Trades accuracy for speed - optimized for millions of files.
    """
    if not text or len(text) < 6:
        return False

    # Skip pathologically large strings that cause regex timeouts
    # These are typically obfuscated payloads, not legitimate SQL
    if len(text) > STRING_REGEX_SIZE_LIMIT:
        return False

    # Check for SQL structural patterns
    text_lower = text.lower()
    if not any(pattern.lower() in text_lower for pattern in _SQL_SYNTACTICAL_PATTERNS):
        return False

    # Only run expensive regex if SQL patterns found
    return bool(SQL_PATTERN.search(text))


def is_sql(text: str) -> bool:
    """
    Fast function to determine if text contains SQL statements.
    Simplified for scalable preprocessing of large datasets.
    """
    if not isinstance(text, str):
        return False
    return _is_sql_cached(text)


@lru_cache(maxsize=8192)
def _is_large_payload_cached(text: str) -> bool:
    """
    Cached function to detect large payloads.
    Simply checks if the string is abnormally long.
    """
    # If the string is longer than threshold, it's likely an obfuscated payload
    return len(text) > STRING_LARGE_PAYLOAD_THRESHOLD


def get_string_size_bucket(text: str) -> str:
    """
    Get the appropriate size bucket token for strings longer than 20 characters.
    Returns empty string if text is 20 characters or less.

    Size buckets:
    - S (Small): 21-100 characters
    - M (Medium): 101-1000 characters
    - L (Large): >1000 characters
    """
    if not isinstance(text, str) or len(text) <= STRING_MAX_LENGTH:
        return ""

    length = len(text)
    if length <= STRING_SIZE_BUCKET_SMALL_MAX:
        return SpecialCases.STRING_SIZE_S.value
    elif length <= STRING_SIZE_BUCKET_MEDIUM_MAX:
        return SpecialCases.STRING_SIZE_M.value
    else:
        return SpecialCases.STRING_SIZE_L.value


def is_large_payload(text: str) -> bool:
    """
    Fast function to detect large payloads commonly found in malware.
    Simply checks string length - abnormally long strings are suspicious.
    """
    if not isinstance(text, str):
        return False
    return _is_large_payload_cached(text)
