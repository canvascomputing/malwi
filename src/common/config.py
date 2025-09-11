"""Configuration constants for malwi."""

# String processing limits
STRING_MAX_LENGTH = 20  # Maximum length for preserving literal string values
STRING_REGEX_SIZE_LIMIT = (
    50000  # 50KB - Maximum size for regex-based classification to prevent timeouts
)
STRING_LARGE_PAYLOAD_THRESHOLD = (
    5000  # 5KB - Threshold for detecting large obfuscated payloads
)

# String size bucket thresholds (for strings longer than STRING_MAX_LENGTH)
STRING_SIZE_BUCKET_SMALL_MAX = 100  # Small bucket: 21-100 characters
STRING_SIZE_BUCKET_MEDIUM_MAX = 1000  # Medium bucket: 101-1000 characters
# Large bucket: >1000 characters (no upper limit)

# File size thresholds
FILE_LARGE_THRESHOLD = 500 * 1024  # 500KB - Threshold for LARGE_FILE warning
FILE_PATHOLOGICAL_THRESHOLD = (
    1024 * 1024
)  # 1MB - Threshold for PATHOLOGICAL_FILE warning

# Supported file extensions for analysis
SUPPORTED_EXTENSIONS = ["py", "js", "mjs", "cjs", "rs"]

# Language mappings based on file extensions
EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".rs": "rust",
}

# Comment prefixes for different file extensions (used in code output format)
EXTENSION_COMMENT_PREFIX = {
    ".py": "#",
    ".js": "//",
    ".mjs": "//",
    ".cjs": "//",
    ".rs": "#",
}
