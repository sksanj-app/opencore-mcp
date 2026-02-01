"""OpenCore MCP - Code analysis, fixing, and dependency management via Model Context Protocol."""

__version__ = "0.1.0"

# Language detection
from opencore_mcp.language_detector import (
    LanguageDetector,
    UnsupportedLanguageError,
    detect_framework,
    detect_language,
    get_detector,
    is_supported_language,
)

__all__ = [
    # Language detection
    "LanguageDetector",
    "UnsupportedLanguageError",
    "detect_language",
    "detect_framework",
    "is_supported_language",
    "get_detector",
]
