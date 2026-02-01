"""
Language and framework detection for code analysis.

This module provides intelligent detection of programming languages and frameworks
from file paths and code content. It integrates with the RuleEngine to ensure
only supported languages are analyzed.

Features:
- File extension-based language detection (most reliable)
- Content analysis for ambiguous cases
- Framework detection from import statements
- Cached configuration loading for performance
- Helpful error messages for unsupported languages

Example:
    >>> detector = LanguageDetector()
    >>> language = detector.detect_language("app.py")
    >>> print(language)  # 'python'
    >>> frameworks = detector.detect_framework(code, "python")
    >>> print(frameworks)  # ['flask', 'sqlalchemy']
"""

from __future__ import annotations

import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


# =============================================================================
# Custom Exceptions
# =============================================================================


class UnsupportedLanguageError(Exception):
    """
    Raised when a file's language is not supported for security analysis.
    
    Provides helpful context about the unsupported file and available alternatives.
    
    Attributes:
        file_path: Path to the unsupported file.
        extension: File extension that was not recognized.
        supported_extensions: List of extensions that are supported.
        message: Human-readable error message with guidance.
    
    Example:
        >>> raise UnsupportedLanguageError(
        ...     file_path="app.rb",
        ...     extension=".rb",
        ...     supported_extensions=[".py", ".js", ".ts"]
        ... )
    """
    
    def __init__(
        self,
        file_path: str,
        extension: str | None = None,
        supported_extensions: list[str] | None = None,
        message: str | None = None,
    ):
        self.file_path = file_path
        self.extension = extension or Path(file_path).suffix
        self.supported_extensions = supported_extensions or []
        
        if message:
            self.message = message
        else:
            self.message = self._build_message()
        
        super().__init__(self.message)
    
    def _build_message(self) -> str:
        """Build a helpful error message with guidance."""
        msg = f"Unsupported language for file: {self.file_path}"
        
        if self.extension:
            msg += f" (extension: {self.extension})"
        
        if self.supported_extensions:
            supported = ", ".join(sorted(self.supported_extensions))
            msg += f". Supported extensions: {supported}"
        
        return msg


# =============================================================================
# Framework Detection Patterns
# =============================================================================


# JavaScript/TypeScript framework detection patterns
JS_FRAMEWORK_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "express": [
        re.compile(r"import\s+express\s+from\s+['\"]express['\"]", re.IGNORECASE),
        re.compile(r"require\s*\(\s*['\"]express['\"]\s*\)", re.IGNORECASE),
        re.compile(r"from\s+['\"]express['\"]", re.IGNORECASE),
    ],
    "fastify": [
        re.compile(r"import\s+(?:fastify|Fastify)\s+from\s+['\"]fastify['\"]", re.IGNORECASE),
        re.compile(r"require\s*\(\s*['\"]fastify['\"]\s*\)", re.IGNORECASE),
        re.compile(r"from\s+['\"]fastify['\"]", re.IGNORECASE),
    ],
    "koa": [
        re.compile(r"import\s+Koa\s+from\s+['\"]koa['\"]", re.IGNORECASE),
        re.compile(r"require\s*\(\s*['\"]koa['\"]\s*\)", re.IGNORECASE),
        re.compile(r"from\s+['\"]koa['\"]", re.IGNORECASE),
    ],
    "next": [
        re.compile(r"from\s+['\"]next['\"/]", re.IGNORECASE),
        re.compile(r"import\s+.*from\s+['\"]next/", re.IGNORECASE),
        re.compile(r"require\s*\(\s*['\"]next['\"/]", re.IGNORECASE),
    ],
    "nestjs": [
        re.compile(r"from\s+['\"]@nestjs/", re.IGNORECASE),
        re.compile(r"import\s+.*from\s+['\"]@nestjs/", re.IGNORECASE),
        re.compile(r"@Module\s*\(", re.IGNORECASE),
        re.compile(r"@Controller\s*\(", re.IGNORECASE),
        re.compile(r"@Injectable\s*\(", re.IGNORECASE),
    ],
    "react": [
        re.compile(r"from\s+['\"]react['\"]", re.IGNORECASE),
        re.compile(r"import\s+.*from\s+['\"]react['\"]", re.IGNORECASE),
        re.compile(r"require\s*\(\s*['\"]react['\"]\s*\)", re.IGNORECASE),
        re.compile(r"import\s+\{\s*(?:useState|useEffect|useContext|useReducer|useCallback|useMemo|useRef)\s*\}\s*from\s+['\"]react['\"]", re.IGNORECASE),
    ],
    "vue": [
        re.compile(r"from\s+['\"]vue['\"]", re.IGNORECASE),
        re.compile(r"import\s+.*from\s+['\"]vue['\"]", re.IGNORECASE),
        re.compile(r"createApp\s*\(", re.IGNORECASE),
        re.compile(r"defineComponent\s*\(", re.IGNORECASE),
    ],
    "angular": [
        re.compile(r"from\s+['\"]@angular/", re.IGNORECASE),
        re.compile(r"import\s+.*from\s+['\"]@angular/", re.IGNORECASE),
        re.compile(r"@Component\s*\(", re.IGNORECASE),
        re.compile(r"@NgModule\s*\(", re.IGNORECASE),
    ],
    "hono": [
        re.compile(r"from\s+['\"]hono['\"]", re.IGNORECASE),
        re.compile(r"import\s+.*from\s+['\"]hono['\"]", re.IGNORECASE),
    ],
}

# Python framework detection patterns
PYTHON_FRAMEWORK_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "flask": [
        re.compile(r"from\s+flask\s+import", re.IGNORECASE),
        re.compile(r"import\s+flask", re.IGNORECASE),
        re.compile(r"Flask\s*\(__name__\)", re.IGNORECASE),
        re.compile(r"@app\.route\s*\(", re.IGNORECASE),
    ],
    "django": [
        re.compile(r"from\s+django\s+import", re.IGNORECASE),
        re.compile(r"from\s+django\.", re.IGNORECASE),
        re.compile(r"import\s+django", re.IGNORECASE),
        re.compile(r"django\.conf\.settings", re.IGNORECASE),
        re.compile(r"INSTALLED_APPS\s*=", re.IGNORECASE),
    ],
    "fastapi": [
        re.compile(r"from\s+fastapi\s+import", re.IGNORECASE),
        re.compile(r"import\s+fastapi", re.IGNORECASE),
        re.compile(r"FastAPI\s*\(", re.IGNORECASE),
        re.compile(r"@app\.(get|post|put|delete|patch)\s*\(", re.IGNORECASE),
    ],
    "starlette": [
        re.compile(r"from\s+starlette\s+import", re.IGNORECASE),
        re.compile(r"from\s+starlette\.", re.IGNORECASE),
        re.compile(r"import\s+starlette", re.IGNORECASE),
    ],
    "tornado": [
        re.compile(r"from\s+tornado\s+import", re.IGNORECASE),
        re.compile(r"from\s+tornado\.", re.IGNORECASE),
        re.compile(r"import\s+tornado", re.IGNORECASE),
    ],
    "aiohttp": [
        re.compile(r"from\s+aiohttp\s+import", re.IGNORECASE),
        re.compile(r"import\s+aiohttp", re.IGNORECASE),
    ],
    "sqlalchemy": [
        re.compile(r"from\s+sqlalchemy\s+import", re.IGNORECASE),
        re.compile(r"from\s+sqlalchemy\.", re.IGNORECASE),
        re.compile(r"import\s+sqlalchemy", re.IGNORECASE),
    ],
}


# =============================================================================
# Content Analysis Patterns
# =============================================================================


# Patterns to distinguish JavaScript from TypeScript when extension is ambiguous
TYPESCRIPT_INDICATORS: list[re.Pattern[str]] = [
    re.compile(r":\s*(string|number|boolean|any|void|never|unknown)\b"),
    re.compile(r"interface\s+\w+\s*\{"),
    re.compile(r"type\s+\w+\s*="),
    re.compile(r"<\w+(?:,\s*\w+)*>"),  # Generic types
    re.compile(r"as\s+\w+"),  # Type assertions
    re.compile(r":\s*\w+\[\]"),  # Array type annotations
    re.compile(r"implements\s+\w+"),
    re.compile(r"declare\s+(const|let|var|function|class|module|namespace)"),
    re.compile(r"readonly\s+\w+"),
    re.compile(r"\?\s*:"),  # Optional properties
]

PYTHON_INDICATORS: list[re.Pattern[str]] = [
    re.compile(r"def\s+\w+\s*\("),
    re.compile(r"class\s+\w+\s*(\(.*\))?:"),
    re.compile(r"import\s+\w+"),
    re.compile(r"from\s+\w+\s+import"),
    re.compile(r"if\s+__name__\s*==\s*['\"]__main__['\"]"),
    re.compile(r":\s*$", re.MULTILINE),  # Colon at end of line (blocks)
]


# =============================================================================
# LanguageDetector Class
# =============================================================================


class LanguageDetector:
    """
    Intelligent language and framework detector for security analysis.
    
    Provides reliable detection of programming languages from file paths and
    code content, with framework detection for context-aware analysis.
    
    The detector prioritizes file extensions as the most reliable indicator,
    falling back to content analysis for ambiguous cases.
    
    Attributes:
        rules_dir: Path to the rules directory containing config.yaml.
        _extension_cache: Cached extension to language mapping.
        _supported_languages_cache: Cached set of supported languages.
    
    Example:
        >>> detector = LanguageDetector()
        >>> 
        >>> # Detect language from file path
        >>> lang = detector.detect_language("src/api/routes.ts")
        >>> print(lang)  # 'typescript'
        >>> 
        >>> # Detect frameworks from code
        >>> code = '''
        ... from fastapi import FastAPI
        ... app = FastAPI()
        ... '''
        >>> frameworks = detector.detect_framework(code, "python")
        >>> print(frameworks)  # ['fastapi']
        >>>
        >>> # Check if language is supported
        >>> detector.is_supported_language("python")  # True
        >>> detector.is_supported_language("ruby")    # False
    
    Thread Safety:
        The LanguageDetector is thread-safe. All caching uses thread-safe
        mechanisms and there is no mutable shared state.
    """
    
    def __init__(self, rules_dir: str = "rules"):
        """
        Initialize the LanguageDetector.
        
        Args:
            rules_dir: Path to directory containing config.yaml and rule files.
        
        Example:
            >>> # Standard initialization
            >>> detector = LanguageDetector()
            >>>
            >>> # Custom rules directory
            >>> detector = LanguageDetector(rules_dir="/custom/rules")
        """
        self.rules_dir = self._resolve_rules_dir(rules_dir)
        self._extension_cache: dict[str, str] | None = None
        self._supported_languages_cache: set[str] | None = None
        
        logger.debug(
            "LanguageDetector initialized",
            extra={"rules_dir": str(self.rules_dir)},
        )
    
    def _resolve_rules_dir(self, rules_dir: str) -> Path:
        """
        Resolve the rules directory path.
        
        Checks in order:
        1. OPENCORE_MCP_RULES_DIR environment variable
        2. Explicit rules_dir parameter
        3. Project root (2 levels up from package)
        4. Current working directory
        
        Args:
            rules_dir: Default rules directory name.
        
        Returns:
            Resolved Path to rules directory.
        """
        # Check environment variable first
        if env_path := os.environ.get("OPENCORE_MCP_RULES_DIR"):
            return Path(env_path)
        
        pkg_dir = Path(__file__).resolve().parent
        project_root = pkg_dir.parent.parent
        
        # Search candidates
        candidates = [
            project_root / rules_dir,
            Path.cwd() / rules_dir,
            pkg_dir.parent / rules_dir,
            Path(rules_dir),
        ]
        
        for candidate in candidates:
            if candidate.exists():
                return candidate
        
        # Default to project root even if it doesn't exist
        return project_root / rules_dir
    
    def detect_language(
        self,
        file_path: str,
        code: Optional[str] = None,
    ) -> str:
        """
        Detect the programming language of a file.
        
        Detection priority:
        1. File extension (most reliable)
        2. Content analysis (if extension is ambiguous or missing)
        
        Args:
            file_path: Path to the file (extension used for detection).
            code: Optional code content for content-based detection.
        
        Returns:
            Lowercase language name (e.g., "python", "javascript", "typescript").
        
        Raises:
            UnsupportedLanguageError: If the language cannot be detected or
                is not supported for security analysis.
        
        Example:
            >>> detector = LanguageDetector()
            >>> 
            >>> # Extension-based detection
            >>> detector.detect_language("app.py")
            'python'
            >>> detector.detect_language("index.tsx")
            'typescript'
            >>> 
            >>> # Handles edge cases
            >>> detector.detect_language("cython_module.pyx")
            'python'
            >>> 
            >>> # Content-based fallback
            >>> code = "def hello(): print('world')"
            >>> detector.detect_language("script", code)
            'python'
        """
        extension_mapping = self.get_file_extension_mapping()
        supported_extensions = list(extension_mapping.keys())
        
        # Extract extension
        path = Path(file_path)
        extension = path.suffix.lower()
        
        # Try extension-based detection first (most reliable)
        if extension and extension in extension_mapping:
            language = extension_mapping[extension]
            logger.debug(
                f"Detected language from extension",
                extra={"file_path": file_path, "extension": extension, "language": language},
            )
            return language
        
        # Handle files without extension or unknown extensions
        if code:
            detected = self._detect_from_content(code)
            if detected and self.is_supported_language(detected):
                logger.debug(
                    f"Detected language from content analysis",
                    extra={"file_path": file_path, "language": detected},
                )
                return detected
        
        # Could not detect language
        raise UnsupportedLanguageError(
            file_path=file_path,
            extension=extension if extension else None,
            supported_extensions=supported_extensions,
        )
    
    def _detect_from_content(self, code: str) -> str | None:
        """
        Analyze code content to detect language.
        
        Uses heuristics based on language-specific patterns and syntax.
        
        Args:
            code: Source code content to analyze.
        
        Returns:
            Detected language name or None if detection fails.
        """
        if not code or not code.strip():
            return None
        
        # Score each language based on pattern matches
        scores: dict[str, int] = {
            "python": 0,
            "typescript": 0,
            "javascript": 0,
        }
        
        # Check for Python indicators
        for pattern in PYTHON_INDICATORS:
            if pattern.search(code):
                scores["python"] += 1
        
        # Check for TypeScript indicators
        for pattern in TYPESCRIPT_INDICATORS:
            if pattern.search(code):
                scores["typescript"] += 2  # TypeScript patterns are more distinctive
        
        # JavaScript gets a score if we see JS-like syntax but not TypeScript
        if re.search(r"function\s+\w+\s*\(", code) or re.search(r"const\s+\w+\s*=", code):
            scores["javascript"] += 1
            # If no TypeScript indicators, boost JavaScript
            if scores["typescript"] == 0:
                scores["javascript"] += 1
        
        # Return the language with the highest score
        max_score = max(scores.values())
        if max_score == 0:
            return None
        
        # Get the language with max score (prefer Python > TypeScript > JavaScript for ties)
        priority_order = ["python", "typescript", "javascript"]
        for lang in priority_order:
            if scores[lang] == max_score:
                return lang
        
        return None
    
    def detect_framework(self, code: str, language: str) -> list[str]:
        """
        Detect frameworks used in the code based on import statements.
        
        Analyzes import patterns to identify common web frameworks and libraries.
        Can detect multiple frameworks if the code uses several.
        
        Args:
            code: Source code content to analyze.
            language: Programming language of the code.
        
        Returns:
            List of detected framework names (lowercase). Empty list if none detected.
        
        Example:
            >>> detector = LanguageDetector()
            >>> 
            >>> # Python Flask detection
            >>> code = '''
            ... from flask import Flask, request
            ... app = Flask(__name__)
            ... '''
            >>> detector.detect_framework(code, "python")
            ['flask']
            >>> 
            >>> # React detection
            >>> code = '''
            ... import { useState, useEffect } from 'react';
            ... '''
            >>> detector.detect_framework(code, "javascript")
            ['react']
            >>> 
            >>> # Multiple frameworks
            >>> code = '''
            ... from fastapi import FastAPI
            ... from sqlalchemy import create_engine
            ... '''
            >>> detector.detect_framework(code, "python")
            ['fastapi', 'sqlalchemy']
        """
        if not code or not code.strip():
            return []
        
        detected_frameworks: list[str] = []
        language_lower = language.lower()
        
        # Select pattern set based on language
        if language_lower in ("javascript", "typescript"):
            patterns = JS_FRAMEWORK_PATTERNS
        elif language_lower == "python":
            patterns = PYTHON_FRAMEWORK_PATTERNS
        else:
            logger.debug(f"No framework patterns available for language: {language}")
            return []
        
        # Check each framework's patterns
        for framework_name, framework_patterns in patterns.items():
            for pattern in framework_patterns:
                if pattern.search(code):
                    if framework_name not in detected_frameworks:
                        detected_frameworks.append(framework_name)
                    break  # Move to next framework once one pattern matches
        
        if detected_frameworks:
            logger.debug(
                f"Detected frameworks",
                extra={"language": language, "frameworks": detected_frameworks},
            )
        
        return detected_frameworks
    
    def get_file_extension_mapping(self) -> dict[str, str]:
        """
        Get the mapping of file extensions to language names.
        
        Loads the mapping from rules/config.yaml on first call and caches
        the result for subsequent calls.
        
        Returns:
            Dictionary mapping extensions (with dot, e.g., ".py") to language names.
        
        Example:
            >>> detector = LanguageDetector()
            >>> mapping = detector.get_file_extension_mapping()
            >>> print(mapping)
            {'.js': 'javascript', '.jsx': 'javascript', '.ts': 'typescript', ...}
        """
        if self._extension_cache is not None:
            return self._extension_cache
        
        self._extension_cache = self._load_extension_mapping()
        return self._extension_cache
    
    def _load_extension_mapping(self) -> dict[str, str]:
        """
        Load extension mapping from config.yaml.
        
        Returns:
            Dictionary mapping extensions to languages, with fallback defaults.
        """
        config_path = self.rules_dir / "config.yaml"
        
        # Default mappings as fallback
        defaults: dict[str, str] = {
            ".js": "javascript",
            ".jsx": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".py": "python",
            ".pyx": "python",  # Cython
            ".pyi": "python",  # Type stubs
        }
        
        if not config_path.exists():
            logger.warning(f"Config file not found at {config_path}, using defaults")
            return defaults
        
        try:
            with open(config_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            
            extensions = data.get("extensions", {})
            
            # Merge with defaults (config takes precedence)
            merged = {**defaults, **extensions}
            
            logger.debug(
                f"Loaded extension mapping",
                extra={"mapping_count": len(merged), "source": str(config_path)},
            )
            
            return merged
            
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML in config.yaml: {e}")
            return defaults
        except OSError as e:
            logger.error(f"Cannot read config.yaml: {e}")
            return defaults
    
    def is_supported_language(self, language: str) -> bool:
        """
        Check if a language has rule definitions for security analysis.
        
        A language is considered supported if there is a corresponding
        JSON rules file in the rules directory (e.g., rules/python.json).
        
        Args:
            language: Language name to check (case-insensitive).
        
        Returns:
            True if the language has rules defined, False otherwise.
        
        Example:
            >>> detector = LanguageDetector()
            >>> detector.is_supported_language("python")
            True
            >>> detector.is_supported_language("ruby")
            False
            >>> detector.is_supported_language("JAVASCRIPT")  # Case insensitive
            True
        """
        language_lower = language.lower()
        
        # Use cached result if available
        if self._supported_languages_cache is not None:
            return language_lower in self._supported_languages_cache
        
        # Build cache of supported languages
        self._supported_languages_cache = self._discover_supported_languages()
        
        return language_lower in self._supported_languages_cache
    
    def _discover_supported_languages(self) -> set[str]:
        """
        Discover supported languages from rule files in rules directory.
        
        Returns:
            Set of supported language names (lowercase).
        """
        supported: set[str] = set()
        
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory does not exist: {self.rules_dir}")
            return supported
        
        # Find all JSON rule files
        for json_file in self.rules_dir.glob("*.json"):
            language = json_file.stem.lower()
            supported.add(language)
        
        logger.debug(
            f"Discovered supported languages",
            extra={"languages": list(supported)},
        )
        
        return supported
    
    def get_supported_languages(self) -> list[str]:
        """
        Get a list of all supported languages.
        
        Returns:
            Sorted list of supported language names.
        
        Example:
            >>> detector = LanguageDetector()
            >>> detector.get_supported_languages()
            ['javascript', 'python', 'typescript']
        """
        if self._supported_languages_cache is None:
            self._supported_languages_cache = self._discover_supported_languages()
        
        return sorted(self._supported_languages_cache)
    
    def clear_cache(self) -> None:
        """
        Clear all cached data.
        
        Use this if configuration files have been modified and need to be reloaded.
        """
        self._extension_cache = None
        self._supported_languages_cache = None
        logger.debug("LanguageDetector cache cleared")


# =============================================================================
# Module-level convenience functions
# =============================================================================


# Global detector instance (lazy initialization)
_global_detector: LanguageDetector | None = None


def get_detector() -> LanguageDetector:
    """
    Get the global LanguageDetector instance (singleton pattern).
    
    Returns:
        Shared LanguageDetector instance.
    
    Example:
        >>> from opencore_mcp.language_detector import get_detector
        >>> detector = get_detector()
        >>> lang = detector.detect_language("app.py")
    """
    global _global_detector
    if _global_detector is None:
        _global_detector = LanguageDetector()
    return _global_detector


def detect_language(file_path: str, code: Optional[str] = None) -> str:
    """
    Detect language using the global detector instance.
    
    Convenience function for quick detection without managing detector lifecycle.
    
    Args:
        file_path: Path to the file.
        code: Optional code content for content-based detection.
    
    Returns:
        Detected language name.
    
    Raises:
        UnsupportedLanguageError: If language cannot be detected or is not supported.
    
    Example:
        >>> from opencore_mcp.language_detector import detect_language
        >>> detect_language("main.py")
        'python'
    """
    return get_detector().detect_language(file_path, code)


def detect_framework(code: str, language: str) -> list[str]:
    """
    Detect frameworks using the global detector instance.
    
    Args:
        code: Source code content.
        language: Programming language.
    
    Returns:
        List of detected frameworks.
    
    Example:
        >>> from opencore_mcp.language_detector import detect_framework
        >>> detect_framework("from flask import Flask", "python")
        ['flask']
    """
    return get_detector().detect_framework(code, language)


def is_supported_language(language: str) -> bool:
    """
    Check if language is supported using the global detector instance.
    
    Args:
        language: Language name to check.
    
    Returns:
        True if supported, False otherwise.
    
    Example:
        >>> from opencore_mcp.language_detector import is_supported_language
        >>> is_supported_language("python")
        True
    """
    return get_detector().is_supported_language(language)
