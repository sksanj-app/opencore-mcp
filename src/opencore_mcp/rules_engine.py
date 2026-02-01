"""
Production-ready rules engine for detecting AI-generated security vulnerabilities.

This module provides a high-performance, thread-safe RuleEngine class optimized for
detecting security vulnerabilities commonly introduced by AI code generation tools.
It supports multiple languages, regex-based pattern matching with timeout protection,
and comprehensive AI risk tracking.

Features:
- Compiled regex patterns for performance
- Regex timeout protection (ReDoS prevention)
- Thread-safe operation with caching
- Structured logging and comprehensive error handling
- Indexing by language, category, and severity
- Deduplication of overlapping findings

Example:
    >>> engine = RuleEngine()
    >>> findings = engine.analyze_code(
    ...     code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    ...     language="python",
    ...     file_path="app/db.py"
    ... )
    >>> for finding in findings:
    ...     print(f"{finding.severity}: {finding.message}")
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import os
import re
import signal
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

import yaml
from pydantic import ValidationError

from opencore_mcp.models import Category, Finding, SecurityRule, Severity

# Configure structured logging
logger = logging.getLogger(__name__)


# =============================================================================
# Custom Exceptions
# =============================================================================


class RuleEngineError(Exception):
    """Base exception for all RuleEngine errors."""

    pass


class RuleLoadError(RuleEngineError):
    """Raised when rules cannot be loaded or parsed."""

    def __init__(self, message: str, language: str | None = None, path: str | None = None):
        self.language = language
        self.path = path
        super().__init__(message)


class RuleValidationError(RuleEngineError):
    """Raised when a rule fails validation against the schema."""

    def __init__(self, message: str, rule_id: str | None = None, details: dict[str, Any] | None = None):
        self.rule_id = rule_id
        self.details = details or {}
        super().__init__(message)


class PatternCompilationError(RuleEngineError):
    """Raised when a regex pattern cannot be compiled."""

    def __init__(self, message: str, rule_id: str, pattern: str):
        self.rule_id = rule_id
        self.pattern = pattern
        super().__init__(message)


class PatternTimeoutError(RuleEngineError):
    """Raised when regex matching exceeds the timeout threshold."""

    def __init__(self, message: str, rule_id: str, timeout_seconds: float):
        self.rule_id = rule_id
        self.timeout_seconds = timeout_seconds
        super().__init__(message)


class ConfigurationError(RuleEngineError):
    """Raised when configuration files are invalid or missing."""

    pass


# =============================================================================
# Internal Data Structures
# =============================================================================


@dataclass
class CompiledRule:
    """
    A security rule with its regex pattern pre-compiled for performance.

    Attributes:
        rule: The original SecurityRule with all metadata.
        compiled_pattern: Pre-compiled regex pattern for matching.
        is_multiline: Whether the pattern uses multiline matching.
    """

    rule: SecurityRule
    compiled_pattern: re.Pattern[str]
    is_multiline: bool = False


@dataclass
class RuleIndex:
    """
    Index structure for fast rule lookups by various attributes.

    Attributes:
        by_id: Rules indexed by their unique ID.
        by_language: Rules grouped by programming language.
        by_category: Rules grouped by vulnerability category.
        by_severity: Rules grouped by severity level.
    """

    by_id: dict[str, CompiledRule] = field(default_factory=dict)
    by_language: dict[str, list[CompiledRule]] = field(default_factory=dict)
    by_category: dict[Category, dict[str, list[CompiledRule]]] = field(default_factory=dict)
    by_severity: dict[Severity, dict[str, list[CompiledRule]]] = field(default_factory=dict)


@dataclass
class RulesConfig:
    """
    Global rules configuration loaded from config.yaml.

    Attributes:
        extensions: Mapping of file extensions to language names.
        default_languages: Languages to scan by default.
        severity_levels: Numeric priority for each severity level.
        fix_strategy: How to handle fixes (auto, prompt, none).
        ignored_patterns: Glob patterns for files/directories to ignore.
        max_findings_per_scan: Maximum findings to return per scan.
        scan_timeout_seconds: Maximum time for a complete scan.
    """

    extensions: dict[str, str] = field(default_factory=dict)
    default_languages: list[str] = field(default_factory=lambda: ["python", "typescript", "javascript"])
    severity_levels: dict[str, int] = field(default_factory=lambda: {"error": 1, "warning": 2, "info": 3})
    fix_strategy: str = "auto"
    ignored_patterns: list[str] = field(default_factory=list)
    max_findings_per_scan: int = 1000
    scan_timeout_seconds: int = 300


# =============================================================================
# Timeout Context Manager (ReDoS Protection)
# =============================================================================


class TimeoutException(Exception):
    """Raised when an operation times out."""

    pass


@contextmanager
def timeout_context(seconds: float) -> Iterator[None]:
    """
    Context manager for timeout protection on Unix systems.

    Uses SIGALRM for timeout. On Windows or when signals aren't available,
    the operation runs without timeout protection.

    Args:
        seconds: Maximum execution time in seconds.

    Yields:
        None

    Raises:
        TimeoutException: If the operation exceeds the timeout.

    Example:
        >>> with timeout_context(5.0):
        ...     result = expensive_operation()
    """

    def timeout_handler(signum: int, frame: Any) -> None:
        raise TimeoutException(f"Operation timed out after {seconds} seconds")

    # Only use signals on Unix systems (not available on Windows)
    if hasattr(signal, "SIGALRM"):
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        # Fallback: no timeout protection on Windows
        yield


# =============================================================================
# Helper Functions
# =============================================================================


def _normalize_severity(value: str) -> Severity:
    """
    Map a severity string to a Severity enum value.

    Args:
        value: Severity string from rule definition.

    Returns:
        Corresponding Severity enum value, defaulting to MEDIUM.
    """
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "info": Severity.LOW,
    }
    return mapping.get(value.lower(), Severity.MEDIUM) if isinstance(value, str) else Severity.MEDIUM


def _normalize_category(value: str | None) -> Category:
    """
    Map a category string to a Category enum value.

    Args:
        value: Category string from rule definition.

    Returns:
        Corresponding Category enum value, defaulting to INJECTION.
    """
    if not value:
        return Category.INJECTION
    try:
        return Category(value.lower())
    except ValueError:
        # Try to map common alternative names
        mapping = {
            "validation": Category.DATA_VALIDATION,
            "input_validation": Category.DATA_VALIDATION,
            "data-validation": Category.DATA_VALIDATION,
            "path-traversal": Category.PATH_TRAVERSAL,
            "error-handling": Category.ERROR_HANDLING,
            "cross-site-scripting": Category.XSS,
        }
        return mapping.get(value.lower(), Category.INJECTION)


def _severity_sort_key(severity: Severity) -> int:
    """Return sort key for severity (lower = more critical)."""
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    return order.get(severity, 4)


def _rules_dir_path(rules_dir: str) -> Path:
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


# =============================================================================
# RuleEngine Class
# =============================================================================


class RuleEngine:
    """
    Production-ready engine for detecting AI-generated security vulnerabilities.

    The RuleEngine loads security rules from JSON files, compiles regex patterns
    for performance, and provides thread-safe code analysis with comprehensive
    AI risk tracking.

    Attributes:
        rules_dir: Path to the directory containing rule files.
        config: Global configuration loaded from config.yaml.
        pattern_timeout: Maximum seconds for regex matching (ReDoS protection).

    Example:
        >>> # Initialize with default rules directory
        >>> engine = RuleEngine()
        >>>
        >>> # Analyze Python code
        >>> code = '''
        ... import pickle
        ... data = pickle.loads(user_input)
        ... '''
        >>> findings = engine.analyze_code(code, "python", "app/data.py")
        >>>
        >>> # Get critical findings
        >>> critical = [f for f in findings if f.severity == Severity.CRITICAL]
        >>> print(f"Found {len(critical)} critical vulnerabilities")

    Thread Safety:
        The RuleEngine is thread-safe. Multiple threads can call analyze_code()
        concurrently. Rule loading is protected by a lock.
    """

    # Default pattern timeout in seconds (ReDoS protection)
    DEFAULT_PATTERN_TIMEOUT: float = 5.0

    # Confidence score adjustments
    BASE_CONFIDENCE: float = 0.75
    SPECIFICITY_BONUS: float = 0.15
    MULTILINE_PENALTY: float = 0.05

    def __init__(
        self,
        rules_dir: str = "rules",
        pattern_timeout: float | None = None,
        auto_load: bool = True,
    ):
        """
        Initialize the RuleEngine.

        Args:
            rules_dir: Path to directory containing rule JSON files.
            pattern_timeout: Maximum seconds for regex matching (default: 5.0).
            auto_load: Whether to load all rules on initialization.

        Raises:
            ConfigurationError: If config.yaml is invalid.
            RuleLoadError: If rules cannot be loaded (when auto_load=True).

        Example:
            >>> # Standard initialization
            >>> engine = RuleEngine()
            >>>
            >>> # Custom rules directory with longer timeout
            >>> engine = RuleEngine(
            ...     rules_dir="/custom/rules",
            ...     pattern_timeout=10.0
            ... )
            >>>
            >>> # Lazy loading (rules loaded on first use)
            >>> engine = RuleEngine(auto_load=False)
        """
        self.rules_dir = _rules_dir_path(rules_dir)
        self.pattern_timeout = pattern_timeout or self.DEFAULT_PATTERN_TIMEOUT

        # Thread safety
        self._lock = threading.RLock()
        self._rules_loaded = False

        # Rule storage and indexing
        self._index = RuleIndex()
        self._compiled_rules: dict[str, list[CompiledRule]] = {}  # by language

        # Load configuration
        self.config = self._load_config()

        # Compile ignored patterns for faster matching
        self._ignored_patterns_compiled: list[re.Pattern[str]] = []
        self._compile_ignored_patterns()

        # Auto-load rules if requested
        if auto_load:
            self._load_all_rules()

        logger.info(
            "RuleEngine initialized",
            extra={
                "rules_dir": str(self.rules_dir),
                "pattern_timeout": self.pattern_timeout,
                "languages_available": list(self._compiled_rules.keys()),
            },
        )

    def _load_config(self) -> RulesConfig:
        """
        Load global configuration from config.yaml.

        Returns:
            RulesConfig with all configuration values.

        Raises:
            ConfigurationError: If config.yaml is invalid.
        """
        config_path = self.rules_dir / "config.yaml"

        if not config_path.exists():
            logger.warning(f"Config file not found at {config_path}, using defaults")
            return RulesConfig()

        try:
            with open(config_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            return RulesConfig(
                extensions=data.get("extensions", {}),
                default_languages=data.get("default_languages", ["python", "typescript", "javascript"]),
                severity_levels=data.get("severity_levels", {"error": 1, "warning": 2, "info": 3}),
                fix_strategy=data.get("fix_strategy", "auto"),
                ignored_patterns=data.get("default_config", {}).get("ignored_patterns", []),
                max_findings_per_scan=data.get("default_config", {}).get("max_findings_per_scan", 1000),
                scan_timeout_seconds=data.get("default_config", {}).get("scan_timeout_seconds", 300),
            )
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid config.yaml: {e}") from e
        except OSError as e:
            raise ConfigurationError(f"Cannot read config.yaml: {e}") from e

    def _compile_ignored_patterns(self) -> None:
        """Compile glob patterns to regex for efficient matching."""
        self._ignored_patterns_compiled = []
        for pattern in self.config.ignored_patterns:
            try:
                # Convert glob to regex
                regex_pattern = fnmatch.translate(pattern)
                self._ignored_patterns_compiled.append(re.compile(regex_pattern))
            except re.error as e:
                logger.warning(f"Invalid ignore pattern '{pattern}': {e}")

    def _load_all_rules(self) -> None:
        """Load rules for all available languages."""
        with self._lock:
            if self._rules_loaded:
                return

            # Find all rule files
            if not self.rules_dir.exists():
                logger.warning(f"Rules directory does not exist: {self.rules_dir}")
                self._rules_loaded = True
                return

            for json_file in self.rules_dir.glob("*.json"):
                language = json_file.stem
                try:
                    self.load_rules(language)
                except RuleEngineError as e:
                    logger.error(f"Failed to load rules for {language}: {e}")

            self._rules_loaded = True

    def load_rules(self, language: str) -> list[SecurityRule]:
        """
        Load language-specific rules from JSON file.

        Rules are validated against the SecurityRule schema, regex patterns
        are compiled with appropriate flags, and rules are indexed for
        fast lookup.

        Args:
            language: Programming language (e.g., "python", "javascript").

        Returns:
            List of SecurityRule objects sorted by severity (CRITICAL first).

        Raises:
            RuleLoadError: If the rule file cannot be read or parsed.
            RuleValidationError: If rules fail schema validation.

        Example:
            >>> engine = RuleEngine(auto_load=False)
            >>> python_rules = engine.load_rules("python")
            >>> print(f"Loaded {len(python_rules)} Python rules")
            >>>
            >>> # Critical rules are first
            >>> for rule in python_rules[:3]:
            ...     print(f"{rule.severity}: {rule.name}")
        """
        with self._lock:
            json_path = self.rules_dir / f"{language}.json"

            if not json_path.exists():
                logger.debug(f"No rules file found for language: {language}")
                return []

            try:
                with open(json_path, encoding="utf-8") as f:
                    data = json.load(f)
            except json.JSONDecodeError as e:
                raise RuleLoadError(
                    f"Invalid JSON in {json_path}: {e}",
                    language=language,
                    path=str(json_path),
                ) from e
            except OSError as e:
                raise RuleLoadError(
                    f"Cannot read {json_path}: {e}",
                    language=language,
                    path=str(json_path),
                ) from e

            # Handle both array and object formats
            items = data if isinstance(data, list) else data.get("rules", [])

            compiled_rules: list[CompiledRule] = []
            security_rules: list[SecurityRule] = []

            for idx, item in enumerate(items):
                try:
                    # Validate and create SecurityRule
                    rule = self._validate_rule(item, language, idx)
                    if rule is None:
                        continue

                    # Compile regex pattern
                    compiled = self._compile_pattern(rule, item.get("multiline", False))
                    if compiled is None:
                        continue

                    compiled_rules.append(compiled)
                    security_rules.append(rule)

                    # Index the rule
                    self._index_rule(compiled)

                except RuleValidationError as e:
                    logger.warning(f"Skipping invalid rule at index {idx}: {e}")
                except PatternCompilationError as e:
                    logger.warning(f"Skipping rule with invalid pattern: {e}")

            # Store compiled rules by language
            self._compiled_rules[language] = compiled_rules

            # Sort by severity (CRITICAL first)
            security_rules.sort(key=lambda r: _severity_sort_key(r.severity))

            logger.info(
                f"Loaded {len(security_rules)} rules for {language}",
                extra={
                    "language": language,
                    "rule_count": len(security_rules),
                    "critical_count": sum(1 for r in security_rules if r.severity == Severity.CRITICAL),
                },
            )

            return security_rules

    def _validate_rule(self, item: dict[str, Any], language: str, index: int) -> SecurityRule | None:
        """
        Validate a rule dictionary against the SecurityRule schema.

        Args:
            item: Raw rule dictionary from JSON.
            language: Language this rule belongs to.
            index: Index in the rules array (for error messages).

        Returns:
            Validated SecurityRule or None if validation fails.

        Raises:
            RuleValidationError: If required fields are missing or invalid.
        """
        required_fields = ["id", "name", "pattern", "severity", "category"]
        missing = [f for f in required_fields if f not in item or not item[f]]

        if missing:
            raise RuleValidationError(
                f"Rule at index {index} missing required fields: {missing}",
                rule_id=item.get("id"),
                details={"missing_fields": missing},
            )

        try:
            # Map raw data to SecurityRule model
            rule = SecurityRule(
                id=item["id"],
                name=item["name"],
                description=item.get("description", ""),
                pattern=item["pattern"],
                severity=_normalize_severity(item["severity"]),
                category=_normalize_category(item.get("category")),
                message=item.get("message", item.get("description", f"Violation: {item['name']}")),
                technical_detail=item.get(
                    "technical_detail",
                    item.get("description", "Security vulnerability detected."),
                ),
                cwe=item.get("cwe", "CWE-000"),
                owasp_category=item.get("owasp_category"),
                language=language,
                ai_risk_explanation=item.get(
                    "ai_risk_explanation",
                    "AI models may generate this pattern without security context.",
                ),
                enabled=item.get("enabled", True),
                fix_template=item.get("fix_template"),
            )
            return rule
        except ValidationError as e:
            raise RuleValidationError(
                f"Rule '{item.get('id')}' failed validation: {e}",
                rule_id=item.get("id"),
                details={"validation_errors": e.errors()},
            ) from e

    def _compile_pattern(self, rule: SecurityRule, multiline: bool = False) -> CompiledRule | None:
        """
        Compile a rule's regex pattern.

        Args:
            rule: SecurityRule with pattern to compile.
            multiline: Whether to use multiline matching.

        Returns:
            CompiledRule with pre-compiled pattern or None on failure.

        Raises:
            PatternCompilationError: If the pattern is invalid regex.
        """
        flags = re.MULTILINE | re.DOTALL if multiline else re.MULTILINE

        try:
            compiled = re.compile(rule.pattern, flags)
            return CompiledRule(rule=rule, compiled_pattern=compiled, is_multiline=multiline)
        except re.error as e:
            raise PatternCompilationError(
                f"Invalid regex in rule '{rule.id}': {e}",
                rule_id=rule.id,
                pattern=rule.pattern,
            ) from e

    def _index_rule(self, compiled_rule: CompiledRule) -> None:
        """Add a compiled rule to all indexes."""
        rule = compiled_rule.rule

        # Index by ID
        self._index.by_id[rule.id] = compiled_rule

        # Index by language
        if rule.language not in self._index.by_language:
            self._index.by_language[rule.language] = []
        self._index.by_language[rule.language].append(compiled_rule)

        # Index by category
        if rule.category not in self._index.by_category:
            self._index.by_category[rule.category] = {}
        if rule.language not in self._index.by_category[rule.category]:
            self._index.by_category[rule.category][rule.language] = []
        self._index.by_category[rule.category][rule.language].append(compiled_rule)

        # Index by severity
        if rule.severity not in self._index.by_severity:
            self._index.by_severity[rule.severity] = {}
        if rule.language not in self._index.by_severity[rule.severity]:
            self._index.by_severity[rule.severity][rule.language] = []
        self._index.by_severity[rule.severity][rule.language].append(compiled_rule)

    def analyze_code(
        self,
        code: str,
        language: str,
        file_path: str = "",
    ) -> list[Finding]:
        """
        Analyze code for security vulnerabilities.

        Applies all enabled rules for the specified language, matches patterns
        with timeout protection, extracts context, generates findings with
        AI risk explanations, and deduplicates overlapping results.

        Args:
            code: Source code to analyze.
            language: Programming language (e.g., "python", "javascript").
            file_path: Optional path for context in findings.

        Returns:
            List of Finding objects sorted by severity then line number.

        Example:
            >>> engine = RuleEngine()
            >>> code = '''
            ... import os
            ... os.system(f"rm {user_input}")
            ... '''
            >>> findings = engine.analyze_code(code, "python", "cleanup.py")
            >>> for f in findings:
            ...     print(f"Line {f.line_number}: {f.message}")
            ...     print(f"AI Risk: {f.ai_generated_risk}")

        Note:
            Results are limited by config.max_findings_per_scan to prevent
            overwhelming output on highly problematic files.
        """
        if not code or not code.strip():
            return []

        # Ensure rules are loaded for this language
        if language not in self._compiled_rules:
            self.load_rules(language)

        compiled_rules = self._compiled_rules.get(language, [])
        if not compiled_rules:
            logger.debug(f"No rules available for language: {language}")
            return []

        all_findings: list[Finding] = []
        file_path = file_path or "<unknown>"

        for compiled_rule in compiled_rules:
            if not compiled_rule.rule.enabled:
                continue

            try:
                findings = self._match_pattern(code, compiled_rule, file_path)
                all_findings.extend(findings)
            except PatternTimeoutError as e:
                logger.warning(f"Pattern timeout for rule {e.rule_id}: {e}")
            except Exception as e:
                logger.error(f"Error matching rule {compiled_rule.rule.id}: {e}")

        # Deduplicate overlapping findings
        all_findings = self._deduplicate_findings(all_findings)

        # Sort by severity (CRITICAL first), then by line number
        all_findings.sort(key=lambda f: (_severity_sort_key(f.severity), f.line_number))

        # Limit results
        if len(all_findings) > self.config.max_findings_per_scan:
            logger.warning(
                f"Findings truncated from {len(all_findings)} to {self.config.max_findings_per_scan}"
            )
            all_findings = all_findings[: self.config.max_findings_per_scan]

        logger.info(
            f"Analysis complete for {file_path}",
            extra={
                "file_path": file_path,
                "language": language,
                "findings_count": len(all_findings),
                "critical_count": sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
            },
        )

        return all_findings

    def _match_pattern(
        self,
        code: str,
        compiled_rule: CompiledRule,
        file_path: str,
    ) -> list[Finding]:
        """
        Execute regex pattern matching with timeout protection.

        Args:
            code: Source code to search.
            compiled_rule: Rule with pre-compiled regex pattern.
            file_path: File path for finding context.

        Returns:
            List of findings for all pattern matches.

        Raises:
            PatternTimeoutError: If matching exceeds timeout threshold.
        """
        rule = compiled_rule.rule
        findings: list[Finding] = []

        try:
            with timeout_context(self.pattern_timeout):
                matches = list(compiled_rule.compiled_pattern.finditer(code))
        except TimeoutException:
            raise PatternTimeoutError(
                f"Pattern matching timed out after {self.pattern_timeout}s",
                rule_id=rule.id,
                timeout_seconds=self.pattern_timeout,
            )

        for match in matches:
            # Calculate line and column numbers
            line_number = self._line_number_at_pos(code, match.start())
            column_number = self._column_at_pos(code, match.start())

            # Extract code snippet with context
            snippet = self._extract_code_snippet(code, line_number, context_lines=3)

            # Calculate confidence score
            confidence = self._calculate_confidence(rule, match, compiled_rule.is_multiline)

            # Generate unique finding ID
            finding_id = self._generate_finding_id(file_path, line_number, rule.id)

            # Create Finding object
            finding = Finding(
                id=finding_id,
                rule_id=rule.id,
                severity=rule.severity,
                category=rule.category,
                file_path=file_path,
                line_number=line_number,
                column_number=column_number,
                code_snippet=snippet,
                message=rule.message,
                technical_detail=rule.technical_detail,
                cwe=rule.cwe,
                owasp_category=rule.owasp_category,
                fix_available=bool(rule.fix_template),
                confidence=confidence,
                ai_generated_risk=rule.ai_risk_explanation,
                metadata={
                    "matched_text": match.group(0)[:200],  # Limit matched text length
                    "fix_template": rule.fix_template,
                    "rule_name": rule.name,
                },
            )
            findings.append(finding)

        return findings

    def _extract_code_snippet(
        self,
        code: str,
        line_number: int,
        context_lines: int = 3,
    ) -> str:
        """
        Extract code snippet with surrounding context.

        The vulnerable line is marked with an arrow (>>>) for highlighting.

        Args:
            code: Full source code.
            line_number: 1-based line number of the vulnerability.
            context_lines: Number of lines to include before and after.

        Returns:
            Formatted code snippet with line numbers and highlighting.

        Example:
            >>> snippet = engine._extract_code_snippet(code, 42, context_lines=2)
            >>> print(snippet)
              40 | def process_data(user_input):
              41 |     query = f"SELECT * FROM users WHERE id = {user_input}"
            >>> 42 |     cursor.execute(query)
              43 |     return cursor.fetchall()
              44 |
        """
        lines = code.split("\n")
        total_lines = len(lines)

        # Calculate range (0-based indexing)
        start_line = max(0, line_number - 1 - context_lines)
        end_line = min(total_lines, line_number + context_lines)

        # Build formatted snippet
        snippet_lines = []
        max_line_num_width = len(str(end_line))

        for idx in range(start_line, end_line):
            current_line_num = idx + 1
            line_content = lines[idx] if idx < len(lines) else ""

            # Mark the vulnerable line
            prefix = ">>>" if current_line_num == line_number else "   "
            line_num_str = str(current_line_num).rjust(max_line_num_width)

            snippet_lines.append(f"{prefix} {line_num_str} | {line_content}")

        return "\n".join(snippet_lines)

    def _line_number_at_pos(self, content: str, pos: int) -> int:
        """Return 1-based line number for character position."""
        return content[:pos].count("\n") + 1

    def _column_at_pos(self, content: str, pos: int) -> int:
        """Return 1-based column number for character position."""
        last_newline = content.rfind("\n", 0, pos)
        return pos - last_newline if last_newline >= 0 else pos + 1

    def _calculate_confidence(
        self,
        rule: SecurityRule,
        match: re.Match[str],
        is_multiline: bool,
    ) -> float:
        """
        Calculate confidence score based on pattern specificity.

        Args:
            rule: The security rule that matched.
            match: The regex match object.
            is_multiline: Whether multiline matching was used.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        confidence = self.BASE_CONFIDENCE

        # More specific patterns (longer) get higher confidence
        matched_text = match.group(0)
        if len(matched_text) > 50:
            confidence += self.SPECIFICITY_BONUS
        elif len(matched_text) > 20:
            confidence += self.SPECIFICITY_BONUS / 2

        # Critical severity rules are generally more reliable
        if rule.severity == Severity.CRITICAL:
            confidence += 0.05

        # Multiline patterns are slightly less precise
        if is_multiline:
            confidence -= self.MULTILINE_PENALTY

        # Cap at 1.0
        return min(confidence, 1.0)

    def _generate_finding_id(self, file_path: str, line_number: int, rule_id: str) -> str:
        """Generate a unique, deterministic finding ID."""
        # Use hash for deterministic IDs (same finding = same ID)
        content = f"{file_path}:{line_number}:{rule_id}"
        hash_suffix = hashlib.sha256(content.encode()).hexdigest()[:8]
        return f"finding-{hash_suffix}"

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """
        Remove duplicate or overlapping findings.

        Findings with the same rule at the same line are considered duplicates.
        When duplicates exist, the one with higher confidence is kept.

        Args:
            findings: List of all findings before deduplication.

        Returns:
            Deduplicated list of findings.
        """
        seen: dict[str, Finding] = {}

        for finding in findings:
            key = f"{finding.file_path}:{finding.line_number}:{finding.rule_id}"

            if key not in seen or finding.confidence > seen[key].confidence:
                seen[key] = finding

        return list(seen.values())

    def get_rule_by_id(self, rule_id: str) -> SecurityRule | None:
        """
        Retrieve a specific rule by its ID.

        Args:
            rule_id: Unique rule identifier.

        Returns:
            SecurityRule if found, None otherwise.

        Example:
            >>> rule = engine.get_rule_by_id("sql-injection-001")
            >>> if rule:
            ...     print(f"Fix: {rule.fix_template}")
        """
        compiled_rule = self._index.by_id.get(rule_id)
        return compiled_rule.rule if compiled_rule else None

    def get_rules_by_category(
        self,
        category: Category,
        language: str,
    ) -> list[SecurityRule]:
        """
        Filter rules by category for targeted scans.

        Args:
            category: Vulnerability category to filter by.
            language: Programming language to filter by.

        Returns:
            List of SecurityRule objects matching the criteria.

        Example:
            >>> # Get all injection rules for Python
            >>> injection_rules = engine.get_rules_by_category(
            ...     Category.INJECTION, "python"
            ... )
            >>> print(f"Found {len(injection_rules)} injection rules")
        """
        category_rules = self._index.by_category.get(category, {})
        language_rules = category_rules.get(language, [])
        return [cr.rule for cr in language_rules]

    def get_rules_by_severity(
        self,
        severity: Severity,
        language: str,
    ) -> list[SecurityRule]:
        """
        Filter rules by severity level.

        Args:
            severity: Severity level to filter by.
            language: Programming language to filter by.

        Returns:
            List of SecurityRule objects matching the criteria.

        Example:
            >>> # Get all critical JavaScript rules
            >>> critical_rules = engine.get_rules_by_severity(
            ...     Severity.CRITICAL, "javascript"
            ... )
        """
        severity_rules = self._index.by_severity.get(severity, {})
        language_rules = severity_rules.get(language, [])
        return [cr.rule for cr in language_rules]

    def should_ignore_file(self, file_path: str) -> bool:
        """
        Check if a file should be ignored based on configured patterns.

        Supports glob patterns like "**/node_modules/**", "**/*.test.js".

        Args:
            file_path: Path to check against ignore patterns.

        Returns:
            True if the file should be ignored, False otherwise.

        Example:
            >>> engine.should_ignore_file("src/app.py")
            False
            >>> engine.should_ignore_file("node_modules/lodash/index.js")
            True
            >>> engine.should_ignore_file("tests/test_auth.py")
            True
        """
        # Normalize path separators
        normalized_path = file_path.replace("\\", "/")

        # Check against compiled patterns
        for pattern in self._ignored_patterns_compiled:
            if pattern.match(normalized_path):
                return True

        # Also check raw patterns with fnmatch for glob support
        for pattern in self.config.ignored_patterns:
            if fnmatch.fnmatch(normalized_path, pattern):
                return True

        return False

    def detect_language(self, file_path: str, code: str | None = None) -> str | None:
        """
        Detect programming language from file extension or content.

        Uses the LanguageDetector for robust detection with fallback to
        content analysis when extension is ambiguous or missing.

        Args:
            file_path: Path to the file.
            code: Optional code content for content-based detection.

        Returns:
            Language name or None if not recognized/supported.

        Example:
            >>> engine.detect_language("app.py")
            'python'
            >>> engine.detect_language("index.tsx")
            'typescript'
            >>> engine.detect_language("script", code="def foo(): pass")
            'python'
        """
        from opencore_mcp.language_detector import LanguageDetector, UnsupportedLanguageError

        try:
            detector = LanguageDetector(rules_dir=str(self.rules_dir))
            return detector.detect_language(file_path, code)
        except UnsupportedLanguageError:
            # Fall back to simple extension lookup for backwards compatibility
            ext = Path(file_path).suffix.lower()
            return self.config.extensions.get(ext)

    def detect_frameworks(self, code: str, language: str) -> list[str]:
        """
        Detect frameworks used in the code.

        Analyzes import patterns to identify common web frameworks and libraries.

        Args:
            code: Source code content to analyze.
            language: Programming language of the code.

        Returns:
            List of detected framework names (lowercase).

        Example:
            >>> code = "from flask import Flask\\napp = Flask(__name__)"
            >>> engine.detect_frameworks(code, "python")
            ['flask']
        """
        from opencore_mcp.language_detector import LanguageDetector

        detector = LanguageDetector(rules_dir=str(self.rules_dir))
        return detector.detect_framework(code, language)

    def get_available_languages(self) -> list[str]:
        """
        Get list of languages with loaded rules.

        Returns:
            List of language names.
        """
        return list(self._compiled_rules.keys())

    def get_stats(self) -> dict[str, Any]:
        """
        Get statistics about loaded rules.

        Returns:
            Dictionary with rule counts and categories.

        Example:
            >>> stats = engine.get_stats()
            >>> print(f"Total rules: {stats['total_rules']}")
            >>> print(f"Languages: {stats['languages']}")
        """
        total_rules = sum(len(rules) for rules in self._compiled_rules.values())

        categories: dict[str, int] = {}
        severities: dict[str, int] = {}

        for compiled_rules in self._compiled_rules.values():
            for cr in compiled_rules:
                cat = cr.rule.category.value
                sev = cr.rule.severity.value
                categories[cat] = categories.get(cat, 0) + 1
                severities[sev] = severities.get(sev, 0) + 1

        return {
            "total_rules": total_rules,
            "languages": list(self._compiled_rules.keys()),
            "rules_by_language": {lang: len(rules) for lang, rules in self._compiled_rules.items()},
            "rules_by_category": categories,
            "rules_by_severity": severities,
            "ignored_patterns": len(self.config.ignored_patterns),
        }

    def clear_cache(self) -> None:
        """
        Clear all cached rules and force reload.

        Use this if rule files have been modified and need to be reloaded.
        """
        with self._lock:
            self._compiled_rules.clear()
            self._index = RuleIndex()
            self._rules_loaded = False
            logger.info("Rule cache cleared")


# =============================================================================
# Module-level convenience functions
# =============================================================================


# Global engine instance (lazy initialization)
_global_engine: RuleEngine | None = None
_global_engine_lock = threading.Lock()


def get_engine() -> RuleEngine:
    """
    Get the global RuleEngine instance (singleton pattern).

    Returns:
        Shared RuleEngine instance.

    Example:
        >>> from opencore_mcp.rules_engine import get_engine
        >>> engine = get_engine()
        >>> findings = engine.analyze_code(code, "python")
    """
    global _global_engine
    with _global_engine_lock:
        if _global_engine is None:
            _global_engine = RuleEngine()
        return _global_engine


def analyze_code(
    code: str,
    language: str,
    file_path: str = "",
) -> list[Finding]:
    """
    Analyze code using the global RuleEngine instance.

    Convenience function for quick analysis without managing engine lifecycle.

    Args:
        code: Source code to analyze.
        language: Programming language.
        file_path: Optional file path for context.

    Returns:
        List of Finding objects.

    Example:
        >>> from opencore_mcp.rules_engine import analyze_code
        >>> findings = analyze_code(
        ...     'os.system(f"rm {user_input}")',
        ...     "python"
        ... )
    """
    return get_engine().analyze_code(code, language, file_path)


# Backwards compatibility aliases
def load_rules(language: str | None = None) -> list[SecurityRule]:
    """Load rules for a language (backwards compatibility)."""
    engine = get_engine()
    if language:
        return engine.load_rules(language)
    # Load all default languages
    all_rules: list[SecurityRule] = []
    for lang in engine.config.default_languages:
        all_rules.extend(engine.load_rules(lang))
    return all_rules


def load_config() -> RulesConfig:
    """Load rules configuration (backwards compatibility)."""
    return get_engine().config


def evaluate_rules(
    content: str,
    file_path: str | None = None,
    language: str | None = None,
) -> list[Finding]:
    """Evaluate content against rules (backwards compatibility)."""
    engine = get_engine()
    lang = language or "python"
    path = file_path or "<unknown>"
    return engine.analyze_code(content, lang, path)
