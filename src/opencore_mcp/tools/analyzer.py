"""
Security analysis tool for detecting AI-generated vulnerabilities.

This module provides the main MCP tool for comprehensive security analysis
of source code, with special focus on patterns commonly introduced by AI
code generation tools.

Features:
- Multi-language support (Python, JavaScript, TypeScript)
- Severity-based filtering
- Category-based grouping
- AI risk analysis and explanations
- Actionable recommendations
- Comprehensive error handling

Example:
    >>> result = await analyze_security(
    ...     file_path="src/api/users.py",
    ...     severity_threshold="medium"
    ... )
    >>> print(f"Found {result['summary']['total']} issues")
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from opencore_mcp.language_detector import (
    LanguageDetector,
    UnsupportedLanguageError,
    get_detector,
)
from opencore_mcp.models import (
    AnalysisResult,
    Category,
    Finding,
    RuleResult,
    Severity,
)
from opencore_mcp.rules_engine import (
    RuleEngine,
    RuleEngineError,
    get_engine,
    evaluate_rules,
    load_rules,
)
from opencore_mcp.tools.fixer import register_findings

# Configure structured logging
logger = logging.getLogger(__name__)

# =============================================================================
# Custom Exceptions
# =============================================================================


class FileNotFoundError(Exception):
    """Raised when the specified file cannot be found."""
    
    def __init__(self, file_path: str, message: str | None = None):
        self.file_path = file_path
        self.message = message or f"File not found: {file_path}"
        super().__init__(self.message)


class InvalidCodeError(Exception):
    """Raised when the provided code is invalid or cannot be parsed."""
    
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        self.details = details or {}
        super().__init__(message)


class AnalysisTimeoutError(Exception):
    """Raised when analysis exceeds the timeout threshold."""
    
    def __init__(self, message: str, timeout_seconds: float):
        self.timeout_seconds = timeout_seconds
        super().__init__(message)


# =============================================================================
# Global Engine Cache
# =============================================================================


_cached_engine: RuleEngine | None = None
_engine_lock = threading.Lock()


def get_cached_engine() -> RuleEngine:
    """
    Get or create a cached RuleEngine instance.
    
    Thread-safe singleton pattern for efficient reuse across requests.
    
    Returns:
        Cached RuleEngine instance.
    """
    global _cached_engine
    with _engine_lock:
        if _cached_engine is None:
            logger.info("Initializing cached RuleEngine instance")
            _cached_engine = RuleEngine()
        return _cached_engine


def clear_engine_cache() -> None:
    """Clear the cached engine instance (useful for testing or rule updates)."""
    global _cached_engine
    with _engine_lock:
        _cached_engine = None
        logger.info("RuleEngine cache cleared")


# =============================================================================
# Severity Utilities
# =============================================================================


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def severity_meets_threshold(severity: str | Severity, threshold: str) -> bool:
    """
    Check if a severity level meets the minimum threshold.
    
    Args:
        severity: Severity level to check.
        threshold: Minimum severity threshold (low, medium, high, critical).
    
    Returns:
        True if severity meets or exceeds threshold.
    """
    severity_str = severity.value if isinstance(severity, Severity) else severity.lower()
    threshold_lower = threshold.lower()
    
    severity_rank = SEVERITY_ORDER.get(severity_str, 3)
    threshold_rank = SEVERITY_ORDER.get(threshold_lower, 3)
    
    return severity_rank <= threshold_rank


def get_severity_enum(threshold: str) -> Severity:
    """Convert string severity to Severity enum."""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get(threshold.lower(), Severity.LOW)


# =============================================================================
# Main Analysis Function
# =============================================================================


async def analyze_security(
    file_path: str,
    code: Optional[str] = None,
    severity_threshold: str = "low",
) -> dict[str, Any]:
    """
    Analyze code for security vulnerabilities with AI-specific context.
    
    This is the main MCP tool for security analysis. It detects programming
    language, runs pattern-based analysis, filters by severity, groups findings
    by category, and generates actionable recommendations.
    
    Args:
        file_path: Path to the file to analyze. Used for language detection
                   and context in findings. Required even if code is provided.
        code: Optional source code content. If not provided, the file will
              be read from disk.
        severity_threshold: Minimum severity level to include in results.
                           Options: "low", "medium", "high", "critical".
                           Default: "low" (include all findings).
    
    Returns:
        Dictionary containing:
        - findings: List of security findings with full details
        - summary: Aggregated statistics by severity and category
        - scanned_file: Path to the analyzed file
        - language: Detected programming language
        - recommendations: Prioritized action items
    
    Raises:
        FileNotFoundError: If file_path doesn't exist and code not provided.
        UnsupportedLanguageError: If the language cannot be determined or
                                  is not supported for security analysis.
        InvalidCodeError: If the code content is invalid.
        AnalysisTimeoutError: If analysis exceeds timeout threshold.
    
    Example:
        >>> result = await analyze_security(
        ...     file_path="src/api/users.py",
        ...     severity_threshold="medium"
        ... )
        >>> print(result["summary"]["total"])
        12
        >>> for finding in result["findings"]:
        ...     print(f"{finding['severity']}: {finding['message']}")
    """
    start_time = time.time()
    logger.info(
        "Starting security analysis",
        extra={
            "file_path": file_path,
            "code_provided": code is not None,
            "severity_threshold": severity_threshold,
        },
    )
    
    try:
        # Step 1: Validate inputs
        code_content = await _validate_and_load_code(file_path, code)
        
        # Step 2: Detect language
        language = _detect_language(file_path, code_content)
        
        # Step 3: Initialize rule engine (cached)
        engine = get_cached_engine()
        
        # Step 4: Run comprehensive analysis
        findings = await _run_analysis(engine, code_content, language, file_path)
        
        # Step 5: Filter by severity threshold
        filtered_findings = _filter_by_severity(findings, severity_threshold)
        
        # Step 6: Group by category
        categories_grouped = _group_by_category(filtered_findings)
        
        # Step 7: Generate summary with AI context
        summary = _generate_summary(filtered_findings)
        
        # Step 8: Generate recommendations
        recommendations = _generate_recommendations(filtered_findings)
        
        # Step 9: Format findings for output
        formatted_findings = _format_findings(filtered_findings)

        # Step 10: Register findings for fix generation (generate_fix looks up by id)
        register_findings(formatted_findings)

        elapsed_ms = int((time.time() - start_time) * 1000)
        logger.info(
            "Security analysis completed",
            extra={
                "file_path": file_path,
                "language": language,
                "total_findings": len(filtered_findings),
                "critical_count": summary["critical"],
                "elapsed_ms": elapsed_ms,
            },
        )
        
        return {
            "findings": formatted_findings,
            "summary": summary,
            "scanned_file": file_path,
            "language": language,
            "recommendations": recommendations,
        }
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {file_path}")
        raise
    except UnsupportedLanguageError as e:
        logger.error(f"Unsupported language for file: {file_path}")
        # Enhance the error message with suggestions
        detector = get_detector()
        supported = detector.get_supported_languages()
        raise UnsupportedLanguageError(
            file_path=file_path,
            supported_extensions=[f".{lang[:2]}" for lang in supported],  # Simplified
            message=f"Language not supported for security analysis. "
                    f"Supported languages: {', '.join(supported)}"
        ) from e
    except asyncio.TimeoutError as e:
        logger.error(f"Analysis timeout for file: {file_path}")
        raise AnalysisTimeoutError(
            f"Analysis timed out for {file_path}. "
            "Consider breaking the file into smaller modules or reviewing patterns manually.",
            timeout_seconds=300.0,
        ) from e
    except RuleEngineError as e:
        logger.error(f"Rule engine error: {e}")
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during analysis: {e}")
        raise


async def _validate_and_load_code(
    file_path: str,
    code: Optional[str],
) -> str:
    """
    Validate inputs and load code content.
    
    Args:
        file_path: Path to the file.
        code: Optional code content.
    
    Returns:
        Code content string.
    
    Raises:
        FileNotFoundError: If file doesn't exist and code not provided.
        InvalidCodeError: If code is empty or invalid.
    """
    # If code is provided, use it
    if code is not None:
        if not code.strip():
            raise InvalidCodeError(
                "Provided code content is empty",
                details={"file_path": file_path},
            )
        logger.debug(f"Using provided code content ({len(code)} chars)")
        return code
    
    # Otherwise, try to read from file
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(
            file_path,
            f"File not found: {file_path}. "
            "Either provide the 'code' parameter or ensure the file exists."
        )
    
    if not path.is_file():
        raise FileNotFoundError(
            file_path,
            f"Path is not a file: {file_path}"
        )
    
    try:
        # File reads are fast, run synchronously
        content = path.read_text()
        logger.debug(f"Read file content ({len(content)} chars) from {file_path}")
        return content
    except OSError as e:
        raise FileNotFoundError(
            file_path,
            f"Cannot read file {file_path}: {e}"
        ) from e
    except UnicodeDecodeError as e:
        raise InvalidCodeError(
            f"Cannot decode file content (not valid text): {file_path}",
            details={"file_path": file_path, "error": str(e)},
        ) from e


def _detect_language(file_path: str, code: str) -> str:
    """
    Detect programming language from file path or content.
    
    Args:
        file_path: Path to the file.
        code: Code content for content-based detection.
    
    Returns:
        Detected language name.
    
    Raises:
        UnsupportedLanguageError: If language cannot be detected.
    """
    detector = get_detector()
    
    try:
        language = detector.detect_language(file_path, code)
        logger.debug(f"Detected language: {language} for {file_path}")
        return language
    except UnsupportedLanguageError:
        # Try harder with content analysis
        if code:
            # Check for common patterns
            if "def " in code and "import " in code:
                return "python"
            if "function " in code or "const " in code or "let " in code:
                if ": string" in code or ": number" in code or "interface " in code:
                    return "typescript"
                return "javascript"
        raise


async def _run_analysis(
    engine: RuleEngine,
    code: str,
    language: str,
    file_path: str,
) -> list[Finding]:
    """
    Run security analysis on code.
    
    Note: Analysis is run synchronously because:
    1. It's CPU-bound (regex matching), so thread pools don't help
    2. Signal-based timeout protection requires main thread context
    3. MCP servers handle request-level concurrency
    
    Args:
        engine: RuleEngine instance.
        code: Code content to analyze.
        language: Programming language.
        file_path: File path for context.
    
    Returns:
        List of Finding objects.
    """
    # Run synchronously - analysis is CPU-bound and signal-based
    # timeout protection requires main thread context
    findings = engine.analyze_code(code, language, file_path)
    
    logger.debug(f"Analysis found {len(findings)} potential issues")
    return findings


def _filter_by_severity(
    findings: list[Finding],
    threshold: str,
) -> list[Finding]:
    """
    Filter findings by minimum severity threshold.
    
    Args:
        findings: List of findings to filter.
        threshold: Minimum severity level.
    
    Returns:
        Filtered list of findings.
    """
    filtered = [
        f for f in findings
        if severity_meets_threshold(f.severity, threshold)
    ]
    
    if len(filtered) < len(findings):
        logger.debug(
            f"Filtered {len(findings) - len(filtered)} findings below {threshold} threshold"
        )
    
    return filtered


def _group_by_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    """
    Group findings by vulnerability category.
    
    Args:
        findings: List of findings to group.
    
    Returns:
        Dictionary mapping category names to findings.
    """
    grouped: dict[str, list[Finding]] = defaultdict(list)
    
    for finding in findings:
        category = finding.category.value if isinstance(finding.category, Category) else finding.category
        grouped[category].append(finding)
    
    return dict(grouped)


def _generate_summary(findings: list[Finding]) -> dict[str, Any]:
    """
    Generate summary statistics with AI risk context.
    
    Args:
        findings: List of findings to summarize.
    
    Returns:
        Summary dictionary with counts and AI risk analysis.
    """
    # Count by severity
    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in findings if f.severity == Severity.LOW)
    
    # Count by category
    categories: dict[str, int] = defaultdict(int)
    for f in findings:
        cat = f.category.value if isinstance(f.category, Category) else f.category
        categories[cat] += 1
    
    # Count AI-generated risks (findings with AI risk explanations)
    ai_risk_count = sum(
        1 for f in findings
        if f.ai_generated_risk and "AI" in f.ai_generated_risk
    )
    
    # Generate AI risk summary
    ai_risk_summary = _generate_ai_risk_summary(findings, ai_risk_count)
    
    return {
        "total": len(findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "categories": dict(categories),
        "ai_risk_summary": ai_risk_summary,
    }


def _generate_ai_risk_summary(
    findings: list[Finding],
    ai_risk_count: int,
) -> str:
    """
    Generate a human-readable AI risk summary.
    
    Args:
        findings: List of findings.
        ai_risk_count: Number of findings with AI risk context.
    
    Returns:
        Summary string describing AI-related risks.
    """
    if not findings:
        return "No security issues found"
    
    if ai_risk_count == 0:
        return f"Found {len(findings)} issues, none specifically linked to AI code generation patterns"
    
    # Identify most common AI-related issues
    ai_patterns: dict[str, int] = defaultdict(int)
    for f in findings:
        if f.ai_generated_risk:
            # Extract key phrases
            risk_text = f.ai_generated_risk.lower()
            if "f-string" in risk_text or "string concatenation" in risk_text:
                ai_patterns["string interpolation for queries"] += 1
            elif "eval" in risk_text or "exec" in risk_text:
                ai_patterns["unsafe code execution"] += 1
            elif "hardcoded" in risk_text or "secret" in risk_text:
                ai_patterns["hardcoded secrets"] += 1
            elif "validation" in risk_text:
                ai_patterns["missing input validation"] += 1
            elif "auth" in risk_text.lower():
                ai_patterns["missing authentication"] += 1
            else:
                ai_patterns["common AI-generated patterns"] += 1
    
    if ai_patterns:
        top_patterns = sorted(ai_patterns.items(), key=lambda x: x[1], reverse=True)[:3]
        pattern_list = ", ".join([p[0] for p in top_patterns])
        return f"Found {ai_risk_count} issues commonly introduced by AI code generation, including: {pattern_list}"
    
    return f"Found {ai_risk_count} issues commonly introduced by AI code generation"


def _generate_recommendations(findings: list[Finding]) -> list[str]:
    """
    Generate prioritized actionable recommendations.
    
    Args:
        findings: List of findings to generate recommendations from.
    
    Returns:
        List of recommendation strings, sorted by priority.
    """
    recommendations: list[str] = []
    
    # Group by severity for prioritized recommendations
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    # Critical recommendations
    if critical_findings:
        # Group critical by category
        critical_by_category: dict[str, list[Finding]] = defaultdict(list)
        for f in critical_findings:
            cat = f.category.value if isinstance(f.category, Category) else f.category
            critical_by_category[cat].append(f)
        
        for cat, findings_list in critical_by_category.items():
            count = len(findings_list)
            cat_display = cat.replace("_", " ").title()
            if cat == "injection":
                recommendations.append(
                    f"Critical: Fix {count} injection vulnerabilit{'y' if count == 1 else 'ies'} immediately"
                )
            elif cat == "secrets":
                recommendations.append(
                    f"Critical: Move {count} hardcoded credential{'s' if count > 1 else ''} to environment variables immediately"
                )
            else:
                recommendations.append(
                    f"Critical: Address {count} {cat_display} issue{'s' if count > 1 else ''} immediately"
                )
    
    # High severity recommendations
    if high_findings:
        high_by_category: dict[str, list[Finding]] = defaultdict(list)
        for f in high_findings:
            cat = f.category.value if isinstance(f.category, Category) else f.category
            high_by_category[cat].append(f)
        
        for cat, findings_list in high_by_category.items():
            count = len(findings_list)
            cat_display = cat.replace("_", " ").title()
            if cat == "authentication":
                recommendations.append(
                    f"High: Add authentication middleware to {count} unprotected endpoint{'s' if count > 1 else ''}"
                )
            elif cat == "authorization":
                recommendations.append(
                    f"High: Implement access control for {count} resource{'s' if count > 1 else ''}"
                )
            elif cat == "cryptography":
                recommendations.append(
                    f"High: Replace {count} weak cryptographic implementation{'s' if count > 1 else ''}"
                )
            else:
                recommendations.append(
                    f"High: Review and fix {count} {cat_display} issue{'s' if count > 1 else ''}"
                )
    
    # Medium severity aggregated recommendation
    if medium_findings:
        categories = set(
            f.category.value if isinstance(f.category, Category) else f.category
            for f in medium_findings
        )
        recommendations.append(
            f"Medium: Address {len(medium_findings)} issue{'s' if len(medium_findings) > 1 else ''} "
            f"in {len(categories)} categor{'ies' if len(categories) > 1 else 'y'}"
        )
    
    # If no findings
    if not recommendations:
        recommendations.append("No critical issues found. Continue regular security reviews.")
    
    return recommendations


def _format_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    """
    Format findings for output with unique IDs.
    
    Args:
        findings: List of Finding objects.
    
    Returns:
        List of dictionaries with formatted finding data.
    """
    formatted: list[dict[str, Any]] = []
    
    for idx, finding in enumerate(findings, start=1):
        formatted.append({
            "id": f"FINDING-{idx:03d}",
            "rule_id": finding.rule_id,
            "severity": finding.severity.value if isinstance(finding.severity, Severity) else finding.severity,
            "category": finding.category.value if isinstance(finding.category, Category) else finding.category,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "code_snippet": finding.code_snippet,
            "message": finding.message,
            "technical_detail": finding.technical_detail,
            "cwe": finding.cwe,
            "owasp_category": finding.owasp_category,
            "ai_generated_risk": finding.ai_generated_risk,
            "fix_available": finding.fix_available,
            "confidence": finding.confidence,
        })
    
    return formatted


# =============================================================================
# Legacy Functions (Backwards Compatibility)
# =============================================================================


def analyze_code(
    content: str,
    file_path: str | None = None,
    language: str | None = None,
) -> AnalysisResult:
    """
    Analyze code content against configured rules.
    
    Legacy synchronous function for backwards compatibility.
    For new code, prefer the async analyze_security function.

    Args:
        content: Source code to analyze.
        file_path: Optional path for context in results.
        language: Optional language hint (python, typescript, javascript).

    Returns:
        AnalysisResult with all findings.
    """
    findings = evaluate_rules(content, file_path=file_path, language=language)

    critical_count = sum(1 for r in findings if r.severity == Severity.CRITICAL)
    high_count = sum(1 for r in findings if r.severity == Severity.HIGH)
    medium_count = sum(1 for r in findings if r.severity == Severity.MEDIUM)
    low_count = sum(1 for r in findings if r.severity == Severity.LOW)

    categories_affected: dict[Category, int] = {}
    for r in findings:
        cat = r.category
        categories_affected[cat] = categories_affected.get(cat, 0) + 1

    return AnalysisResult(
        findings=findings,
        scanned_files=1 if file_path else 0,
        total_issues=len(findings),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        categories_affected=categories_affected,
    )


def analyze_file(path: str | Path) -> AnalysisResult:
    """
    Analyze a file from disk.
    
    Legacy synchronous function for backwards compatibility.
    For new code, prefer the async analyze_security function.
    """
    p = Path(path)
    if not p.exists():
        return AnalysisResult(
            findings=[
                RuleResult(
                    id="file_not_found",
                    rule_id="file_not_found",
                    severity=Severity.CRITICAL,
                    category=Category.ERROR_HANDLING,
                    file_path=str(path),
                    line_number=1,
                    code_snippet=f"File not found: {path}",
                    message=f"File not found: {path}",
                    technical_detail=f"Could not read file at {path}",
                    cwe="CWE-000",
                    fix_available=False,
                    confidence=1.0,
                    ai_generated_risk="N/A",
                )
            ],
            total_issues=1,
            critical_count=1,
        )

    content = p.read_text()
    ext_to_lang = {
        ".py": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
    }
    language = ext_to_lang.get(p.suffix.lower())

    return analyze_code(content, file_path=str(p), language=language)


def list_available_rules(language: str | None = None) -> list[dict]:
    """List all loaded rules for the given language."""
    rules = load_rules(language)
    return [r.model_dump() for r in rules]


# =============================================================================
# Synchronous Wrapper
# =============================================================================


def analyze_security_sync(
    file_path: str,
    code: Optional[str] = None,
    severity_threshold: str = "low",
) -> dict[str, Any]:
    """
    Synchronous wrapper for analyze_security.
    
    Use this when calling from synchronous code contexts.
    
    Args:
        file_path: Path to the file to analyze.
        code: Optional source code content.
        severity_threshold: Minimum severity level to include.
    
    Returns:
        Analysis result dictionary.
    """
    return asyncio.run(analyze_security(file_path, code, severity_threshold))
