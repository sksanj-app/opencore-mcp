"""
Full project security scanner for comprehensive codebase analysis.

This module provides the scan_project MCP tool for analyzing entire projects,
walking directory trees, aggregating findings, identifying hotspots, and
generating security scores with AI-risk analysis.

Features:
- Recursive directory scanning with .gitignore support
- Parallel file analysis for performance
- Progress callbacks for large projects
- Security scoring (0-100)
- Hotspot identification (files with most issues)
- AI-risk heatmap generation
- Dependency scanning integration

Example:
    >>> result = await scan_project(
    ...     directory="/path/to/project",
    ...     severity_threshold="medium",
    ...     include_dependencies=True
    ... )
    >>> print(f"Security score: {result['security_score']}")
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from opencore_mcp.language_detector import get_detector, UnsupportedLanguageError
from opencore_mcp.models import Severity
from opencore_mcp.tools.analyzer import analyze_security, severity_meets_threshold
from opencore_mcp.tools.dependencies import get_dependencies

# Configure structured logging
logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================


# Severity weights for scoring (higher = more impact on score)
SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 10,
    "medium": 3,
    "low": 1,
}

# Default ignored patterns (can be extended from config)
DEFAULT_IGNORED_PATTERNS = [
    "**/node_modules/**",
    "**/.git/**",
    "**/venv/**",
    "**/__pycache__/**",
    "**/dist/**",
    "**/build/**",
    "**/.next/**",
    "**/test/**",
    "**/tests/**",
    "**/*.test.js",
    "**/*.test.ts",
    "**/*.spec.js",
    "**/*.spec.ts",
    "**/.env",
    "**/.env.*",
    "**/coverage/**",
    "**/.pytest_cache/**",
    "**/.mypy_cache/**",
    "**/.tox/**",
    "**/egg-info/**",
    "**/*.egg-info/**",
]

# Default concurrency for parallel scanning
DEFAULT_CONCURRENCY = 10


# =============================================================================
# Custom Exceptions
# =============================================================================


class ScanError(Exception):
    """Base exception for scanner errors."""
    pass


class DirectoryNotFoundError(ScanError):
    """Raised when the target directory doesn't exist."""
    
    def __init__(self, directory: str, message: str | None = None):
        self.directory = directory
        self.message = message or f"Directory not found: {directory}"
        super().__init__(self.message)


class ScanTimeoutError(ScanError):
    """Raised when the scan exceeds the timeout threshold."""
    
    def __init__(self, message: str, timeout_seconds: float, files_scanned: int):
        self.timeout_seconds = timeout_seconds
        self.files_scanned = files_scanned
        super().__init__(message)


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class ScanProgress:
    """Progress information for scan callbacks."""
    
    total_files: int
    files_scanned: int
    files_with_issues: int
    current_file: str
    elapsed_seconds: float
    
    @property
    def percent_complete(self) -> float:
        """Calculate completion percentage."""
        if self.total_files == 0:
            return 100.0
        return (self.files_scanned / self.total_files) * 100


@dataclass
class FileResult:
    """Result of scanning a single file."""
    
    file_path: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    language: str = ""
    error: str | None = None
    scan_time_ms: int = 0


@dataclass
class Hotspot:
    """A file identified as a security hotspot."""
    
    file: str
    issue_count: int
    critical_count: int
    high_count: int
    categories: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "file": self.file,
            "issue_count": self.issue_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "categories": self.categories,
        }


# =============================================================================
# Gitignore Parser
# =============================================================================


def parse_gitignore(directory: Path) -> list[str]:
    """
    Parse .gitignore file and return list of patterns.
    
    Args:
        directory: Project root directory.
    
    Returns:
        List of gitignore patterns.
    """
    gitignore_path = directory / ".gitignore"
    patterns: list[str] = []
    
    if not gitignore_path.exists():
        return patterns
    
    try:
        with open(gitignore_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                # Convert gitignore pattern to glob pattern
                if not line.startswith("**/"):
                    if line.startswith("/"):
                        # Anchored to root
                        line = line[1:]
                    else:
                        # Match anywhere
                        line = f"**/{line}"
                patterns.append(line)
    except OSError as e:
        logger.warning(f"Could not read .gitignore: {e}")
    
    return patterns


def load_ignored_patterns_from_config(rules_dir: Path | None = None) -> list[str]:
    """
    Load ignored patterns from config.yaml.
    
    Args:
        rules_dir: Path to rules directory. Auto-detected if None.
    
    Returns:
        List of patterns from config or defaults.
    """
    if rules_dir is None:
        # Auto-detect rules directory
        pkg_dir = Path(__file__).resolve().parent.parent
        project_root = pkg_dir.parent.parent
        rules_dir = project_root / "rules"
        if not rules_dir.exists():
            rules_dir = Path.cwd() / "rules"
    
    config_path = rules_dir / "config.yaml"
    
    if not config_path.exists():
        return DEFAULT_IGNORED_PATTERNS.copy()
    
    try:
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        
        default_config = data.get("default_config", {})
        patterns = default_config.get("ignored_patterns", DEFAULT_IGNORED_PATTERNS)
        return list(patterns)
    except (yaml.YAMLError, OSError) as e:
        logger.warning(f"Could not load config.yaml: {e}")
        return DEFAULT_IGNORED_PATTERNS.copy()


def should_ignore_path(path: Path, base_dir: Path, patterns: list[str]) -> bool:
    """
    Check if a path should be ignored based on patterns.
    
    Args:
        path: Path to check (file or directory).
        base_dir: Base directory for relative path calculation.
        patterns: List of glob patterns to match against.
    
    Returns:
        True if the path should be ignored.
    """
    try:
        rel_path = path.relative_to(base_dir)
    except ValueError:
        rel_path = path
    
    rel_str = str(rel_path)
    
    for pattern in patterns:
        # Handle patterns with ** prefix
        if pattern.startswith("**/"):
            # Match anywhere in the path
            if fnmatch.fnmatch(rel_str, pattern):
                return True
            # Also check if any parent directory matches
            parts = rel_str.split(os.sep)
            for i in range(len(parts)):
                partial = "/".join(parts[i:])
                if fnmatch.fnmatch(partial, pattern[3:]):  # Remove **/
                    return True
                if fnmatch.fnmatch(partial, pattern):
                    return True
        else:
            if fnmatch.fnmatch(rel_str, pattern):
                return True
    
    return False


# =============================================================================
# File Discovery
# =============================================================================


def discover_files(
    directory: Path,
    ignored_patterns: list[str],
    supported_extensions: set[str],
) -> list[Path]:
    """
    Discover all scannable files in a directory.
    
    Args:
        directory: Root directory to scan.
        ignored_patterns: Patterns to ignore.
        supported_extensions: File extensions to include.
    
    Returns:
        List of file paths to scan.
    """
    files: list[Path] = []
    
    for root, dirs, filenames in os.walk(directory):
        root_path = Path(root)
        
        # Filter directories to avoid descending into ignored paths
        dirs[:] = [
            d for d in dirs
            if not should_ignore_path(root_path / d, directory, ignored_patterns)
            and not d.startswith(".")
        ]
        
        for filename in filenames:
            # Skip hidden files
            if filename.startswith("."):
                continue
            
            file_path = root_path / filename
            
            # Check extension
            ext = file_path.suffix.lower()
            if ext not in supported_extensions:
                continue
            
            # Check if file should be ignored
            if should_ignore_path(file_path, directory, ignored_patterns):
                continue
            
            files.append(file_path)
    
    return files


# =============================================================================
# File Analysis
# =============================================================================


async def analyze_file_safe(
    file_path: Path,
    base_dir: Path,
    severity_threshold: str,
) -> FileResult:
    """
    Analyze a single file with error handling.
    
    Args:
        file_path: Path to the file to analyze.
        base_dir: Base directory for relative path calculation.
        severity_threshold: Minimum severity to include.
    
    Returns:
        FileResult with findings or error.
    """
    start_time = time.time()
    rel_path = str(file_path.relative_to(base_dir))
    
    try:
        result = await analyze_security(
            file_path=str(file_path),
            severity_threshold=severity_threshold,
        )
        
        elapsed_ms = int((time.time() - start_time) * 1000)
        
        return FileResult(
            file_path=rel_path,
            findings=result.get("findings", []),
            language=result.get("language", ""),
            scan_time_ms=elapsed_ms,
        )
        
    except UnsupportedLanguageError as e:
        logger.debug(f"Skipping unsupported file: {rel_path}")
        return FileResult(
            file_path=rel_path,
            error=f"Unsupported language: {e}",
            scan_time_ms=int((time.time() - start_time) * 1000),
        )
    except Exception as e:
        logger.warning(f"Error analyzing {rel_path}: {e}")
        return FileResult(
            file_path=rel_path,
            error=str(e),
            scan_time_ms=int((time.time() - start_time) * 1000),
        )


async def analyze_files_parallel(
    files: list[Path],
    base_dir: Path,
    severity_threshold: str,
    concurrency: int = DEFAULT_CONCURRENCY,
    progress_callback: Callable[[ScanProgress], None] | None = None,
) -> list[FileResult]:
    """
    Analyze multiple files in parallel with controlled concurrency.
    
    Args:
        files: List of files to analyze.
        base_dir: Base directory for relative paths.
        severity_threshold: Minimum severity to include.
        concurrency: Maximum concurrent analyses.
        progress_callback: Optional callback for progress updates.
    
    Returns:
        List of FileResult objects.
    """
    results: list[FileResult] = []
    semaphore = asyncio.Semaphore(concurrency)
    start_time = time.time()
    files_with_issues = 0
    
    async def analyze_with_semaphore(file_path: Path, index: int) -> FileResult:
        nonlocal files_with_issues
        
        async with semaphore:
            result = await analyze_file_safe(file_path, base_dir, severity_threshold)
            
            if result.findings:
                files_with_issues += 1
            
            # Call progress callback if provided
            if progress_callback:
                progress = ScanProgress(
                    total_files=len(files),
                    files_scanned=index + 1,
                    files_with_issues=files_with_issues,
                    current_file=result.file_path,
                    elapsed_seconds=time.time() - start_time,
                )
                try:
                    progress_callback(progress)
                except Exception as e:
                    logger.warning(f"Progress callback error: {e}")
            
            return result
    
    # Create tasks for all files
    tasks = [
        analyze_with_semaphore(file_path, i)
        for i, file_path in enumerate(files)
    ]
    
    # Gather results
    results = await asyncio.gather(*tasks)
    
    return results


# =============================================================================
# Aggregation and Analysis
# =============================================================================


def aggregate_findings(
    file_results: list[FileResult],
) -> dict[str, list[dict[str, Any]]]:
    """
    Aggregate findings by file path.
    
    Args:
        file_results: List of file analysis results.
    
    Returns:
        Dictionary mapping file paths to findings.
    """
    findings_by_file: dict[str, list[dict[str, Any]]] = {}
    
    for result in file_results:
        if result.findings:
            findings_by_file[result.file_path] = result.findings
    
    return findings_by_file


def calculate_summary(
    findings_by_file: dict[str, list[dict[str, Any]]],
    total_files_scanned: int,
) -> dict[str, Any]:
    """
    Calculate summary statistics from findings.
    
    Args:
        findings_by_file: Findings grouped by file.
        total_files_scanned: Total number of files analyzed.
    
    Returns:
        Summary dictionary with counts by severity and category.
    """
    by_severity: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    by_category: dict[str, int] = defaultdict(int)
    total_findings = 0
    
    for findings in findings_by_file.values():
        for finding in findings:
            total_findings += 1
            severity = finding.get("severity", "low").lower()
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            category = finding.get("category", "unknown")
            by_category[category] += 1
    
    return {
        "files_scanned": total_files_scanned,
        "total_findings": total_findings,
        "by_severity": by_severity,
        "by_category": dict(by_category),
    }


def calculate_security_score(summary: dict[str, Any]) -> float:
    """
    Calculate a security score from 0-100.
    
    Score calculation:
    - Starts at 100
    - Deducts points based on severity and count
    - Formula: score = max(0, 100 - sum(count * weight))
    
    Args:
        summary: Summary statistics from calculate_summary.
    
    Returns:
        Security score from 0 to 100.
    """
    by_severity = summary.get("by_severity", {})
    
    # Calculate penalty
    penalty = 0
    for severity, count in by_severity.items():
        weight = SEVERITY_WEIGHTS.get(severity.lower(), 1)
        penalty += count * weight
    
    # Score is 100 minus penalty, but never below 0
    score = max(0, 100 - penalty)
    
    # Round to 1 decimal place
    return round(score, 1)


def identify_hotspots(
    findings_by_file: dict[str, list[dict[str, Any]]],
    top_n: int = 10,
) -> list[Hotspot]:
    """
    Identify security hotspots (files with most issues).
    
    Args:
        findings_by_file: Findings grouped by file.
        top_n: Number of hotspots to return.
    
    Returns:
        List of Hotspot objects sorted by severity and count.
    """
    hotspots: list[Hotspot] = []
    
    for file_path, findings in findings_by_file.items():
        critical_count = sum(
            1 for f in findings if f.get("severity", "").lower() == "critical"
        )
        high_count = sum(
            1 for f in findings if f.get("severity", "").lower() == "high"
        )
        categories = list(set(f.get("category", "unknown") for f in findings))
        
        hotspots.append(Hotspot(
            file=file_path,
            issue_count=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            categories=categories,
        ))
    
    # Sort by critical count (desc), then high count (desc), then issue count (desc)
    hotspots.sort(
        key=lambda h: (h.critical_count, h.high_count, h.issue_count),
        reverse=True,
    )
    
    return hotspots[:top_n]


def analyze_ai_risks(
    findings_by_file: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """
    Analyze AI-generated risk patterns across all findings.
    
    Args:
        findings_by_file: Findings grouped by file.
    
    Returns:
        AI risk analysis with common patterns and counts.
    """
    ai_patterns: dict[str, int] = defaultdict(int)
    total_ai_patterns = 0
    
    for findings in findings_by_file.values():
        for finding in findings:
            ai_risk = finding.get("ai_generated_risk", "")
            if not ai_risk:
                continue
            
            # Categorize AI risks
            risk_lower = ai_risk.lower()
            
            if "f-string" in risk_lower or "string concatenation" in risk_lower or "string interpolation" in risk_lower:
                ai_patterns["String concatenation in SQL queries"] += 1
                total_ai_patterns += 1
            elif "hardcoded" in risk_lower or "secret" in risk_lower or "credential" in risk_lower:
                ai_patterns["Hardcoded secrets"] += 1
                total_ai_patterns += 1
            elif "auth" in risk_lower and ("missing" in risk_lower or "skip" in risk_lower):
                ai_patterns["Missing authentication"] += 1
                total_ai_patterns += 1
            elif "validation" in risk_lower or "sanitiz" in risk_lower:
                ai_patterns["Missing input validation"] += 1
                total_ai_patterns += 1
            elif "eval" in risk_lower or "exec" in risk_lower:
                ai_patterns["Unsafe code execution (eval/exec)"] += 1
                total_ai_patterns += 1
            elif "crypto" in risk_lower or "md5" in risk_lower or "sha1" in risk_lower:
                ai_patterns["Weak cryptography"] += 1
                total_ai_patterns += 1
            elif "debug" in risk_lower or "verbose" in risk_lower:
                ai_patterns["Debug/verbose mode enabled"] += 1
                total_ai_patterns += 1
            elif "cors" in risk_lower or "wildcard" in risk_lower:
                ai_patterns["Insecure CORS configuration"] += 1
                total_ai_patterns += 1
            elif "path" in risk_lower or "traversal" in risk_lower:
                ai_patterns["Path traversal vulnerabilities"] += 1
                total_ai_patterns += 1
            elif "xss" in risk_lower or "escap" in risk_lower:
                ai_patterns["Cross-site scripting (XSS)"] += 1
                total_ai_patterns += 1
            elif ai_risk and "ai" in risk_lower:
                ai_patterns["Other AI-generated patterns"] += 1
                total_ai_patterns += 1
    
    # Sort by occurrence count and format
    sorted_patterns = sorted(ai_patterns.items(), key=lambda x: x[1], reverse=True)
    most_common = [
        f"{pattern} ({count} occurrence{'s' if count > 1 else ''})"
        for pattern, count in sorted_patterns[:5]
    ]
    
    return {
        "total_ai_generated_patterns": total_ai_patterns,
        "most_common_ai_issues": most_common,
        "pattern_breakdown": dict(sorted_patterns),
    }


def generate_recommendations(
    summary: dict[str, Any],
    hotspots: list[Hotspot],
    ai_risk_analysis: dict[str, Any],
) -> list[str]:
    """
    Generate prioritized recommendations based on scan results.
    
    Args:
        summary: Summary statistics.
        hotspots: List of identified hotspots.
        ai_risk_analysis: AI risk analysis results.
    
    Returns:
        List of recommendation strings.
    """
    recommendations: list[str] = []
    by_severity = summary.get("by_severity", {})
    total_findings = summary.get("total_findings", 0)
    
    # Critical recommendations
    critical_count = by_severity.get("critical", 0)
    if critical_count > 0:
        recommendations.append(
            f"CRITICAL: Fix {critical_count} critical vulnerabilit{'y' if critical_count == 1 else 'ies'} immediately"
        )
    
    # High severity recommendations
    high_count = by_severity.get("high", 0)
    if high_count > 0:
        recommendations.append(
            f"HIGH: Address {high_count} high severity issue{'s' if high_count > 1 else ''} before deployment"
        )
    
    # Hotspot recommendations
    if hotspots:
        top_hotspot = hotspots[0]
        if top_hotspot.issue_count >= 3:
            recommendations.append(
                f"Focus on {top_hotspot.file} - highest risk file with {top_hotspot.issue_count} issues"
            )
    
    # AI risk recommendations
    ai_patterns = ai_risk_analysis.get("total_ai_generated_patterns", 0)
    if ai_patterns > 0 and total_findings > 0:
        ai_percentage = int((ai_patterns / total_findings) * 100)
        if ai_percentage >= 50:
            recommendations.append(
                f"{ai_patterns} of {total_findings} issues ({ai_percentage}%) are common AI-generated patterns - consider reviewing AI code generation practices"
            )
        elif ai_patterns >= 5:
            recommendations.append(
                f"{ai_patterns} of {total_findings} issues are common AI-generated patterns"
            )
    
    # Category-specific recommendations
    by_category = summary.get("by_category", {})
    if by_category.get("injection", 0) >= 3:
        recommendations.append(
            "Multiple injection vulnerabilities detected - implement parameterized queries and input validation"
        )
    if by_category.get("secrets", 0) >= 2:
        recommendations.append(
            "Multiple hardcoded secrets found - migrate to environment variables or secret management"
        )
    if by_category.get("authentication", 0) >= 2:
        recommendations.append(
            "Multiple authentication issues - review authentication middleware coverage"
        )
    
    # If no critical issues
    if not recommendations:
        medium_count = by_severity.get("medium", 0)
        low_count = by_severity.get("low", 0)
        if medium_count > 0 or low_count > 0:
            recommendations.append(
                f"No critical or high issues found. Address {medium_count + low_count} medium/low findings when possible."
            )
        else:
            recommendations.append(
                "No security issues found. Continue regular security reviews."
            )
    
    return recommendations


# =============================================================================
# Main Scan Function
# =============================================================================


async def scan_project(
    directory: str,
    severity_threshold: str = "low",
    include_dependencies: bool = True,
    concurrency: int = DEFAULT_CONCURRENCY,
    progress_callback: Callable[[ScanProgress], None] | None = None,
    timeout_seconds: float = 600.0,
) -> dict[str, Any]:
    """
    Scan an entire project directory for security vulnerabilities.
    
    This is the main MCP tool for full project analysis. It walks the directory
    tree, respects .gitignore patterns, analyzes all supported files, and
    generates comprehensive security reports.
    
    Args:
        directory: Path to the project directory to scan.
        severity_threshold: Minimum severity level to include in results.
                           Options: "low", "medium", "high", "critical".
                           Default: "low" (include all findings).
        include_dependencies: Whether to scan project dependencies.
                             Default: True.
        concurrency: Maximum number of files to analyze in parallel.
                    Default: 10.
        progress_callback: Optional callback function for progress updates.
                          Called with ScanProgress object for each file.
        timeout_seconds: Maximum time for the scan in seconds.
                        Default: 600 (10 minutes).
    
    Returns:
        Dictionary containing:
        - findings_by_file: Findings grouped by file path
        - summary: Aggregated statistics
        - security_score: Score from 0-100
        - hotspots: Files with most issues
        - ai_risk_analysis: AI-generated pattern analysis
        - recommendations: Prioritized action items
        - dependencies: Dependency report (if include_dependencies=True)
    
    Raises:
        DirectoryNotFoundError: If the directory doesn't exist.
        ScanTimeoutError: If the scan exceeds timeout_seconds.
    
    Example:
        >>> result = await scan_project(
        ...     directory="/path/to/project",
        ...     severity_threshold="medium",
        ...     include_dependencies=True
        ... )
        >>> print(f"Score: {result['security_score']}/100")
        >>> print(f"Files with issues: {len(result['findings_by_file'])}")
    """
    start_time = time.time()
    
    logger.info(
        "Starting project scan",
        extra={
            "directory": directory,
            "severity_threshold": severity_threshold,
            "include_dependencies": include_dependencies,
            "concurrency": concurrency,
        },
    )
    
    # Validate directory
    dir_path = Path(directory).resolve()
    if not dir_path.exists():
        raise DirectoryNotFoundError(
            directory,
            f"Directory not found: {directory}. Please provide a valid project path."
        )
    if not dir_path.is_dir():
        raise DirectoryNotFoundError(
            directory,
            f"Path is not a directory: {directory}"
        )
    
    # Load ignored patterns
    ignored_patterns = load_ignored_patterns_from_config()
    gitignore_patterns = parse_gitignore(dir_path)
    all_ignored = ignored_patterns + gitignore_patterns
    
    logger.debug(
        f"Loaded {len(all_ignored)} ignore patterns",
        extra={"config_patterns": len(ignored_patterns), "gitignore_patterns": len(gitignore_patterns)},
    )
    
    # Get supported extensions
    detector = get_detector()
    extension_mapping = detector.get_file_extension_mapping()
    supported_extensions = set(extension_mapping.keys())
    
    # Discover files
    files = discover_files(dir_path, all_ignored, supported_extensions)
    
    logger.info(
        f"Discovered {len(files)} files to scan",
        extra={"directory": directory},
    )
    
    if not files:
        # No files to scan
        empty_result = {
            "findings_by_file": {},
            "summary": {
                "files_scanned": 0,
                "total_findings": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "by_category": {},
            },
            "security_score": 100.0,
            "hotspots": [],
            "ai_risk_analysis": {
                "total_ai_generated_patterns": 0,
                "most_common_ai_issues": [],
                "pattern_breakdown": {},
            },
            "recommendations": ["No supported source files found in the directory."],
        }
        
        if include_dependencies:
            try:
                dep_report = get_dependencies(directory)
                empty_result["dependencies"] = {
                    "total_count": dep_report.total_count,
                    "outdated_count": dep_report.outdated_count,
                    "vulnerable_count": dep_report.vulnerable_count,
                    "dependencies": [d.model_dump() for d in dep_report.dependencies],
                }
            except Exception as e:
                logger.warning(f"Failed to scan dependencies: {e}")
                empty_result["dependencies"] = {"error": str(e)}
        
        return empty_result
    
    # Analyze files in parallel with timeout
    try:
        file_results = await asyncio.wait_for(
            analyze_files_parallel(
                files=files,
                base_dir=dir_path,
                severity_threshold=severity_threshold,
                concurrency=concurrency,
                progress_callback=progress_callback,
            ),
            timeout=timeout_seconds,
        )
    except asyncio.TimeoutError:
        elapsed = time.time() - start_time
        raise ScanTimeoutError(
            f"Scan timed out after {timeout_seconds} seconds. "
            f"Consider scanning smaller directories or increasing timeout.",
            timeout_seconds=timeout_seconds,
            files_scanned=0,  # We don't have partial results with asyncio.wait_for
        )
    
    # Aggregate results
    findings_by_file = aggregate_findings(file_results)
    
    # Calculate summary
    summary = calculate_summary(findings_by_file, len(files))
    
    # Calculate security score
    security_score = calculate_security_score(summary)
    
    # Identify hotspots
    hotspots = identify_hotspots(findings_by_file)
    
    # Analyze AI risks
    ai_risk_analysis = analyze_ai_risks(findings_by_file)
    
    # Generate recommendations
    recommendations = generate_recommendations(summary, hotspots, ai_risk_analysis)
    
    # Build result
    result: dict[str, Any] = {
        "findings_by_file": findings_by_file,
        "summary": summary,
        "security_score": security_score,
        "hotspots": [h.to_dict() for h in hotspots],
        "ai_risk_analysis": ai_risk_analysis,
        "recommendations": recommendations,
    }
    
    # Scan dependencies if requested
    if include_dependencies:
        try:
            dep_report = get_dependencies(directory)
            result["dependencies"] = {
                "total_count": dep_report.total_count,
                "outdated_count": dep_report.outdated_count,
                "vulnerable_count": dep_report.vulnerable_count,
                "dependencies": [d.model_dump() for d in dep_report.dependencies],
            }
        except Exception as e:
            logger.warning(f"Failed to scan dependencies: {e}")
            result["dependencies"] = {"error": str(e)}
    
    elapsed_ms = int((time.time() - start_time) * 1000)
    
    logger.info(
        "Project scan completed",
        extra={
            "directory": directory,
            "files_scanned": summary["files_scanned"],
            "total_findings": summary["total_findings"],
            "security_score": security_score,
            "elapsed_ms": elapsed_ms,
        },
    )
    
    return result


# =============================================================================
# Synchronous Wrapper
# =============================================================================


def scan_project_sync(
    directory: str,
    severity_threshold: str = "low",
    include_dependencies: bool = True,
    concurrency: int = DEFAULT_CONCURRENCY,
    progress_callback: Callable[[ScanProgress], None] | None = None,
    timeout_seconds: float = 600.0,
) -> dict[str, Any]:
    """
    Synchronous wrapper for scan_project.
    
    Use this when calling from synchronous code contexts.
    
    Args:
        directory: Path to the project directory to scan.
        severity_threshold: Minimum severity level to include.
        include_dependencies: Whether to scan dependencies.
        concurrency: Maximum parallel file analyses.
        progress_callback: Optional progress callback.
        timeout_seconds: Maximum scan time.
    
    Returns:
        Scan result dictionary.
    """
    return asyncio.run(
        scan_project(
            directory=directory,
            severity_threshold=severity_threshold,
            include_dependencies=include_dependencies,
            concurrency=concurrency,
            progress_callback=progress_callback,
            timeout_seconds=timeout_seconds,
        )
    )
