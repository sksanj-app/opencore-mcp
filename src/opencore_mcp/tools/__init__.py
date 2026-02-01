"""MCP tools for code analysis, fixing, dependency management, and project scanning."""

from opencore_mcp.tools.analyzer import (
    analyze_code,
    analyze_file,
    analyze_security,
    analyze_security_sync,
    list_available_rules,
    clear_engine_cache,
)
from opencore_mcp.tools.dependencies import check_dependencies, get_dependencies
from opencore_mcp.tools.fixer import (
    apply_fix,
    apply_fix_to_file,
    clear_findings_cache,
    generate_fix,
    get_cached_finding,
    register_findings,
)
from opencore_mcp.tools.scanner import (
    scan_project,
    scan_project_sync,
    ScanProgress,
    DirectoryNotFoundError,
    ScanTimeoutError,
)

__all__ = [
    "analyze_code",
    "analyze_file",
    "analyze_security",
    "analyze_security_sync",
    "apply_fix",
    "apply_fix_to_file",
    "check_dependencies",
    "clear_engine_cache",
    "clear_findings_cache",
    "DirectoryNotFoundError",
    "generate_fix",
    "get_cached_finding",
    "get_dependencies",
    "list_available_rules",
    "register_findings",
    "scan_project",
    "scan_project_sync",
    "ScanProgress",
    "ScanTimeoutError",
]
