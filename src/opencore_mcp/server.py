"""OpenCore MCP Server - Security analysis for AI-generated code."""

import json
import logging

from mcp.server.fastmcp import FastMCP

from opencore_mcp.tools import (
    analyze_code,
    apply_fix,
    check_dependencies,
    generate_fix,
    get_dependencies,
)
from opencore_mcp.tools.analyzer import analyze_file, list_available_rules
from opencore_mcp.resources.resource_handlers import (
    get_config_resource,
    get_rule_file_content,
    get_rules_resource,
)
from opencore_mcp.prompts.prompt_templates import (
    CODE_REVIEW_PROMPT,
    DEPENDENCY_REVIEW_PROMPT,
    FIX_SUGGESTION_PROMPT,
)

# ────────────────────────────────────────────
# LOGGING SETUP
# ────────────────────────────────────────────

logger = logging.getLogger("opencore")

# ────────────────────────────────────────────
# SERVER INSTANTIATION
# ────────────────────────────────────────────

mcp = FastMCP(
    name="OpenCore MCP",
    instructions="Security analysis for AI-generated code. Detects vulnerabilities like injection, hardcoded secrets, broken auth, weak cryptography, and XSS via MCP.",
)

# ────────────────────────────────────────────
# TOOLS
# ────────────────────────────────────────────


@mcp.tool()
def analyze(
    content: str, file_path: str | None = None, language: str | None = None
) -> dict:
    """Analyze a code snippet for security vulnerabilities. Returns findings with severity, category, CWE, and fix availability."""
    result = analyze_code(content, file_path, language)
    logger.info(f"analyze: {len(result.findings)} findings")
    return result.model_dump()


@mcp.tool()
def analyze_file_path(path: str) -> dict:
    """Analyze a file on disk by its path. Detects language automatically from the file extension."""
    result = analyze_file(path)
    logger.info(f"analyze_file_path: {path}, {len(result.findings)} findings")
    return result.model_dump()


@mcp.tool()
def fix_code(
    content: str,
    rule_id: str,
    file_path: str | None = None,
    language: str | None = None,
) -> dict:
    """Apply a fix for a specific rule violation. Provide the rule_id from an analyze result to get a corrected version of the code."""
    result = apply_fix(content, rule_id, file_path, language)
    logger.info(f"fix_code: fixing rule {rule_id}")
    return result.model_dump()


@mcp.tool()
def list_rules(language: str | None = None) -> list:
    """List all available security rules. Optionally filter by language (javascript, typescript, python)."""
    return list_available_rules(language)


@mcp.tool()
def get_project_dependencies(project_path: str | None = None) -> dict:
    """Parse and return all dependencies from a project's package file (package.json, requirements.txt, pyproject.toml)."""
    result = get_dependencies(project_path)
    logger.info(f"get_project_dependencies: {project_path}")
    return result.model_dump(mode="json")


@mcp.tool()
async def check_dependencies_tool(package_file: str) -> dict:
    """Scan a package file for known vulnerable dependencies. Supports package.json, requirements.txt, pyproject.toml. Returns CVE details, severity, and upgrade recommendations for each vulnerable package found."""
    result = await check_dependencies(package_file)
    logger.info(f"check_dependencies_tool: {package_file}")
    return result


@mcp.tool()
async def generate_fix_tool(finding_id: str, approach: str = "comprehensive") -> dict:
    """Generate a secure code patch for a specific finding. Run analyze or analyze_file_path first — findings are cached by ID. Then call this with that finding_id. approach is either 'minimal' (fixes only the vulnerable line) or 'comprehensive' (adds validation, error handling, and logging around the fix)."""
    result = await generate_fix(finding_id, approach)
    logger.info(f"generate_fix_tool: finding_id={finding_id}, approach={approach}")
    return result


# ────────────────────────────────────────────
# RESOURCES
# ────────────────────────────────────────────


@mcp.resource("opencore://rules")
def rules_resource() -> str:
    """All security rules across all supported languages."""
    return get_rules_resource()

@mcp.resource("opencore://rules/javascript")
def rules_javascript() -> str:
    """Security rules for JavaScript."""
    return get_rules_resource("javascript")

@mcp.resource("opencore://rules/typescript")
def rules_typescript() -> str:
    """Security rules for TypeScript."""
    return get_rules_resource("typescript")

@mcp.resource("opencore://rules/python")
def rules_python() -> str:
    """Security rules for Python."""
    return get_rules_resource("python")

@mcp.resource("opencore://config")
def config_resource() -> str:
    """Opencore detection configuration and settings."""
    return get_config_resource()

@mcp.resource("opencore://raw/javascript")
def raw_rules_javascript() -> str:
    """Raw JSON rule definitions for JavaScript."""
    return get_rule_file_content("javascript")

@mcp.resource("opencore://raw/typescript")
def raw_rules_typescript() -> str:
    """Raw JSON rule definitions for TypeScript."""
    return get_rule_file_content("typescript")

@mcp.resource("opencore://raw/python")
def raw_rules_python() -> str:
    """Raw JSON rule definitions for Python."""
    return get_rule_file_content("python")


# ────────────────────────────────────────────
# PROMPTS
# ────────────────────────────────────────────


@mcp.prompt()
def code_review(code: str, language: str = "python", file_path: str = "") -> str:
    """Run security analysis on code and return a structured review prompt with all findings included."""
    result = analyze_code(code, file_path=file_path or None, language=language)
    analysis_text = (
        json.dumps([r.model_dump() for r in result.findings], indent=2)
        if result.findings
        else "No findings."
    )
    logger.info(f"code_review prompt generated: {len(result.findings)} findings")
    return CODE_REVIEW_PROMPT.format(
        language=language,
        file_path=file_path or "<inline>",
        code=code,
        analysis=analysis_text,
    )


@mcp.prompt()
def fix_suggestion(
    code: str,
    rule_id: str,
    message: str,
    file_path: str = "",
    line: int | None = None,
) -> str:
    """Generate a targeted fix suggestion prompt for a specific rule violation."""
    logger.info(f"fix_suggestion prompt: rule={rule_id}, line={line}")
    return FIX_SUGGESTION_PROMPT.format(
        rule_id=rule_id,
        message=message,
        file_path=file_path or "<unknown>",
        line=line or "?",
        code=code,
    )


@mcp.prompt()
def dependency_review(project_path: str = ".") -> str:
    """Parse project dependencies and return a structured review prompt for security assessment."""
    report = get_dependencies(project_path)
    deps_text = json.dumps([d.model_dump() for d in report.dependencies], indent=2)
    logger.info(f"dependency_review prompt: {len(report.dependencies)} deps")
    return DEPENDENCY_REVIEW_PROMPT.format(
        project_path=report.project_path,
        dependencies=deps_text,
    )


# ────────────────────────────────────────────
# ENTRY POINT
# ────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("Starting OpenCore MCP server...")
    mcp.run(transport="stdio")
