"""
Intelligent fix generation for security findings.

This module provides the generate_fix MCP tool: given a finding ID (from a prior
analyze_security run), it retrieves the finding from cache, loads the matching rule
and fix template, and produces a minimal or comprehensive code patch with
explanation, prerequisites, and security rationale.

Features:
- Finding cache populated by analyze_security
- Rule-based template selection (SQL injection, command injection, etc.)
- Minimal vs comprehensive patch modes
- Non-technical explanation and security rationale
- Prerequisites and additional steps
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from opencore_mcp.models import FixResult
from opencore_mcp.rules_engine import get_engine, load_rules

# Configure structured logging
logger = logging.getLogger(__name__)

# =============================================================================
# Finding cache (populated by analyzer after analyze_security)
# =============================================================================

_findings_cache: dict[str, dict[str, Any]] = {}
_cache_lock = threading.Lock()


def register_findings(formatted_findings: list[dict[str, Any]]) -> None:
    """
    Register findings from a completed analysis for later fix generation.

    Call this after analyze_security formats its findings so generate_fix
    can look up by finding id (e.g. FINDING-001).

    Args:
        formatted_findings: List of finding dicts with "id", "rule_id",
            "file_path", "line_number", "code_snippet", etc.
    """
    with _cache_lock:
        for f in formatted_findings:
            fid = f.get("id")
            if fid:
                _findings_cache[fid] = dict(f)
        logger.debug("Registered %d findings for fix generation", len(formatted_findings))


def get_cached_finding(finding_id: str) -> dict[str, Any] | None:
    """Return cached finding by id, or None."""
    with _cache_lock:
        return _findings_cache.get(finding_id)


def clear_findings_cache() -> None:
    """Clear the findings cache (e.g. before a new scan)."""
    with _cache_lock:
        _findings_cache.clear()
        logger.debug("Findings cache cleared")


# =============================================================================
# Template resolution
# =============================================================================

def _fixes_templates_dir() -> Path:
    """Resolve fixes/templates directory (env, then project root, cwd)."""
    if env_path := os.environ.get("OPENCORE_MCP_FIXES_DIR"):
        return Path(env_path) / "templates"
    pkg_dir = Path(__file__).resolve().parent
    # tools -> opencore_mcp -> src -> project root
    project_root = pkg_dir.parent.parent.parent
    candidates = [
        project_root / "fixes" / "templates",
        Path.cwd() / "fixes" / "templates",
        pkg_dir.parent.parent / "fixes" / "templates",
    ]
    for c in candidates:
        if c.exists():
            return c
    return project_root / "fixes" / "templates"


# Map rule_id prefix or full id to template slug (without extension)
_RULE_ID_TO_TEMPLATE: dict[str, str] = {
    # JavaScript/TypeScript
    "sql-injection": "sql_injection",
    "command-injection": "command_injection",
    "hardcoded-session-secret": "hardcoded_secret",
    "hardcoded-api-key": "hardcoded_secret",
    "hardcoded-password": "hardcoded_secret",
    "hardcoded-jwt-secret": "hardcoded_secret",
    "hardcoded-encryption-key": "hardcoded_secret",
    "hardcoded-credentials": "hardcoded_secret",
    "aws-credentials-in-code": "hardcoded_secret",
    "database-credentials-in-code": "hardcoded_secret",
    "private-keys-in-code": "hardcoded_secret",
    "secrets-env-default": "hardcoded_secret",
    "missing-auth-middleware": "missing_auth",
    "missing-auth-nextjs": "missing_auth",
    "xss-innerhtml": "xss_innerHTML",
    "xss-dangerouslysetinnerhtml": "xss_innerHTML",
    "xss-document-write": "xss_innerHTML",
    "xss-unsafe-jquery": "xss_innerHTML",
    "xss-unescaped-template": "xss_innerHTML",
    "weak-hashing-md5": "weak_crypto",
    "weak-hashing-sha1": "weak_crypto",
    "insecure-random-math-random": "weak_crypto",
    "hardcoded-encryption-key": "weak_crypto",
    "custom-crypto-implementation": "weak_crypto",
    "cors-wildcard-origin": "cors_wildcard",
    "code-injection-eval": "eval_usage",
    # Python
    "sql-injection-string-formatting": "sql_injection",
    "sql-injection-format-method": "sql_injection",
    "command-injection-os-system": "command_injection",
    "command-injection-subprocess-shell": "command_injection",
    "unsafe-pickle-loads": "pickle_loads",
    "weak-password-hashing-md5": "weak_hashing",
    "weak-password-hashing-sha-no-salt": "weak_hashing",
    "django-default-secret-key": "hardcoded_secret",
    "flask-secret-key-hardcoded": "hardcoded_secret",
    "hardcoded-api-keys": "hardcoded_secret",
    "missing-login-required": "missing_auth",
    "django-debug-true": "debug_true",
    "flask-debug-true": "debug_true",
}


def _rule_id_to_template_slug(rule_id: str, language: str) -> str | None:
    """Map rule_id and language to template slug (e.g. sql_injection)."""
    # Exact match first
    if rule_id in _RULE_ID_TO_TEMPLATE:
        return _RULE_ID_TO_TEMPLATE[rule_id]
    # Prefix match
    for prefix, slug in _RULE_ID_TO_TEMPLATE.items():
        if rule_id.startswith(prefix) or prefix in rule_id:
            return slug
    # Category-based fallbacks
    if "sql" in rule_id and "injection" in rule_id:
        return "sql_injection"
    if "command" in rule_id and "injection" in rule_id:
        return "command_injection"
    if "hardcoded" in rule_id or "secret" in rule_id or "credential" in rule_id:
        return "hardcoded_secret"
    if "auth" in rule_id and "middleware" in rule_id:
        return "missing_auth"
    if "xss" in rule_id or "innerhtml" in rule_id:
        return "xss_innerHTML"
    if "weak" in rule_id and ("hash" in rule_id or "crypto" in rule_id):
        return "weak_crypto" if language in ("javascript", "typescript") else "weak_hashing"
    if "cors" in rule_id:
        return "cors_wildcard"
    if "eval" in rule_id:
        return "eval_usage"
    if "pickle" in rule_id:
        return "pickle_loads"
    if "debug" in rule_id:
        return "debug_true"
    return None


def _load_template(language: str, template_slug: str) -> dict[str, Any] | None:
    """Load fix template JSON for language and slug. Returns None if not found."""
    templates_dir = _fixes_templates_dir()
    # Try language-specific filename: sql_injection.js.template, sql_injection.py.template
    ext = "js" if language in ("javascript", "typescript") else "py"
    path = templates_dir / f"{template_slug}.{ext}.template"
    if not path.exists():
        path = templates_dir / f"{template_slug}.template"
    if not path.exists():
        logger.debug("No template at %s or %s", path, templates_dir / f"{template_slug}.template")
        return None
    try:
        data = json.loads(path.read_text())
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load template %s: %s", path, e)
        return None


# =============================================================================
# Patch generation
# =============================================================================

def _build_patch(
    finding: dict[str, Any],
    template: dict[str, Any],
    approach: str,
) -> dict[str, Any]:
    """Build patch dict (old_code, new_code, file_path, line_start, line_end)."""
    line = finding.get("line_number", 1)
    file_path = finding.get("file_path", "")
    old_code = finding.get("code_snippet", "").strip()

    # Prefer approach-specific new_code from template, then generic
    if approach == "comprehensive":
        new_code = (
            template.get("new_code_comprehensive")
            or template.get("new_code_minimal")
            or template.get("new_code")
        )
    else:
        new_code = (
            template.get("new_code_minimal")
            or template.get("new_code")
            or template.get("new_code_comprehensive")
        )

    # If template has placeholder, substitute finding's vulnerable code as context
    if not new_code and template.get("new_code"):
        new_code = template["new_code"]
    # Use template example as fallback when we don't have a smarter transform
    if not new_code:
        new_code = template.get("example_new_code", old_code)

    # Prefer actual finding code for old_code
    if not old_code and template.get("old_code"):
        old_code = template.get("old_code", "")

    return {
        "old_code": old_code,
        "new_code": new_code or old_code,
        "file_path": file_path,
        "line_start": line,
        "line_end": line,
    }


def _vulnerability_name_from_rule(rule: Any) -> str:
    """Human-readable vulnerability name from rule."""
    if rule is None:
        return "Security issue"
    return getattr(rule, "name", None) or getattr(rule, "id", "Security issue")


# =============================================================================
# Public API: generate_fix (async MCP tool)
# =============================================================================

async def generate_fix(
    finding_id: str,
    approach: str = "comprehensive",
) -> dict[str, Any]:
    """
    Generate an intelligent fix for a security finding by ID.

    Retrieves the finding from cache (populated by a prior analyze_security run),
    loads the rule and fix template for the finding's category, and returns a
    minimal or comprehensive code patch with explanation, prerequisites, and
    security rationale.

    Args:
        finding_id: ID of the finding (e.g. FINDING-001 from analyze_security).
        approach: "minimal" — fix only the vulnerable line;
                  "comprehensive" — fix plus validation, error handling, logging.

    Returns:
        Dict with:
        - finding_id, vulnerability, patch (old_code, new_code, file_path, line_start, line_end)
        - explanation, security_rationale, why_ai_generated_this
        - prerequisites, additional_steps, additional_files
        - testing_suggestion, references

    Raises:
        No exception; on error returns a dict with error key and message.
    """
    approach = (approach or "comprehensive").lower()
    if approach not in ("minimal", "comprehensive"):
        approach = "comprehensive"

    finding = get_cached_finding(finding_id)
    if not finding:
        return {
            "error": "finding_not_found",
            "message": f"No cached finding for id '{finding_id}'. Run analyze_security first so findings can be looked up by id.",
            "finding_id": finding_id,
        }

    rule_id = finding.get("rule_id", "")
    language = _infer_language(finding.get("file_path", ""))
    engine = get_engine()
    rule = engine.get_rule_by_id(rule_id)
    if not rule:
        # Load rules for language so engine has them indexed
        load_rules(language)
        rule = engine.get_rule_by_id(rule_id)

    vulnerability = _vulnerability_name_from_rule(rule)
    template_slug = _rule_id_to_template_slug(rule_id, language)
    loaded_template: dict[str, Any] | None = None
    if template_slug:
        loaded_template = _load_template(language, template_slug)

    template = loaded_template
    if not template:
        # Fallback: use rule's fix_template and message only
        template = {
            "explanation": finding.get("message", ""),
            "security_rationale": finding.get("technical_detail", ""),
            "why_ai_generated": finding.get("ai_generated_risk", ""),
            "prerequisites": [],
            "additional_steps": ["Review the change and run tests."],
            "references": [],
            "new_code": getattr(rule, "fix_template", None) if rule else None,
        }

    patch = _build_patch(finding, template, approach)
    explanation = template.get("explanation", finding.get("message", ""))
    security_rationale = template.get("security_rationale", finding.get("technical_detail", ""))
    why_ai = template.get("why_ai_generated_this") or template.get("why_ai_generated") or finding.get("ai_generated_risk", "")

    prerequisites = list(template.get("prerequisites", []))
    additional_steps = list(template.get("additional_steps", []))
    if approach == "comprehensive" and template.get("comprehensive_steps"):
        additional_steps = list(template["comprehensive_steps"]) + additional_steps

    return {
        "finding_id": finding_id,
        "vulnerability": vulnerability,
        "patch": patch,
        "explanation": explanation,
        "security_rationale": security_rationale,
        "why_ai_generated_this": why_ai,
        "prerequisites": prerequisites,
        "additional_steps": additional_steps,
        "additional_files": list(template.get("additional_files", [])),
        "testing_suggestion": template.get("testing_suggestion", "Run existing tests and try malicious inputs that could exploit the original issue."),
        "references": list(template.get("references", [])),
    }


def _infer_language(file_path: str) -> str:
    """Infer language from file path extension."""
    p = Path(file_path)
    ext = p.suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
    }
    return mapping.get(ext, "javascript")


# =============================================================================
# Legacy: apply_fix (unchanged behavior, kept for compatibility)
# =============================================================================

def apply_fix(
    content: str,
    rule_id: str,
    file_path: str | None = None,
    language: str | None = None,
) -> FixResult:
    """
    Attempt to apply a fix for a rule violation.

    Args:
        content: Source code to fix.
        rule_id: ID of the rule whose fix to apply.
        file_path: Optional path for the target file.
        language: Optional language hint.

    Returns:
        FixResult indicating success and any changes.
    """
    rules = load_rules(language)
    rule = next((r for r in rules if r.id == rule_id), None)

    if not rule:
        return FixResult(
            success=False,
            file_path=file_path or "<unknown>",
            message=f"Unknown rule: {rule_id}",
        )

    if not rule.fix_template:
        return FixResult(
            success=False,
            file_path=file_path or "<unknown>",
            message=f"Rule '{rule_id}' has no fix template",
        )

    return FixResult(
        success=True,
        file_path=file_path or "<inline>",
        message=f"Fix for rule '{rule_id}' would be applied (template-based fixes require integration)",
        original_content=content,
        fixed_content=content,
    )


def apply_fix_to_file(path: str | Path, rule_id: str) -> FixResult:
    """Apply a fix to a file on disk."""
    p = Path(path)
    if not p.exists():
        return FixResult(
            success=False,
            file_path=str(path),
            message=f"File not found: {path}",
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

    result = apply_fix(content, rule_id, file_path=str(p), language=language)

    if result.success and result.fixed_content and result.fixed_content != content:
        p.write_text(result.fixed_content)

    return result
