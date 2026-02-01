"""Tests for MCP tools."""

import pytest

from opencore_mcp.models import AnalysisResult, FixResult
from opencore_mcp.tools import analyze_code, apply_fix, get_dependencies
from opencore_mcp.tools.analyzer import analyze_file, list_available_rules


def test_analyze_code_returns_analysis_result():
    """analyze_code returns AnalysisResult."""
    result = analyze_code("def foo(): pass", language="python")
    assert isinstance(result, AnalysisResult)
    assert hasattr(result, "findings")
    assert hasattr(result, "total_issues")
    assert hasattr(result, "critical_count")
    assert hasattr(result, "high_count")


def test_analyze_code_empty():
    """analyze_code with empty string."""
    result = analyze_code("", language="python")
    assert result.total_issues == 0
    assert result.findings == []


def test_list_available_rules():
    """list_available_rules returns list of dicts."""
    rules = list_available_rules("python")
    assert isinstance(rules, list)
    for r in rules:
        assert isinstance(r, dict)
        assert "id" in r or "name" in r


def test_apply_fix_returns_fix_result():
    """apply_fix returns FixResult."""
    result = apply_fix("x = 1", rule_id="trailing-whitespace", language="python")
    assert isinstance(result, FixResult)
    assert result.file_path


def test_apply_fix_unknown_rule():
    """apply_fix with unknown rule returns failure."""
    result = apply_fix("x = 1", rule_id="nonexistent-rule", language="python")
    assert result.success is False
    assert "Unknown rule" in result.message or "unknown" in result.message.lower()


def test_get_dependencies_returns_report():
    """get_dependencies returns DependencyReport."""
    result = get_dependencies()
    assert hasattr(result, "dependencies")
    assert hasattr(result, "total_count")
    assert hasattr(result, "project_path")
    assert isinstance(result.dependencies, list)


def test_analyze_file_not_found():
    """analyze_file with missing path returns error result."""
    result = analyze_file("/nonexistent/path/file.py")
    assert result.total_issues >= 1
    assert result.critical_count >= 1 or result.high_count >= 1
    assert any("not found" in r.message.lower() for r in result.findings)
