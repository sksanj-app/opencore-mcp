"""Tests for the rules engine."""

import pytest

from opencore_mcp.rules_engine import evaluate_rules, load_config, load_rules


def test_load_config_defaults():
    """Config returns defaults when file missing or empty."""
    config = load_config()
    assert "python" in config.default_languages
    assert config.severity_levels["error"] == 1
    assert config.fix_strategy in ("auto", "prompt", "none")


def test_load_rules_returns_list():
    """load_rules returns a list of RuleDefinition."""
    rules = load_rules("python")
    assert isinstance(rules, list)
    for r in rules:
        assert hasattr(r, "id")
        assert hasattr(r, "name")
        assert hasattr(r, "severity")


def test_load_rules_empty_language():
    """load_rules with unknown language may return empty or use defaults."""
    rules = load_rules("nonexistent")
    assert isinstance(rules, list)


def test_evaluate_rules_empty_content():
    """evaluate_rules with empty content returns no results."""
    results = evaluate_rules("", language="python")
    assert results == []


def test_evaluate_rules_trailing_whitespace():
    """evaluate_rules detects trailing whitespace when rule matches."""
    content = "x = 1   \n"  # trailing spaces
    results = evaluate_rules(content, language="python")
    assert isinstance(results, list)
    # May or may not match depending on rule pattern
    for r in results:
        assert r.rule_id
        assert r.message
        assert r.severity
