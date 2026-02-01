"""Resource handlers for exposing rules and configuration via MCP."""

from opencore_mcp.rules_engine import get_engine, load_config, load_rules


def get_rules_resource(language: str | None = None) -> str:
    """Get rules as formatted text resource."""
    rules = load_rules(language)
    if not rules:
        return "No rules configured for the specified language."

    lines = ["# Code Quality Rules\n"]
    for r in rules:
        lines.append(f"## {r.name} (`{r.id}`)")
        lines.append(f"- Severity: {r.severity}")
        if r.description:
            lines.append(f"- Description: {r.description}")
        if r.fix_template:
            lines.append("- Auto-fixable: Yes")
        lines.append("")
    return "\n".join(lines)


def get_config_resource() -> str:
    """Get rules configuration as formatted text."""
    config = load_config()
    lines = [
        "# Rules Configuration",
        "",
        f"Default languages: {', '.join(config.default_languages)}",
        f"Fix strategy: {config.fix_strategy}",
        "",
        "Severity levels:",
    ]
    for name, level in config.severity_levels.items():
        lines.append(f"  - {name}: {level}")
    return "\n".join(lines)


def get_rule_file_content(language: str) -> str:
    """Get raw content of a rule file."""
    path = get_engine().rules_dir / f"{language}.json"
    if not path.exists():
        return f"No rule file found for language: {language}"
    return path.read_text()
