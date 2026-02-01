# Opencore MCP

A production-ready **Model Context Protocol (MCP)** server for code analysis, automated fixing, and dependency management. OpenCore MCP exposes tools, resources, and prompts through a configurable rules engine that supports multiple programming languages.

## Features

- **Code Analysis** – Analyze codebases against configurable linting and style rules
- **Automated Fixes** – Apply fixes using template-based or programmatic transformations
- **Dependency Management** – Inspect and validate project dependencies
- **Multi-Language Support** – Pre-built rules for JavaScript, TypeScript, and Python
- **Extensible Rules Engine** – YAML/JSON configuration for custom rules
- **MCP Compliance** – Full implementation of Tools, Resources, and Prompts primitives

## Requirements

- Python 3.10+
- pip or uv

## Installation

### From source

```bash
# Clone the repository
git clone https://github.com/opencore/opencore-mcp.git
cd opencore-mcp

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in editable mode
pip install -e ".[dev]"
```

### With uv (recommended)

```bash
uv pip install -e ".[dev]"
```

## Quick Start

### Run the MCP server

```bash
# Using the installed script
opencore-mcp

# Or with uv
uv run opencore-mcp

# Or directly with Python
python -m opencore_mcp.server
```

### Configure Cursor / Claude Desktop

Add to your MCP settings (e.g. `~/.cursor/mcp.json` or Claude Desktop config):

```json
{
  "mcpServers": {
    "opencore-mcp": {
      "command": "uv",
      "args": ["run", "opencore-mcp"],
      "cwd": "/path/to/opencore-mcp"
    }
  }
}
```

Or with a virtual environment:

```json
{
  "mcpServers": {
    "opencore-mcp": {
      "command": "/path/to/opencore-mcp/.venv/bin/python",
      "args": ["-m", "opencore_mcp.server"],
      "cwd": "/path/to/opencore-mcp"
    }
  }
}
```

## Configuration

### Rules

Rules define code quality and style checks. Edit files in `rules/`:

- `rules/config.yaml` – Global rules engine settings
- `rules/javascript.json` – JavaScript/ESLint rules
- `rules/typescript.json` – TypeScript rules
- `rules/python.json` – Python (Ruff/Black) rules

### Example: `rules/config.yaml`

```yaml
default_languages:
  - python
  - typescript
  - javascript

severity_levels:
  error: 1
  warning: 2
  info: 3

fix_strategy: auto  # auto | prompt | none
```

### Fix Templates

Place fix templates in `fixes/templates/`. Templates can reference rule IDs and variables for consistent automated fixes.

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src tests
ruff check src tests

# Type check
mypy src
```

## Project Structure

```
opencore-mcp/
├── pyproject.toml
├── README.md
├── src/
│   └── opencore_mcp/
│       ├── server.py        # Main MCP server
│       ├── models.py        # Pydantic models
│       ├── rules_engine.py  # Rules loading & matching
│       ├── tools/           # MCP tools
│       ├── resources/       # MCP resources
│       └── prompts/         # MCP prompts
├── rules/                   # Rule definitions
├── fixes/templates/         # Fix templates
├── tests/
└── docs/
```

## License

MIT
