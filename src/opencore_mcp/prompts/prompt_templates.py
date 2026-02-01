"""Prompt templates for code review and fixing workflows."""

CODE_REVIEW_PROMPT = """You are a code reviewer. Review the following code for quality, style, and potential issues.

**Language:** {language}
**File:** {file_path}

**Code to review:**
```
{code}
```

**Analysis results (from rules engine):**
{analysis}

Provide a structured review with:
1. Summary of findings
2. Critical issues (if any)
3. Suggestions for improvement
4. Specific line references where applicable
"""

FIX_SUGGESTION_PROMPT = """Suggest a fix for the following code issue.

**Rule ID:** {rule_id}
**Message:** {message}
**File:** {file_path}
**Line:** {line}

**Current code:**
```
{code}
```

Provide a concrete fix. If the fix is straightforward, show the exact replacement. Otherwise, explain the approach.
"""

DEPENDENCY_REVIEW_PROMPT = """Review the project dependencies and suggest improvements.

**Project path:** {project_path}

**Dependencies:**
{dependencies}

Consider:
1. Outdated packages that should be updated
2. Security vulnerabilities
3. Unused or redundant dependencies
4. Version constraint best practices
5. Dev vs production dependency organization
"""
