"""
Comprehensive Pydantic models for Opencore MCP.

This module defines all data models used throughout the Opencore security analysis
system, including severity levels, vulnerability categories, findings, rules,
patches, and analysis results.

All models are designed with:
- Comprehensive type hints and validation
- Detailed docstrings for documentation
- JSON serialization support via model_config
- Field validation rules for data integrity
"""

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(str, Enum):
    """
    Security vulnerability severity levels.
    
    Based on industry standards (CVSS-like categorization) to prioritize
    remediation efforts. AI-generated code often contains MEDIUM and HIGH
    severity issues due to pattern completion without security context.
    
    Attributes:
        CRITICAL: Immediate exploitation risk, requires urgent remediation.
                  Examples: RCE, SQL injection with admin access.
        HIGH: Significant security impact, should be fixed before deployment.
              Examples: Authentication bypass, privilege escalation.
        MEDIUM: Moderate risk, plan for remediation in current sprint.
                Examples: XSS in non-critical areas, weak crypto.
        LOW: Minor security concern, address as time permits.
             Examples: Information disclosure, verbose errors.
    """
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(str, Enum):
    """
    Security vulnerability categories.
    
    Aligned with OWASP Top 10 and CWE classifications. Each category represents
    a class of vulnerabilities commonly found in both human-written and
    AI-generated code, with AI being particularly prone to certain patterns.
    
    Attributes:
        INJECTION: SQL, Command, LDAP, XPath, Template injection vulnerabilities.
                   AI often generates string concatenation for queries.
        AUTHENTICATION: Missing auth checks, weak sessions, broken authentication.
                        AI may skip auth middleware or use insecure defaults.
        AUTHORIZATION: Missing access control, privilege escalation, IDOR.
                       AI rarely implements proper authorization checks.
        CRYPTOGRAPHY: Weak algorithms (MD5, SHA1), hardcoded keys, insecure random.
                      AI frequently suggests deprecated crypto functions.
        SECRETS: API keys, passwords, tokens hardcoded in source code.
                 AI models trained on code with exposed secrets may replicate them.
        XSS: Cross-site scripting via unsafe DOM manipulation or template rendering.
             AI often outputs user input without proper escaping.
        ERROR_HANDLING: Stack traces exposure, sensitive info in error messages.
                        AI may generate verbose error handling for debugging.
        CONFIGURATION: Insecure defaults, debug mode enabled, security disabled.
                       AI copies configuration patterns without security review.
        DEPENDENCIES: Vulnerable packages, outdated versions, supply chain risks.
                      AI suggests packages based on popularity, not security.
        DATA_VALIDATION: Missing input validation, unsafe parsing, type coercion.
                         AI often trusts input without validation.
        PATH_TRAVERSAL: Unsafe file operations, directory traversal vulnerabilities.
                        AI uses user input directly in file paths.
        DESERIALIZATION: Unsafe pickle, yaml.load, eval, and similar functions.
                         AI uses convenient but dangerous deserialization methods.
    """
    
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    SECRETS = "secrets"
    XSS = "xss"
    ERROR_HANDLING = "error_handling"
    CONFIGURATION = "configuration"
    DEPENDENCIES = "dependencies"
    DATA_VALIDATION = "data_validation"
    PATH_TRAVERSAL = "path_traversal"
    DESERIALIZATION = "deserialization"


class Finding(BaseModel):
    """
    A security finding representing a detected vulnerability.
    
    Contains all information needed for both technical remediation and
    non-technical stakeholder communication. Includes AI-specific context
    explaining why this vulnerability is common in AI-generated code.
    
    Attributes:
        id: Unique identifier for this specific finding instance.
        rule_id: Reference to the security rule that triggered this finding.
        severity: Impact level of the vulnerability.
        category: Classification of the vulnerability type.
        file_path: Relative or absolute path to the affected file.
        line_number: Line where the vulnerability was detected.
        column_number: Column position if available for precise location.
        code_snippet: Relevant code excerpt showing the vulnerable pattern.
        message: Plain language description for non-technical stakeholders.
        technical_detail: Detailed explanation for developers with context.
        cwe: Common Weakness Enumeration identifier (e.g., "CWE-89").
        owasp_category: OWASP Top 10 category if applicable.
        fix_available: Whether an automated fix can be applied.
        confidence: Confidence score (0.0-1.0) for this detection.
        ai_generated_risk: Explanation of why AI commonly generates this issue.
        metadata: Additional context like git blame, dependencies, etc.
    
    Example:
        >>> finding = Finding(
        ...     id="find-001",
        ...     rule_id="sql-injection-001",
        ...     severity=Severity.CRITICAL,
        ...     category=Category.INJECTION,
        ...     file_path="src/db.py",
        ...     line_number=42,
        ...     code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        ...     message="User input used directly in database query",
        ...     technical_detail="String interpolation in SQL query allows injection",
        ...     cwe="CWE-89",
        ...     owasp_category="A03:2021 - Injection",
        ...     fix_available=True,
        ...     confidence=0.95,
        ...     ai_generated_risk="AI models often use f-strings for convenience",
        ...     metadata={"function": "get_user"}
        ... )
    """
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "find-001",
                "rule_id": "sql-injection-001",
                "severity": "critical",
                "category": "injection",
                "file_path": "src/database/queries.py",
                "line_number": 42,
                "column_number": 12,
                "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                "message": "User input is used directly in a database query",
                "technical_detail": "String interpolation in SQL allows attackers to inject malicious SQL",
                "cwe": "CWE-89",
                "owasp_category": "A03:2021 - Injection",
                "fix_available": True,
                "confidence": 0.95,
                "ai_generated_risk": "AI often uses f-strings for SQL queries due to training data patterns",
                "metadata": {"function_name": "get_user_by_id"}
            }
        },
        use_enum_values=True,
    )
    
    id: str = Field(
        ...,
        description="Unique identifier for this finding instance",
        min_length=1,
        examples=["find-001", "vuln-abc123"]
    )
    rule_id: str = Field(
        ...,
        description="ID of the security rule that triggered this finding",
        min_length=1,
        examples=["sql-injection-001", "xss-dom-001"]
    )
    severity: Severity = Field(
        ...,
        description="Impact level of the vulnerability"
    )
    category: Category = Field(
        ...,
        description="Classification of the vulnerability type"
    )
    file_path: str = Field(
        ...,
        description="Path to the file containing the vulnerability",
        min_length=1,
        examples=["src/api/routes.py", "lib/auth.ts"]
    )
    line_number: int = Field(
        ...,
        description="Line number where the vulnerability was detected",
        ge=1
    )
    column_number: Optional[int] = Field(
        default=None,
        description="Column position for precise location",
        ge=1
    )
    code_snippet: str = Field(
        ...,
        description="Code excerpt showing the vulnerable pattern",
        min_length=1
    )
    message: str = Field(
        ...,
        description="Plain language description for non-technical stakeholders",
        min_length=1
    )
    technical_detail: str = Field(
        ...,
        description="Detailed technical explanation for developers",
        min_length=1
    )
    cwe: str = Field(
        ...,
        description="Common Weakness Enumeration identifier",
        pattern=r"^CWE-\d+$",
        examples=["CWE-89", "CWE-79", "CWE-287"]
    )
    owasp_category: Optional[str] = Field(
        default=None,
        description="OWASP Top 10 category reference",
        examples=["A03:2021 - Injection", "A07:2021 - Identification and Authentication Failures"]
    )
    fix_available: bool = Field(
        ...,
        description="Whether an automated fix can be applied"
    )
    confidence: float = Field(
        ...,
        description="Confidence score for this detection (0.0-1.0)",
        ge=0.0,
        le=1.0
    )
    ai_generated_risk: str = Field(
        ...,
        description="Explanation of why AI commonly generates this vulnerability",
        min_length=1
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context (git blame, dependencies, etc.)"
    )
    
    @field_validator("cwe")
    @classmethod
    def validate_cwe_format(cls, v: str) -> str:
        """Ensure CWE follows standard format."""
        if not v.startswith("CWE-"):
            raise ValueError("CWE must start with 'CWE-' prefix")
        return v


class SecurityRule(BaseModel):
    """
    A security rule definition for vulnerability detection.
    
    Defines patterns to match, severity, and context for security issues.
    Rules can be language-specific and include AI-focused explanations
    for why certain patterns are commonly generated by AI assistants.
    
    Attributes:
        id: Unique identifier for the rule.
        name: Human-readable rule name.
        description: Full description of what the rule detects.
        pattern: Regex pattern for matching vulnerable code.
        severity: Default severity level for matches.
        category: Vulnerability category classification.
        message: Template message for findings.
        technical_detail: Technical explanation template.
        cwe: Associated CWE identifier.
        owasp_category: Associated OWASP Top 10 category.
        language: Programming language this rule applies to.
        ai_risk_explanation: Why AI models commonly generate this pattern.
        enabled: Whether the rule is active.
        fix_template: Optional template for automated fixes.
    
    Example:
        >>> rule = SecurityRule(
        ...     id="sql-injection-001",
        ...     name="SQL Injection via String Interpolation",
        ...     description="Detects SQL queries built with string interpolation",
        ...     pattern=r'(execute|query)\([^)]*[fF]["\'][^"\']*\{',
        ...     severity=Severity.CRITICAL,
        ...     category=Category.INJECTION,
        ...     message="SQL query uses string interpolation with user input",
        ...     technical_detail="Use parameterized queries to prevent injection",
        ...     cwe="CWE-89",
        ...     owasp_category="A03:2021 - Injection",
        ...     language="python",
        ...     ai_risk_explanation="AI often uses f-strings for convenience",
        ...     enabled=True,
        ...     fix_template="cursor.execute(query, (param,))"
        ... )
    """
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "sql-injection-001",
                "name": "SQL Injection via String Interpolation",
                "description": "Detects SQL queries built using string interpolation",
                "pattern": r'(execute|query)\([^)]*[fF]["\'][^"\']*\{',
                "severity": "critical",
                "category": "injection",
                "message": "SQL query constructed with string interpolation",
                "technical_detail": "Use parameterized queries instead of string interpolation",
                "cwe": "CWE-89",
                "owasp_category": "A03:2021 - Injection",
                "language": "python",
                "ai_risk_explanation": "AI assistants often generate f-strings for readability",
                "enabled": True,
                "fix_template": "cursor.execute(query, (param,))"
            }
        },
        use_enum_values=True,
    )
    
    id: str = Field(
        ...,
        description="Unique identifier for the rule",
        min_length=1,
        pattern=r"^[a-z0-9-]+$",
        examples=["sql-injection-001", "xss-dom-001"]
    )
    name: str = Field(
        ...,
        description="Human-readable rule name",
        min_length=1,
        max_length=200
    )
    description: str = Field(
        ...,
        description="Full description of what the rule detects",
        min_length=1
    )
    pattern: str = Field(
        ...,
        description="Regex pattern for matching vulnerable code",
        min_length=1
    )
    severity: Severity = Field(
        ...,
        description="Default severity level for matches"
    )
    category: Category = Field(
        ...,
        description="Vulnerability category classification"
    )
    message: str = Field(
        ...,
        description="Template message for generated findings",
        min_length=1
    )
    technical_detail: str = Field(
        ...,
        description="Technical explanation template for developers",
        min_length=1
    )
    cwe: str = Field(
        ...,
        description="Associated CWE identifier",
        pattern=r"^CWE-\d+$",
        examples=["CWE-89", "CWE-79"]
    )
    owasp_category: Optional[str] = Field(
        default=None,
        description="Associated OWASP Top 10 category",
        examples=["A03:2021 - Injection"]
    )
    language: str = Field(
        ...,
        description="Programming language this rule applies to",
        min_length=1,
        examples=["python", "javascript", "typescript", "java"]
    )
    ai_risk_explanation: str = Field(
        ...,
        description="Explanation of why AI models commonly generate this pattern",
        min_length=1
    )
    enabled: bool = Field(
        default=True,
        description="Whether the rule is active"
    )
    fix_template: Optional[str] = Field(
        default=None,
        description="Template for automated fixes"
    )
    
    @field_validator("cwe")
    @classmethod
    def validate_cwe_format(cls, v: str) -> str:
        """Ensure CWE follows standard format."""
        if not v.startswith("CWE-"):
            raise ValueError("CWE must start with 'CWE-' prefix")
        return v


class CodePatch(BaseModel):
    """
    A code patch representing a security fix.
    
    Contains the original and fixed code along with explanations for both
    technical and non-technical audiences. Supports multi-file patches
    for fixes that require changes across multiple files.
    
    Attributes:
        finding_id: Reference to the finding this patch addresses.
        old_code: Original vulnerable code to be replaced.
        new_code: Secure replacement code.
        explanation: Human-readable explanation of the change.
        file_path: Path to the file being modified.
        line_start: Starting line number for the patch.
        line_end: Ending line number for the patch.
        additional_files: Additional file changes if the fix spans files.
        security_rationale: Detailed explanation of why this fix is secure.
    
    Example:
        >>> patch = CodePatch(
        ...     finding_id="find-001",
        ...     old_code='query = f"SELECT * FROM users WHERE id = {user_id}"',
        ...     new_code='query = "SELECT * FROM users WHERE id = %s"',
        ...     explanation="Use parameterized query instead of string interpolation",
        ...     file_path="src/db.py",
        ...     line_start=42,
        ...     line_end=42,
        ...     security_rationale="Parameterized queries separate code from data"
        ... )
    """
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "finding_id": "find-001",
                "old_code": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                "new_code": 'query = "SELECT * FROM users WHERE id = %s"\ncursor.execute(query, (user_id,))',
                "explanation": "Replace string interpolation with parameterized query",
                "file_path": "src/database/queries.py",
                "line_start": 42,
                "line_end": 43,
                "additional_files": None,
                "security_rationale": "Parameterized queries prevent SQL injection by separating SQL logic from data"
            }
        }
    )
    
    finding_id: str = Field(
        ...,
        description="Reference to the finding this patch addresses",
        min_length=1
    )
    old_code: str = Field(
        ...,
        description="Original vulnerable code to be replaced"
    )
    new_code: str = Field(
        ...,
        description="Secure replacement code"
    )
    explanation: str = Field(
        ...,
        description="Human-readable explanation of the change",
        min_length=1
    )
    file_path: str = Field(
        ...,
        description="Path to the file being modified",
        min_length=1
    )
    line_start: int = Field(
        ...,
        description="Starting line number for the patch",
        ge=1
    )
    line_end: int = Field(
        ...,
        description="Ending line number for the patch",
        ge=1
    )
    additional_files: Optional[list[dict[str, Any]]] = Field(
        default=None,
        description="Additional file changes if fix spans multiple files"
    )
    security_rationale: str = Field(
        ...,
        description="Detailed explanation of why this fix improves security",
        min_length=1
    )
    
    @field_validator("line_end")
    @classmethod
    def validate_line_range(cls, v: int, info) -> int:
        """Ensure line_end >= line_start."""
        line_start = info.data.get("line_start")
        if line_start is not None and v < line_start:
            raise ValueError("line_end must be >= line_start")
        return v


class AnalysisRequest(BaseModel):
    """
    Request model for code analysis.
    
    Represents a request to analyze code for security vulnerabilities.
    Can specify either a file path (for on-disk files) or inline code
    content with an optional language hint.
    
    Attributes:
        file_path: Path to the file to analyze.
        code: Optional inline code content to analyze.
        language: Optional language hint for the analyzer.
    
    Example:
        >>> # Analyze a file on disk
        >>> request = AnalysisRequest(file_path="src/api/routes.py")
        >>> 
        >>> # Analyze inline code
        >>> request = AnalysisRequest(
        ...     file_path="inline.py",
        ...     code='import os; os.system(user_input)',
        ...     language="python"
        ... )
    """
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "file_path": "src/api/routes.py",
                "code": None,
                "language": "python"
            }
        }
    )
    
    file_path: str = Field(
        ...,
        description="Path to the file to analyze",
        min_length=1
    )
    code: Optional[str] = Field(
        default=None,
        description="Optional inline code content to analyze"
    )
    language: Optional[str] = Field(
        default=None,
        description="Optional language hint for the analyzer",
        examples=["python", "javascript", "typescript", "java"]
    )


class AnalysisResult(BaseModel):
    """
    Result of a security analysis operation.
    
    Contains all findings from the analysis along with summary statistics
    for quick assessment of code security posture. Provides breakdown by
    severity and category for prioritization.
    
    Attributes:
        findings: List of all security findings detected.
        scanned_files: Number of files that were analyzed.
        total_issues: Total count of all findings.
        critical_count: Number of CRITICAL severity findings.
        high_count: Number of HIGH severity findings.
        medium_count: Number of MEDIUM severity findings.
        low_count: Number of LOW severity findings.
        categories_affected: Count of findings by category.
    
    Example:
        >>> result = AnalysisResult(
        ...     findings=[finding1, finding2],
        ...     scanned_files=10,
        ...     total_issues=2,
        ...     critical_count=1,
        ...     high_count=1,
        ...     medium_count=0,
        ...     low_count=0,
        ...     categories_affected={Category.INJECTION: 1, Category.XSS: 1}
        ... )
    """
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "findings": [],
                "scanned_files": 15,
                "total_issues": 5,
                "critical_count": 1,
                "high_count": 2,
                "medium_count": 1,
                "low_count": 1,
                "categories_affected": {
                    "injection": 2,
                    "xss": 1,
                    "authentication": 1,
                    "secrets": 1
                }
            }
        },
        use_enum_values=True,
    )
    
    findings: list[Finding] = Field(
        default_factory=list,
        description="List of all security findings detected"
    )
    scanned_files: int = Field(
        default=0,
        description="Number of files that were analyzed",
        ge=0
    )
    total_issues: int = Field(
        default=0,
        description="Total count of all findings",
        ge=0
    )
    critical_count: int = Field(
        default=0,
        description="Number of CRITICAL severity findings",
        ge=0
    )
    high_count: int = Field(
        default=0,
        description="Number of HIGH severity findings",
        ge=0
    )
    medium_count: int = Field(
        default=0,
        description="Number of MEDIUM severity findings",
        ge=0
    )
    low_count: int = Field(
        default=0,
        description="Number of LOW severity findings",
        ge=0
    )
    categories_affected: dict[Category, int] = Field(
        default_factory=dict,
        description="Count of findings by vulnerability category"
    )
    
    @field_validator("total_issues")
    @classmethod
    def validate_total_matches_findings(cls, v: int, info) -> int:
        """Validate total_issues matches findings list length if provided."""
        findings = info.data.get("findings", [])
        if findings and v != len(findings):
            raise ValueError(
                f"total_issues ({v}) must match findings count ({len(findings)})"
            )
        return v


# Backwards compatibility aliases for existing code
class RuleResult(Finding):
    """
    Alias for Finding for backwards compatibility.
    
    Deprecated: Use Finding instead.
    """
    pass


class FixResult(BaseModel):
    """
    Result of applying a security fix.
    
    Represents the outcome of attempting to apply a CodePatch to fix
    a security vulnerability.
    
    Attributes:
        success: Whether the fix was applied successfully.
        file_path: Path to the modified file.
        message: Description of the change or error.
        original_content: Original file content before the fix.
        fixed_content: File content after applying the fix.
    """
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": True,
                "file_path": "src/api/routes.py",
                "message": "Applied SQL injection fix using parameterized queries",
                "original_content": None,
                "fixed_content": None
            }
        }
    )
    
    success: bool = Field(
        ...,
        description="Whether the fix was applied successfully"
    )
    file_path: str = Field(
        ...,
        description="Path to the modified file"
    )
    message: str = Field(
        ...,
        description="Description of the change or error message"
    )
    original_content: Optional[str] = Field(
        default=None,
        description="Original file content before the fix"
    )
    fixed_content: Optional[str] = Field(
        default=None,
        description="File content after applying the fix"
    )


class DependencyInfo(BaseModel):
    """
    Information about a project dependency.
    
    Contains version and security status information for a single
    package dependency.
    
    Attributes:
        name: Package name.
        version: Currently installed version.
        required_version: Version constraint from dependency file.
        latest_version: Latest available version.
        is_outdated: Whether the package is outdated.
        is_dev: Whether this is a development dependency.
        vulnerabilities: List of known vulnerabilities for this version.
    """
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "requests",
                "version": "2.28.0",
                "required_version": ">=2.28.0",
                "latest_version": "2.31.0",
                "is_outdated": True,
                "is_dev": False,
                "vulnerabilities": []
            }
        }
    )
    
    name: str = Field(
        ...,
        description="Package name"
    )
    version: Optional[str] = Field(
        default=None,
        description="Currently installed version"
    )
    required_version: Optional[str] = Field(
        default=None,
        description="Version constraint from dependency file"
    )
    latest_version: Optional[str] = Field(
        default=None,
        description="Latest available version"
    )
    is_outdated: bool = Field(
        default=False,
        description="Whether the package is outdated"
    )
    is_dev: bool = Field(
        default=False,
        description="Whether this is a development dependency"
    )
    vulnerabilities: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of known vulnerabilities for this version"
    )


class DependencyReport(BaseModel):
    """
    Report of project dependencies analysis.
    
    Aggregated report of all dependencies in a project including
    outdated packages and known vulnerabilities.
    
    Attributes:
        dependencies: List of all dependency information.
        total_count: Total number of dependencies.
        outdated_count: Number of outdated dependencies.
        vulnerable_count: Number of dependencies with known vulnerabilities.
        project_path: Path to the analyzed project.
    """
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "dependencies": [],
                "total_count": 25,
                "outdated_count": 5,
                "vulnerable_count": 1,
                "project_path": "/path/to/project"
            }
        }
    )
    
    dependencies: list[DependencyInfo] = Field(
        default_factory=list,
        description="List of all dependency information"
    )
    total_count: int = Field(
        default=0,
        description="Total number of dependencies",
        ge=0
    )
    outdated_count: int = Field(
        default=0,
        description="Number of outdated dependencies",
        ge=0
    )
    vulnerable_count: int = Field(
        default=0,
        description="Number of dependencies with known vulnerabilities",
        ge=0
    )
    project_path: str = Field(
        default=".",
        description="Path to the analyzed project"
    )
