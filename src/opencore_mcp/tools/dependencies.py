"""
Dependency inspection and vulnerability scanning.

Supports package.json, package-lock.json, requirements.txt, pyproject.toml,
and poetry.lock. Compares resolved or declared versions against a known
vulnerability database (rules/known_vulnerabilities.json) using semantic
version comparison (packaging for Python, semver for JavaScript/TypeScript).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from opencore_mcp.models import DependencyInfo, DependencyReport


# -----------------------------------------------------------------------------
# Rules directory resolution (aligned with rules_engine)
# -----------------------------------------------------------------------------


def _rules_dir_path(rules_dir: str = "rules") -> Path:
    """Resolve the rules directory path for known_vulnerabilities.json."""
    if env_path := os.environ.get("OPENCORE_MCP_RULES_DIR"):
        return Path(env_path)
    pkg_dir = Path(__file__).resolve().parent.parent
    project_root = pkg_dir.parent
    candidates = [
        project_root / rules_dir,
        Path.cwd() / rules_dir,
        pkg_dir / rules_dir,
        Path(rules_dir),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return project_root / rules_dir


def _find_project_root(start: Path) -> Path | None:
    """Find project root by looking for package manifests."""
    current = start.resolve()
    for _ in range(10):
        if (current / "pyproject.toml").exists():
            return current
        if (current / "package.json").exists():
            return current
        if (current / "requirements.txt").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


# -----------------------------------------------------------------------------
# File type detection and dependency parsing
# -----------------------------------------------------------------------------

FILE_TYPES = {
    "package.json": "javascript",
    "package-lock.json": "javascript",
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "poetry.lock": "python",
}


def _detect_file_type(package_file: str) -> tuple[str, str] | None:
    """Return (file_type_key, language) or None if unsupported."""
    name = Path(package_file).name.lower()
    for key, lang in FILE_TYPES.items():
        if name == key.lower():
            return (key, lang)
    return None


def _parse_package_json(path: Path) -> list[tuple[str, str]]:
    """Parse package.json; return list of (name, version_spec)."""
    data = json.loads(path.read_text())
    deps: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        obj = data.get(section, {})
        for name, ver in obj.items():
            if isinstance(ver, str):
                deps.append((name, ver))
    return deps


def _parse_package_lock(path: Path) -> list[tuple[str, str]]:
    """Parse package-lock.json; return list of (name, exact_version)."""
    data = json.loads(path.read_text())
    deps: list[tuple[str, str]] = []
    packages = data.get("packages") or {}
    # npm v7+ lockfile has "packages" with "" for root
    for key, info in packages.items():
        if key == "" or not isinstance(info, dict):
            continue
        name = key.removeprefix("node_modules/")
        if "/" in name and not name.startswith("@"):
            continue
        ver = info.get("version")
        if ver:
            deps.append((name, ver))
    # Fallback for npm v6 lockfile
    if not deps and "dependencies" in data:
        def collect(deps_obj: dict, prefix: str = "") -> None:
            for name, info in deps_obj.items():
                if isinstance(info, dict) and "version" in info:
                    deps.append((prefix + name, info["version"]))
                if isinstance(info, dict) and "dependencies" in info:
                    collect(info["dependencies"], prefix + name + "/")
        collect(data["dependencies"])
    return deps


def _parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    """Parse requirements.txt; return list of (name, spec)."""
    deps: list[tuple[str, str]] = []
    for line in path.read_text().splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        # Match package name and optional version spec
        match = re.match(r"^([a-zA-Z0-9_-]+)\s*([^\s#]+)?", line)
        if match:
            name = match.group(1).lower()
            spec = (match.group(2) or "").strip()
            if not spec:
                spec = "any"
            deps.append((name, spec))
    return deps


def _parse_pyproject(path: Path) -> list[tuple[str, str]]:
    """Parse pyproject.toml dependencies; return list of (name, spec)."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]
    data = tomllib.loads(path.read_text())
    project = data.get("project", data)
    requires = project.get("dependencies", [])
    deps: list[tuple[str, str]] = []
    for spec in requires:
        if not isinstance(spec, str):
            continue
        # Extract name (before first version operator)
        name = re.split(r"\[|==|>=|<=|~=|<|>|!=", spec)[0].strip()
        try:
            from packaging.utils import canonicalize_name
            name = canonicalize_name(name)
        except Exception:
            name = name.lower().replace("_", "-")
        deps.append((name, spec))
    return deps


def _parse_poetry_lock(path: Path) -> list[tuple[str, str]]:
    """Parse poetry.lock; return list of (name, exact_version)."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]
    data = tomllib.loads(path.read_text())
    deps: list[tuple[str, str]] = []
    for package in data.get("package", []):
        name = package.get("name")
        version = package.get("version")
        if name and version:
            try:
                from packaging.utils import canonicalize_name
                name = canonicalize_name(name)
            except Exception:
                name = name.lower().replace("_", "-")
            deps.append((name, version))
    return deps


def _parse_dependencies(package_file: str) -> tuple[list[tuple[str, str]], str]:
    """
    Parse the given package file and return (list of (name, version_or_spec), language).
    Raises FileNotFoundError or ValueError for invalid/unsupported files.
    """
    path = Path(package_file).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Package file not found: {package_file}")

    detected = _detect_file_type(package_file)
    if not detected:
        raise ValueError(
            f"Unsupported package file: {path.name}. "
            f"Supported: {', '.join(FILE_TYPES)}"
        )
    file_key, language = detected

    if file_key == "package.json":
        return _parse_package_json(path), language
    if file_key == "package-lock.json":
        return _parse_package_lock(path), language
    if file_key == "requirements.txt":
        return _parse_requirements_txt(path), language
    if file_key == "pyproject.toml":
        return _parse_pyproject(path), language
    if file_key == "poetry.lock":
        return _parse_poetry_lock(path), language
    return [], language


# -----------------------------------------------------------------------------
# Vulnerability database and version comparison
# -----------------------------------------------------------------------------


def _load_vulnerability_database() -> list[dict[str, Any]]:
    """Load rules/known_vulnerabilities.json."""
    rules_dir = _rules_dir_path()
    path = rules_dir / "known_vulnerabilities.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else data.get("vulnerabilities", [])


def _normalize_package_name(name: str, language: str) -> str:
    """Normalize package name for lookup (e.g. PyYAML -> pyyaml for Python)."""
    if language == "python":
        try:
            from packaging.utils import canonicalize_name
            return canonicalize_name(name)
        except Exception:
            return name.lower().replace("_", "-")
    return name.lower()


def _parse_version_python(version_str: str) -> Any:
    """Parse version string for Python; returns comparable Version or None."""
    try:
        from packaging.version import InvalidVersion, Version
        # Strip common suffixes for comparison
        v = version_str.strip().split(" ")[0]
        return Version(v)
    except (InvalidVersion, Exception):
        return None


def _parse_version_javascript(version_str: str) -> Any:
    """Parse version string for JavaScript; returns comparable version or None."""
    s = re.sub(r"^[\^~v=<>]*", "", version_str.strip()).strip()
    try:
        import semver
        return semver.VersionInfo.parse(s)
    except Exception:
        try:
            from packaging.version import Version
            return Version(s)
        except Exception:
            return None


def _version_satisfies_vulnerable_spec(
    current_version: Any,
    vulnerable_versions: str,
    fixed_version: str,
    language: str,
) -> bool:
    """
    Return True if current_version is within the vulnerable range.
    vulnerable_versions is typically '<X.Y.Z'; we treat as "versions < fixed_version".
    """
    if current_version is None:
        return False
    try:
        if language == "python":
            from packaging.specifiers import SpecifierSet
            from packaging.version import Version
            try:
                spec = SpecifierSet(vulnerable_versions)
                return current_version in spec
            except Exception:
                try:
                    fixed = Version(fixed_version)
                    return current_version < fixed
                except Exception:
                    return False
        else:
            # JavaScript: compare with fixed_version (semver)
            fixed = _parse_version_javascript(fixed_version)
            if fixed is None:
                return False
            try:
                return current_version < fixed
            except TypeError:
                # Fallback if one is packaging.Version
                return getattr(current_version, "compare", lambda o: 0)(fixed) < 0
    except Exception:
        return False


def _extract_exact_version(spec: str, language: str) -> str | None:
    """Extract a single comparable version from a spec if possible (e.g. ==1.2.3)."""
    spec = spec.strip()
    if language == "python":
        match = re.match(r"^==\s*(.+)$", spec)
        if match:
            return match.group(1).strip()
        match = re.match(r"^(.+?)\s*$", spec)
        if match and re.match(r"^\d+\.\d+", match.group(1)):
            return match.group(1)
    else:
        # JS: remove ^ ~
        s = re.sub(r"^[\^~]", "", spec).strip()
        if re.match(r"^\d+\.\d+", s):
            return s
    return None


def _check_single_dep(
    name: str,
    version_or_spec: str,
    language: str,
    vuln_db: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Check one dependency against vuln DB; return vuln entry dict or None."""
    norm_name = _normalize_package_name(name, language)
    for entry in vuln_db:
        if entry.get("language") != language:
            continue
        db_name = _normalize_package_name(entry.get("package", ""), language)
        if db_name != norm_name:
            continue
        fixed_version = entry.get("fixed_version", "")
        vulnerable_versions = entry.get("vulnerable_versions", "")
        current_ver: Any = None
        if language == "python":
            current_ver = _parse_version_python(version_or_spec)
            if current_ver is None:
                current_ver = _parse_version_python(_extract_exact_version(version_or_spec, language) or "")
        else:
            current_ver = _parse_version_javascript(version_or_spec)
        if current_ver is None:
            # Declared range only: cannot confirm vulnerability without exact version
            continue
        if _version_satisfies_vulnerable_spec(
            current_ver, vulnerable_versions, fixed_version, language
        ):
            # Prefer clean version string for display when we have exact version
            display_version = _extract_exact_version(version_or_spec, language) or str(version_or_spec).strip()
            return {
                "name": name,
                "current_version": display_version,
                "vulnerable_versions": vulnerable_versions,
                "cve": entry.get("cve", ""),
                "severity": entry.get("severity", "medium"),
                "fixed_version": fixed_version,
                "recommendation": f"Update to {entry.get('package', name)}@{fixed_version} or later",
                "ai_context": entry.get("ai_risk", ""),
            }
    return None


# -----------------------------------------------------------------------------
# Public API: get_dependencies (existing) and check_dependencies (new)
# -----------------------------------------------------------------------------


def get_dependencies(project_path: str | Path | None = None) -> DependencyReport:
    """
    Inspect dependencies for a project.

    Supports pyproject.toml, package.json, and requirements.txt.

    Args:
        project_path: Path to project root. Defaults to current directory.

    Returns:
        DependencyReport with dependency information.
    """
    start = Path(project_path or ".").resolve()
    root = _find_project_root(start) or start

    deps: list[DependencyInfo] = []
    outdated_count = 0

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text()
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]

        try:
            data = tomllib.loads(text)
        except Exception:
            data = None
        if data:
            project = data.get("project", data)
            requires = project.get("dependencies", [])
            optional = project.get("optional-dependencies", {})
            dev_deps: list[str] = []
            for v in optional.values():
                if isinstance(v, list):
                    dev_deps.extend(v)

            for spec in requires:
                if isinstance(spec, str):
                    name = spec.split("[")[0].split("==")[0].split(">=")[0].split("~=")[0].strip()
                    deps.append(
                        DependencyInfo(
                            name=name,
                            required_version=spec,
                            is_dev=spec in dev_deps,
                        )
                    )

    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text())
            deps_obj = data.get("dependencies", {})
            dev_deps_obj = data.get("devDependencies", {})

            for name, ver in deps_obj.items():
                deps.append(
                    DependencyInfo(
                        name=name,
                        required_version=ver if isinstance(ver, str) else str(ver),
                        is_dev=False,
                    )
                )
            for name, ver in dev_deps_obj.items():
                deps.append(
                    DependencyInfo(
                        name=name,
                        required_version=ver if isinstance(ver, str) else str(ver),
                        is_dev=True,
                    )
                )
        except json.JSONDecodeError:
            pass

    return DependencyReport(
        dependencies=deps,
        total_count=len(deps),
        outdated_count=outdated_count,
        project_path=str(root),
    )


async def check_dependencies(package_file: str) -> dict[str, Any]:
    """
    Scan a package file for known vulnerabilities.

    Detects file type (package.json, package-lock.json, requirements.txt,
    pyproject.toml, poetry.lock), parses dependencies, and checks against
    rules/known_vulnerabilities.json. Uses semantic version comparison
    (packaging for Python, semver for JavaScript/TypeScript).

    Args:
        package_file: Path to the package file (e.g. "package.json", "requirements.txt").

    Returns:
        Dict with vulnerable_packages, total_dependencies, vulnerable_count, summary.
    """
    parsed, language = _parse_dependencies(package_file)
    vuln_db = _load_vulnerability_database()
    vulnerable: list[dict[str, Any]] = []
    for name, version_or_spec in parsed:
        hit = _check_single_dep(name, version_or_spec, language, vuln_db)
        if hit:
            vulnerable.append(hit)
    total = len(parsed)
    count = len(vulnerable)
    summary = (
        f"Found {count} vulnerable dependencies with known CVEs"
        if count
        else "No known vulnerable dependencies found"
    )
    return {
        "vulnerable_packages": vulnerable,
        "total_dependencies": total,
        "vulnerable_count": count,
        "summary": summary,
    }
