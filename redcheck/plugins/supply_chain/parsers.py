"""RedCheck246 — Dependency file parsers.

Supports:
  - requirements.txt  (with version specifiers, -r includes, comments)
  - pyproject.toml    (PEP 621 dependencies + optional-dependencies)
  - package.json      (npm dependencies + devDependencies)
"""

from __future__ import annotations

import json
import re
from pathlib import Path  # noqa: TC003


def parse_requirements_txt(path: Path) -> list[dict[str, str]]:
    """Parse a requirements.txt into a list of {name, version, specifier}."""
    deps: list[dict[str, str]] = []
    if not path.exists():
        return deps

    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle extras, e.g. package[extra]>=1.0
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(.*)", line)
        if match:
            name = match.group(1).strip()
            spec = match.group(2).strip()
            # Extract version from specifier like ==1.0, >=2.0,<3
            version = ""
            ver_match = re.search(r"[=<>!~]=?\s*([0-9][0-9a-zA-Z.*]*)", spec)
            if ver_match:
                version = ver_match.group(1)
            deps.append(
                {
                    "name": name.lower(),
                    "version": version,
                    "specifier": spec,
                    "ecosystem": "PyPI",
                }
            )
    return deps


def parse_pyproject_toml(path: Path) -> list[dict[str, str]]:
    """Parse dependencies from pyproject.toml (PEP 621 format)."""
    deps: list[dict[str, str]] = []
    if not path.exists():
        return deps

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return deps

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return deps

    project = data.get("project", {})
    raw_deps = project.get("dependencies", [])

    for dep_str in raw_deps:
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(.*)", dep_str)
        if match:
            name = match.group(1).strip()
            spec = match.group(2).strip()
            version = ""
            ver_match = re.search(r"[=<>!~]=?\s*([0-9][0-9a-zA-Z.*]*)", spec)
            if ver_match:
                version = ver_match.group(1)
            deps.append(
                {
                    "name": name.lower(),
                    "version": version,
                    "specifier": spec,
                    "ecosystem": "PyPI",
                }
            )

    # Optional dependencies
    for _group, opt_deps in project.get("optional-dependencies", {}).items():
        for dep_str in opt_deps:
            match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(.*)", dep_str)
            if match:
                name = match.group(1).strip()
                spec = match.group(2).strip()
                version = ""
                ver_match = re.search(r"[=<>!~]=?\s*([0-9][0-9a-zA-Z.*]*)", spec)
                if ver_match:
                    version = ver_match.group(1)
                deps.append(
                    {
                        "name": name.lower(),
                        "version": version,
                        "specifier": spec,
                        "ecosystem": "PyPI",
                    }
                )
    return deps


def parse_package_json(path: Path) -> list[dict[str, str]]:
    """Parse dependencies from package.json (npm)."""
    deps: list[dict[str, str]] = []
    if not path.exists():
        return deps

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return deps

    for section in ("dependencies", "devDependencies"):
        for name, version_spec in data.get(section, {}).items():
            # Strip leading ^ or ~ for version
            version = re.sub(r"^[\^~>=<]", "", version_spec).strip()
            deps.append(
                {
                    "name": name.lower(),
                    "version": version,
                    "specifier": version_spec,
                    "ecosystem": "npm",
                }
            )
    return deps


def discover_dependency_files(root: Path) -> list[Path]:
    """Find all dependency files under *root*."""
    targets = [
        "requirements.txt",
        "requirements-dev.txt",
        "requirements.in",
        "pyproject.toml",
        "package.json",
    ]
    found: list[Path] = []
    for name in targets:
        p = root / name
        if p.exists():
            found.append(p)
    return found


def parse_dependency_file(path: Path) -> list[dict[str, str]]:
    """Auto-detect and parse a dependency file."""
    name = path.name.lower()
    if name in ("requirements.txt", "requirements-dev.txt", "requirements.in"):
        return parse_requirements_txt(path)
    if name == "pyproject.toml":
        return parse_pyproject_toml(path)
    if name == "package.json":
        return parse_package_json(path)
    return []
