# Contributing to RedCheck246

Thank you for considering contributing to RedCheck246! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating, you agree to maintain a respectful and inclusive environment.

## Getting Started

### Prerequisites

- Python 3.10+
- Git
- (Optional) Docker for containerized development

### Development Setup

```bash
# Clone the repository
git clone https://github.com/SERVER-246/RedCheck246.git
cd RedCheck246

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install in development mode
cd RedCheck246
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Verify installation
redcheck --version
pytest tests/ -v
```

## Development Workflow

### Branch Naming

- `feature/<name>` — New features
- `fix/<name>` — Bug fixes
- `security/<name>` — Security patches
- `docs/<name>` — Documentation updates

### Making Changes

1. Create a branch from `main`
2. Make your changes
3. Add or update tests
4. Run the quality checks:

```bash
# Lint + format
ruff check redcheck/ tests/
ruff format redcheck/ tests/

# Type check
mypy --strict redcheck/

# Security scan
bandit -r redcheck/ -c pyproject.toml

# Tests
pytest tests/ -v --cov=redcheck
```

5. Commit with a clear message
6. Open a pull request

### Commit Messages

Use conventional commit format:

```
type(scope): description

feat(recon): add certificate transparency module
fix(crypto): handle empty passphrase edge case
test(dast): add security header analysis tests
docs(readme): update installation instructions
```

## Architecture

### Plugin System

All plugins inherit from `BasePlugin` and auto-register via `__init_subclass__`. See `docs/plugin-development.md` for the full guide.

### Key Principles

- **Policy-gated execution** — Every scan requires valid RoE + activation
- **Structured logging** — All modules use `structlog`
- **Custom exceptions** — All errors use classes from `exceptions.py`
- **Pydantic v2 models** — All data structures validated at boundaries
- **Async-first plugins** — Network I/O uses `httpx.AsyncClient`

### Directory Structure

```
redcheck/
├── __init__.py          # Version + public exports
├── cli.py               # Typer CLI (7 commands)
├── config.py            # Pydantic BaseSettings
├── exceptions.py        # 11 custom exception classes
├── logging.py           # structlog configuration
├── models.py            # 13 Pydantic v2 models
├── output.py            # Rich terminal formatting
├── core/
│   ├── activation_engine.py
│   ├── audit.py
│   ├── orchestrator.py
│   └── policy_engine.py
├── plugins/
│   ├── base_plugin.py
│   ├── recon/
│   ├── sast/
│   ├── dast/
│   ├── fuzzing/
│   └── supply_chain/
└── security/
    ├── crypto.py
    ├── roe_validator.py
    └── signature_verifier.py
```

## Testing

- Target: 160+ tests
- All tests must pass on Python 3.10, 3.11, 3.12, and 3.13
- Use `conftest.py` fixtures for test isolation
- Mock all network calls in tests

## Security

If you find a security vulnerability, **do NOT open a public issue**. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the project's existing license.
