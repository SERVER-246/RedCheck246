# =============================================================================
# RedCheck246 Makefile
# =============================================================================
# Usage: make <target>
# =============================================================================

.DEFAULT_GOAL := help
SHELL := /bin/bash
PYTHON := python
PIP := pip

# Project paths
SRC_DIR := redcheck
TEST_DIR := tests

.PHONY: help install install-dev test lint format type-check security build clean docker docker-dev

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

install: ## Install RedCheck246 (production)
	$(PIP) install .

install-dev: ## Install RedCheck246 (development, editable)
	$(PIP) install -e ".[dev]"

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------

test: ## Run test suite with coverage
	$(PYTHON) -m pytest $(TEST_DIR)/ -v --cov=$(SRC_DIR) --cov-report=term-missing

lint: ## Run ruff linter
	ruff check $(SRC_DIR)/ $(TEST_DIR)/

format: ## Format code with ruff
	ruff format $(SRC_DIR)/ $(TEST_DIR)/

type-check: ## Run mypy type checker
	mypy --strict $(SRC_DIR)/ || true

security: ## Run bandit security scan
	bandit -r $(SRC_DIR)/ -c pyproject.toml

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

build: ## Build wheel and sdist
	$(PYTHON) -m build

clean: ## Clean build artifacts
	rm -rf dist/ build/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

docker: ## Build production Docker image
	docker build --target runtime -t redcheck246:latest .

docker-dev: ## Build development Docker image
	docker build --target dev -t redcheck246:dev .

# ---------------------------------------------------------------------------
# All-in-one
# ---------------------------------------------------------------------------

ci: lint type-check test security build ## Run full CI pipeline locally
