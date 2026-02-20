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
PROJECT_DIR := RedCheck246
SRC_DIR := $(PROJECT_DIR)/redcheck
TEST_DIR := $(PROJECT_DIR)/tests

.PHONY: help install install-dev test lint format type-check security build clean docker docker-dev

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

install: ## Install RedCheck246 (production)
	cd $(PROJECT_DIR) && $(PIP) install .

install-dev: ## Install RedCheck246 (development, editable)
	cd $(PROJECT_DIR) && $(PIP) install -e ".[dev]"

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------

test: ## Run test suite with coverage
	cd $(PROJECT_DIR) && $(PYTHON) -m pytest tests/ -v --cov=redcheck --cov-report=term-missing

lint: ## Run ruff linter
	cd $(PROJECT_DIR) && ruff check $(SRC_DIR)/ $(TEST_DIR)/

format: ## Format code with ruff
	cd $(PROJECT_DIR) && ruff format $(SRC_DIR)/ $(TEST_DIR)/

type-check: ## Run mypy type checker
	cd $(PROJECT_DIR) && mypy --strict $(SRC_DIR)/ || true

security: ## Run bandit security scan
	cd $(PROJECT_DIR) && bandit -r $(SRC_DIR)/ -c pyproject.toml

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

build: ## Build wheel and sdist
	cd $(PROJECT_DIR) && $(PYTHON) -m build

clean: ## Clean build artifacts
	rm -rf $(PROJECT_DIR)/dist $(PROJECT_DIR)/build $(PROJECT_DIR)/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

docker: ## Build production Docker image
	cd $(PROJECT_DIR) && docker build --target runtime -t redcheck246:latest .

docker-dev: ## Build development Docker image
	cd $(PROJECT_DIR) && docker build --target dev -t redcheck246:dev .

# ---------------------------------------------------------------------------
# All-in-one
# ---------------------------------------------------------------------------

ci: lint type-check test security build ## Run full CI pipeline locally
