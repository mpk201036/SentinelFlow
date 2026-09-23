# SentinelFlow developer tasks.
# Run `make help` for the list.

PYTHON ?= python3.13
VENV   := .venv
BIN    := $(VENV)/bin

.DEFAULT_GOAL := help
.PHONY: help setup install lint format typecheck test test-cov doctor clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Create the virtual environment and install everything
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --quiet --upgrade pip
	$(BIN)/python -m pip install -e ".[dev]"
	@echo "Environment ready. Activate with: source $(VENV)/bin/activate"

install: ## Install/refresh dependencies into an existing venv
	$(BIN)/python -m pip install -e ".[dev]"

lint: ## Lint with ruff
	$(BIN)/ruff check app tests
	$(BIN)/ruff format --check app tests

format: ## Auto-format and fix lint issues
	$(BIN)/ruff format app tests
	$(BIN)/ruff check --fix app tests

typecheck: ## Static type check
	$(BIN)/mypy app

test: ## Run the test suite
	$(BIN)/pytest

test-cov: ## Run tests with a coverage report
	$(BIN)/pytest --cov=app --cov-report=term-missing --cov-report=html

doctor: ## Verify the local environment
	$(BIN)/sentinelflow doctor

clean: ## Remove caches and build artefacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage build dist *.egg-info
