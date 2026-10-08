.PHONY: help install test lint typecheck scan build-sandbox dev-portal clean

PYTHON ?= python
PIP ?= pip
DOCKER ?= docker

help:
	@echo "Available commands:"
	@echo "  make install        Install development and bot dependencies"
	@echo "  make test           Run test suite with pytest"
	@echo "  make lint           Run flake8 code linter"
	@echo "  make typecheck      Run mypy static type analysis"
	@echo "  make scan           Execute local Semgrep and Bandit security scan"
	@echo "  make build-sandbox  Build ephemeral Docker verification container"
	@echo "  make dev-portal     Start local web portal development server"
	@echo "  make clean          Remove caches, pyc files, and temporary artifacts"

install:
	$(PIP) install -r requirements.txt
	$(PIP) install pytest pytest-cov mypy flake8 black bandit semgrep

test:
	$(PYTHON) -m pytest tests/ target_repo/test_app.py -v --cov=agent_engine

lint:
	flake8 agent_engine cli tests target_repo --max-line-length=120 --extend-ignore=E203,W503

typecheck:
	mypy agent_engine cli

scan:
	semgrep --config rules/python-security-rules.yml target_repo/
	bandit -r target_repo/ -f json -o tests/fixtures/bandit_findings.json || true

build-sandbox:
	$(DOCKER) build -f docker/sandbox.Dockerfile -t devsecops-sandbox:latest .

dev-portal:
	cd web && npm run dev

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov/ dist/ build/
