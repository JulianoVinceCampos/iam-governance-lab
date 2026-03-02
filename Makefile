.PHONY: setup test lint run clean

setup:
	pip install -e ".[dev]" --break-system-packages

test:
	pytest tests/ -v --tb=short

lint:
	ruff check src/ tests/

run:
	python -m iam_governance --help

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
