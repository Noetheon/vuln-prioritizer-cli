PYTHON ?= python3

.PHONY: install test lint format typecheck check demo-report demo-explain precommit-install

install:
	$(PYTHON) -m pip install -e .[dev]

test:
	pytest

lint:
	$(PYTHON) -m ruff check .

format:
	$(PYTHON) -m ruff format .

typecheck:
	$(PYTHON) -m mypy src

check:
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy src
	pytest

demo-report:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli analyze --input data/sample_cves.txt --output docs/example_report.md --format markdown

demo-explain:
	PYTHONPATH=src $(PYTHON) -m vuln_prioritizer.cli explain --cve CVE-2021-44228 --output docs/example_explain.json --format json

precommit-install:
	pre-commit install
