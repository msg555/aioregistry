.PHONY: format format-check pylint typecheck lint test docs

PYTHON := python3

all: format lint test docs

format:
	$(PYTHON) -m black . scripts/pyregistry

format-check:
	$(PYTHON) -m black --check . scripts/pyregistry

pylint:
	$(PYTHON) -m pylint pyregistry scripts tests

typecheck:
	$(PYTHON) -m mypy pyregistry

lint: format-check pylint typecheck

test:
	$(PYTHON) -m unittest discover -v tests/
