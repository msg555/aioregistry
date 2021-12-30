.PHONY: format format-check pylint typecheck lint test docs build clean pypi-test pypi-live

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

docs:
	make -C docs html

build:
	$(PYTHON) -m build

clean:
	rm -rf build dist *.egg-info

pypi-test: build
	TWINE_USERNAME=__token__ TWINE_PASSWORD="$(shell gpg -d test.pypi-token.gpg)" \
	  $(PYTHON) -m twine upload --repository testpypi dist/*

pypi-live: build
	TWINE_USERNAME=__token__ TWINE_PASSWORD="$(shell gpg -d live.pypi-token.gpg)" \
	  $(PYTHON) -m twine upload dist/*
