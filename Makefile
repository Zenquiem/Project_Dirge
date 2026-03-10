.PHONY: dev-install test lint compile check

RUFF_TARGETS := tests

dev-install:
	python3 -m pip install -r requirements-dev.txt

test:
	python3 -m unittest discover -s tests -q

lint:
	python3 -m ruff check $(RUFF_TARGETS)

compile:
	python3 -m compileall core scripts tests

check: lint test compile
