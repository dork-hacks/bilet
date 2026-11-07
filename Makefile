PYTHON ?= python3.12
VENV   ?= .venv
BIN    := $(VENV)/bin

.PHONY: setup test lint clean

# One-command setup (NFR-10): creates the virtualenv and installs pinned dependencies.
setup: $(BIN)/tool

$(BIN)/tool: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip
	$(BIN)/pip install --quiet -e '.[dev]'
	@touch $@

test: setup
	$(BIN)/pytest

lint: setup
	$(BIN)/ruff check src tests
	$(BIN)/ruff format --check src tests

# `make validate` (the golden test against the Validation Set) arrives with issue #17.
# CI runs it automatically as soon as the target exists.

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache src/*.egg-info
