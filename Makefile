PYTHON ?= python3.12
VENV   ?= .venv
BIN    := $(VENV)/bin

.PHONY: setup test lint validate clean

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
	$(BIN)/ruff check src tests scripts
	$(BIN)/ruff format --check src tests scripts

# Golden test (#17): the CSV export against the organizers' answer key (byte for byte)
# and our own trap files. CI's golden job runs it on every push and PR.
validate: setup
	$(BIN)/python scripts/validate.py

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache src/*.egg-info
