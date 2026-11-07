PYTHON ?= python3.12
VENV   ?= .venv
BIN    := $(VENV)/bin

.PHONY: setup test test-map lint validate near-misses clean

# One-command setup (NFR-10): creates the virtualenv and installs pinned dependencies.
setup: $(BIN)/tool

$(BIN)/tool: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip
	$(BIN)/pip install --quiet -e '.[dev]'
	@touch $@

test: setup
	$(BIN)/pytest

# Optional map layout checks; the default Python suite does not require Node.
test-map:
	node --test tests/netmap-layout.test.mjs

lint: setup
	$(BIN)/ruff check src tests scripts
	$(BIN)/ruff format --check src tests scripts

# Golden test (#17): the CSV export against the organizers' answer key (byte for byte)
# and our own trap files. CI's golden job runs it on every push and PR.
validate: setup
	$(BIN)/python scripts/validate.py

# Near-miss report (#187): the cases in a folder of scans a human should double-check
# before an upload. Read-only. Usage: make near-misses DIR=<folder>
near-misses: setup
	@test -n "$(DIR)" || { echo "usage: make near-misses DIR=<folder of nmap XML files>"; exit 2; }
	$(BIN)/python scripts/near_misses.py "$(DIR)"

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache src/*.egg-info
