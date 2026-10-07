# Verification harness for the audit suite.
#
# Every target here is a thin wrapper over scripts/harness.py, which owns the
# gate definitions. Nothing in this file knows how a gate works - add a gate
# in harness.py and it shows up in `make list` without editing the Makefile.
#
# NEVER run install.sh by hand. It resolves its destinations from $$HOME and
# $$CODEX_HOME at run time, so an unguarded invocation overwrites the real,
# working skill install under ~/.claude/skills/codebase-audit/. `make install-smoke`
# builds a throwaway HOME, refuses to proceed if that HOME resolves to the real
# one, and asserts afterwards that the real install's mtime did not move.

PYTHON ?= python3
HARNESS := $(PYTHON) scripts/harness.py

.DEFAULT_GOAL := check
.PHONY: check all list test selftest lint eol install-smoke bench json clean help

## check: the pre-merge gate - tests, selftest, lint, eol, install (no bench)
check:
	@$(HARNESS)

## all: check plus the opt-in benchmark gate
all:
	@$(HARNESS) --all

## list: show every gate, whether it runs by default, and what it checks
list:
	@$(HARNESS) --list

## json: run the default gates and emit one JSON object (for CI and agents)
json:
	@$(HARNESS) --all --json

## test: the pytest suite alone
test:
	@$(HARNESS) --only tests

## selftest: verbs vs parser, TABLE_SPECS vs schema.sql, MIGRATIONS vs baseline
selftest:
	@$(HARNESS) --only selftest

## lint: the shipped skill against the economics contract
lint:
	@$(HARNESS) --only lint

## eol: the mixed CRLF/LF contract in scripts/eol-manifest.txt
eol:
	@$(HARNESS) --only eol

## install-smoke: sandboxed install.sh run; cannot touch the real install
install-smoke:
	@$(HARNESS) --only install

## bench: score the golden set; SKIPs when the corpus is not on this machine
bench:
	@$(HARNESS) --only bench

## clean: remove Python caches (never touches reports/ or any audit.db)
clean:
	@find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .pytest_cache
	@echo "caches removed"

## help: this list
help:
	@grep -E "^## " $(MAKEFILE_LIST) | sed "s/^## /  /"
