SHELL := /bin/bash
PYTHON := ./.venv/bin/python
PYTEST := ./.venv/bin/pytest
SCENARIO ?= syn_basic

.PHONY: test lint lab lab-verify prove-oneway eval-all demo help

help:
	@echo "DiodeWatch AI - SIH 2026 PS 26145 Automation"
	@echo "Targets:"
	@echo "  make lab [SCENARIO=syn_basic]  Generate forward-only scenario and label dataset"
	@echo "  make lab-verify                Verify forward-only property (0 reverse packets) & manifest hashes"
	@echo "  make test                      Run all unit, pipeline, detector, and blockchain tests"
	@echo "  make lint                      Run code linting and zero-egress AST audit"
	@echo "  make prove-oneway              Run mathematical and physical one-way proof test"
	@echo "  make eval-all                  Run evaluation harness across all detectors and produce REPORT.md"
	@echo "  make demo                      Run end-to-end demo script"

lab:
	PYTHONPATH=. $(PYTHON) testbed/run_scenario.py $(SCENARIO)

lab-verify:
	PYTHONPATH=. $(PYTHON) testbed/verify_lab.py

test:
	PYTHONPATH=.:anchor $(PYTEST) tests/ -v

lint:
	PYTHONPATH=. $(PYTHON) tests/test_passive_proof.py

prove-oneway:
	PYTHONPATH=. $(PYTHON) tests/prove_oneway.py

eval-all:
	PYTHONPATH=. $(PYTHON) training/eval/eval_harness.py

demo:
	./scripts/demo.sh
