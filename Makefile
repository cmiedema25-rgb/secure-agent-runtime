PYTHON ?= python

.PHONY: install lint test eval demo verify compile

install:
	$(PYTHON) -m pip install -e '.[dev]'

lint:
	ruff check .
	ruff format --check .
	mypy src/secure_agent_runtime

compile:
	PYTHONPATH=src $(PYTHON) -m compileall -q src tests examples

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

eval:
	PYTHONPATH=src $(PYTHON) -m secure_agent_runtime evaluate \
		--corpus evals/attack_corpus.jsonl \
		--report evidence/evaluation-report.json

demo:
	PYTHONPATH=src $(PYTHON) examples/demo_agent.py

verify:
	$(MAKE) lint
	$(MAKE) compile
	$(MAKE) test
	$(MAKE) eval
