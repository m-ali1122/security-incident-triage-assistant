.PHONY: test run lint

test:
	python -m pytest -q

run:
	python -m uvicorn triage.api:app --host 0.0.0.0 --port 8000 --reload

lint:
	python -m compileall -q triage tests
