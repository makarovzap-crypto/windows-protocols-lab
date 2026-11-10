# Сборка и запуск стенда (GNU Make, Linux/macOS или Git Bash в Windows).
PY ?= .venv/bin/python

.PHONY: install test run clean docker-build docker-run all

all: install test run

install:
	test -x $(PY) || python3 -m venv .venv
	$(PY) -m pip install -q -r requirements.txt

test:
	$(PY) -m pytest -q tests

run:
	$(PY) main.py run

clean:
	rm -rf output .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

docker-build:
	docker build -t win-protocols-stand .

docker-run:
	docker run --rm -v "$(CURDIR)/output:/app/output" win-protocols-stand
