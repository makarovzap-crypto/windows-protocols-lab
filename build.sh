#!/usr/bin/env sh
# Сборка и запуск стенда в Linux/macOS: ./build.sh [install|test|run|clean|all]
set -e
cd "$(dirname "$0")"
PY=.venv/bin/python

install() { [ -x "$PY" ] || python3 -m venv .venv; "$PY" -m pip install -q -r requirements.txt; }
run_tests() { "$PY" -m pytest -q tests; }
run_stand() { "$PY" main.py run; }
clean() { rm -rf output .pytest_cache; find . -name __pycache__ -type d -prune -exec rm -rf {} +; }

case "${1:-all}" in
  install) install ;;
  test) run_tests ;;
  run) run_stand ;;
  clean) clean ;;
  all) install; run_tests; run_stand ;;
  *) echo "Использование: $0 [install|test|run|clean|all]"; exit 2 ;;
esac
