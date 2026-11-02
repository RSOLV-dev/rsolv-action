#!/bin/sh
set -eu
case $1 in
  install) python -m venv /tmp/venv && /tmp/venv/bin/pip install -q -r requirements.txt ;;
  test) /tmp/venv/bin/pytest -q --junitxml=/tmp/report/report.xml ;;
esac
