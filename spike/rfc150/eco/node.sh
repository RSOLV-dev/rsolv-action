#!/bin/sh
set -eu
case $1 in
  install) npm ci --no-audit --no-fund ;;
  test) npx --no-install jest --json --outputFile=/tmp/report/report.json ;;
esac
