#!/bin/sh
set -eu
export MIX_HOME=/tmp/mix HEX_HOME=/tmp/hex MIX_ENV=test
case $1 in
  install) mix local.hex --force && mix deps.get && mix deps.compile ;;
  test) mix test --trace > /tmp/report/report.txt 2>&1 ;;
esac
