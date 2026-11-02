#!/bin/sh
set -eu
export BUNDLE_PATH=/tmp/bundle
case $1 in
  install) bundle install ;;
  test) bundle exec rspec --format json --out /tmp/report/report.json ;;
esac
