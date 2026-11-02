#!/bin/sh
set -eu
export COMPOSER_HOME=/tmp/composer
case $1 in
  install) composer install --no-interaction --no-progress ;;
  test) vendor/bin/phpunit --log-junit /tmp/report/report.xml tests ;;
esac
