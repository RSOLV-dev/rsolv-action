#!/bin/sh
# Installs Composer to $1 for the v5 sandbox image (RFC-150 3d): one pinned
# composer.phar, refused unless its SHA-256 is the committed one. The SHA-256 is
# the one getcomposer.org publishes (download/<version>/composer.phar.sha256sum),
# which matches the GitHub release asset's digest.
set -eu

COMPOSER_VERSION=2.11.1
COMPOSER_SHA256=6f1b891e1d4927d62740276c540fb490e47689e19e102c49e8da849794882f8c
url=${COMPOSER_PHAR_URL:-https://getcomposer.org/download/$COMPOSER_VERSION/composer.phar}
dest=$1

phar=$(mktemp)
trap 'rm -f "$phar"' EXIT
curl -fsSL --proto '=https,file' -o "$phar" "$url"
if ! echo "$COMPOSER_SHA256  $phar" | sha256sum -c - >/dev/null 2>&1; then
  echo "composer.phar from $url does not have the pinned SHA-256 for Composer $COMPOSER_VERSION; refusing it" >&2
  exit 1
fi
install -D -m 0755 "$phar" "$dest"
