#!/bin/sh
set -e

DATA="${LLAR_DATA:-/llar}"

# Docker creates a missing bind-mount folder as root: give it to uid/gid 1000
# (Umbrel's app data owner), then run Llar as that user.
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA"
  chown -R 1000:1000 "$DATA"
  exec su-exec node "$@"
fi

exec "$@"
