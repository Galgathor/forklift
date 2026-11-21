#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
[ -f .env ] || printf 'FORKLIFT_REPLICA_BIND=127.0.0.1\nFORKLIFT_REPLICA_PORT=636\n' > .env
# Keep downloaded files owned by the operator so expired deployments can be replaced.
# The one-shot helper copies them into a private volume readable by the non-root runtime.
docker compose run --rm --no-deps prepare
