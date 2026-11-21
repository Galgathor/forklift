#!/bin/sh
set -eu
umask 077
# Restricted enrollment files must be readable by the fixed non-root runtime UID.
docker run --rm -v "$PWD/enrollment:/enrollment" alpine:3.22.2 chown -R 10001:10001 /enrollment
[ -f .env ] || printf 'FORKLIFT_REPLICA_BIND=127.0.0.1\nFORKLIFT_REPLICA_PORT=636\n' > .env
