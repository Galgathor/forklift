#!/bin/sh
# Exception only: local recovery when no administrator can sign in.
set -eu
cd "$(dirname "$0")/.."
docker compose exec maintenance python3 /emergency.py
docker compose restart manager
