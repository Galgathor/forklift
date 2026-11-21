#!/bin/sh
set -eu
cd "$(dirname "$0")"
# Prepare restricted enrollment files for the non-root container and preserve the supplied .env.
./prepare.sh
docker compose up -d --build
printf '\nForklift is installing this directory replica. Return to Directory Servers and wait for Synchronization confirmed.\nFor startup diagnostics: docker compose logs --tail=50 replica\n'
