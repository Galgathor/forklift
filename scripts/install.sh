#!/bin/sh
set -eu
umask 077
cd "$(dirname "$0")/.."
mkdir -p .secrets
if [ ! -f .secrets/bootstrap ]; then openssl rand -hex 32 > .secrets/bootstrap; fi
if [ ! -f .secrets/provision ]; then openssl rand -hex 32 > .secrets/provision; fi
if [ ! -f .secrets/service ]; then openssl rand -hex 48 > .secrets/service; fi
if [ ! -f .secrets/ca.crt ]; then
 openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj '/CN=Forklift Local CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout .secrets/ca.key -out .secrets/ca.crt
fi
if [ ! -f .secrets/ldap.crt ]; then
 openssl req -new -newkey rsa:3072 -nodes -subj '/CN=ldap' -keyout .secrets/ldap.key -out .secrets/ldap.csr
 printf 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:ldap\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' > .secrets/extensions
 openssl x509 -req -in .secrets/ldap.csr -CA .secrets/ca.crt -CAkey .secrets/ca.key -CAcreateserial -days 365 -extfile .secrets/extensions -out .secrets/ldap.crt
fi
# Containers use fixed UID 10001; keep private material inaccessible to other users.
# Bind files must be readable by that UID; Docker named secret support does not remap ownership.
if [ "$(id -u)" = 0 ]; then chown 10001:10001 .secrets/bootstrap .secrets/provision .secrets/service .secrets/ldap.key; else
 docker run --rm -v "$PWD/.secrets:/secrets" alpine:3.22.2 chown 10001:10001 /secrets/bootstrap /secrets/provision /secrets/service /secrets/ldap.key
fi
chmod 644 .secrets/ca.crt .secrets/ldap.crt
[ -f .env ] || cp .env.example .env
printf '\nBootstrap token (store locally; used once):\n'
if [ "$(id -u)" = 0 ]; then cat .secrets/bootstrap; else docker run --rm -v "$PWD/.secrets:/secrets:ro" alpine:3.22.2 cat /secrets/bootstrap; fi
