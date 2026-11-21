#!/bin/sh
# Local operator action; the WebUI has no certificate signing key or command access.
set -eu
cd "$(dirname "$0")/.."
ldap_dns=${1:?Usage: scripts/renew-ldap-certificate.sh ldap.example.com}
case "$ldap_dns" in *[!a-z0-9.-]*|'') echo 'Use a lowercase DNS hostname.' >&2; exit 1;; esac
[ ${#ldap_dns} -le 253 ] || exit 1
# The already-built directory image contains OpenSSL. The helper sees only installation secrets.
docker run --rm --user 0:0 --entrypoint sh -e LDAP_DNS="$ldap_dns" -v "$PWD/.secrets:/secrets" forklift-ldap:latest -c '
set -eu
umask 077
openssl req -new -newkey rsa:3072 -nodes -subj /CN=ldap -keyout /secrets/ldap.key.new -out /secrets/ldap.csr.new
printf "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:ldap,DNS:%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n" "$LDAP_DNS" > /secrets/extensions.new
openssl x509 -req -in /secrets/ldap.csr.new -CA /secrets/ca.crt -CAkey /secrets/ca.key -CAcreateserial -days 365 -extfile /secrets/extensions.new -out /secrets/ldap.crt.new
openssl verify -CAfile /secrets/ca.crt -verify_hostname "$LDAP_DNS" /secrets/ldap.crt.new
cp /secrets/ldap.key /secrets/ldap.key.previous
cp /secrets/ldap.crt /secrets/ldap.crt.previous
# Preserve bind-mounted inodes. Existing services retain their loaded certificate until restarted.
cat /secrets/ldap.key.new > /secrets/ldap.key
cat /secrets/ldap.crt.new > /secrets/ldap.crt
chown 10001:10001 /secrets/ldap.key
chmod 600 /secrets/ldap.key /secrets/ldap.key.previous /secrets/ldap.key.new
chmod 644 /secrets/ldap.crt
'
printf '\nCertificate updated. Restart the directory with docker compose restart ldap during a maintenance window.\n'
