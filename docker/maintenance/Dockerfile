FROM powerdns/pdns-auth-51:5.1.5@sha256:77ff4efdbb9ec30e9309c8a1cbed6121a67fa3be25c848bbbfa756fc75bf9a27 AS dns-schema
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends age python3 python3-argon2 slapd=2.6.10+dfsg-1 ldap-utils=2.6.10+dfsg-1 ca-certificates openssl && rm -rf /var/lib/apt/lists/*
COPY --from=dns-schema /usr/local/share/doc/pdns/schema.sqlite3.sql /dns-schema.sql
COPY docker/powerdns/forwarding.py /forwarding.py
COPY docker/maintenance/dns_storage.py /dns_storage.py
RUN mkdir -p /dns /dns-secrets /run/dns-control /directory /metadata /secrets /directory-secrets /authority /backups /transfers /work /run/ldap-control /run/maintenance-control /run/ldap-socket && chown -R 10001:10001 /dns /dns-secrets /run/dns-control /directory /metadata /secrets /directory-secrets /authority /backups /transfers /work /run/ldap-control /run/maintenance-control /run/ldap-socket
COPY docker/maintenance/storage.py /storage.py
COPY docker/maintenance/custodian.py /custodian.py
COPY docker/maintenance/emergency.py /emergency.py
COPY docker/openldap/provision.py /primary.py
USER 10001:10001
ENTRYPOINT ["python3", "/custodian.py"]
