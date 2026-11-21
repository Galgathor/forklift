FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends age python3 python3-argon2 slapd=2.6.10+dfsg-1 ldap-utils=2.6.10+dfsg-1 ca-certificates openssl && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /directory /metadata /secrets /directory-secrets /authority /backups /transfers /work /run/ldap-control /run/maintenance-control /run/ldap-socket && chown -R 10001:10001 /directory /metadata /secrets /directory-secrets /authority /backups /transfers /work /run/ldap-control /run/maintenance-control /run/ldap-socket
COPY docker/maintenance/storage.py /storage.py
COPY docker/maintenance/custodian.py /custodian.py
COPY docker/maintenance/emergency.py /emergency.py
COPY docker/openldap/provision.py /primary.py
USER 10001:10001
ENTRYPOINT ["python3", "/custodian.py"]
