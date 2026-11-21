FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
LABEL io.forklift.maintenance-version="1"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends age python3 python3-argon2 slapd=2.6.10+dfsg-1 ldap-utils=2.6.10+dfsg-1 ca-certificates openssl && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /directory /metadata /secrets /installation /output /work
COPY docker/maintenance/maintenance.py /maintenance.py
ENTRYPOINT ["python3", "/maintenance.py"]
COPY docker/openldap/provision.py /primary.py
