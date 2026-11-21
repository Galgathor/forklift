FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd=2.6.10+dfsg-1 ldap-utils=2.6.10+dfsg-1 python3 python3-argon2 ca-certificates && rm -rf /var/lib/apt/lists/* /etc/ldap/slapd.d/* && usermod -u 10001 openldap && groupmod -g 10001 openldap && mkdir -p /directory && chown 10001:10001 /directory
COPY docker/openldap/provision.py /provision.py
COPY backend/assets/replica.py /replica.py
USER 10001:10001
EXPOSE 636 8090
ENTRYPOINT ["python3", "/provision.py"]
