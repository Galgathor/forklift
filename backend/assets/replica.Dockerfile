FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd=2.6.10+dfsg-1 ldap-utils=2.6.10+dfsg-1 python3 ca-certificates openssl && rm -rf /var/lib/apt/lists/* && mkdir -p /directory && chown 10001:10001 /directory
COPY --chown=10001:10001 replica.py /replica.py
USER 10001:10001
ENTRYPOINT ["python3", "/replica.py"]
