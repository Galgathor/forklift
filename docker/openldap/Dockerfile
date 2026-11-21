FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils python3 ca-certificates && rm -rf /var/lib/apt/lists/* /etc/ldap/slapd.d/* && usermod -u 10001 openldap && groupmod -g 10001 openldap && mkdir -p /directory && chown 10001:10001 /directory
COPY docker/openldap/provision.py /provision.py
USER 10001:10001
EXPOSE 636 8090
ENTRYPOINT ["python3", "/provision.py"]
