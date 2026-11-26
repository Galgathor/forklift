FROM powerdns/pdns-auth-51:5.1.5@sha256:77ff4efdbb9ec30e9309c8a1cbed6121a67fa3be25c848bbbfa756fc75bf9a27
USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dnsutils openssl dnsdist=1.9.16-0+deb13u1 && rm -rf /var/lib/apt/lists/* && mkdir -p /dns /run/dns-secrets /run/dns-control && chown 10001:10001 /dns /run/dns-secrets /run/dns-control
COPY docker/powerdns/forwarding.py /forwarding.py
COPY docker/powerdns/supervisor.py /supervisor.py
COPY docker/powerdns/secondary.py /secondary.py
USER 10001:10001
ENTRYPOINT ["python3", "/supervisor.py"]
