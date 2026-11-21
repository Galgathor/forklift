FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sssd-ldap sssd-tools libnss-sss libpam-sss openssh-server pamtester sshpass ldap-utils python3 ansible-core ca-certificates && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd /bundle /workspace
WORKDIR /workspace
CMD ["sleep", "infinity"]
