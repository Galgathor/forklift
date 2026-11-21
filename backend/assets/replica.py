"""Replica-only lifecycle. Native Syncrepl owns synchronization; no command API."""
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

ROOT = Path('/directory')


def generate_certificate(hostname):
    if not re.fullmatch(r'[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?', hostname) or len(hostname) > 253:
        raise ValueError('Invalid hostname')
    if not (ROOT/'server.key').exists():
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '365', '-subj', '/CN='+hostname,
            '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
            '-addext', 'extendedKeyUsage=serverAuth', '-addext', 'subjectAltName=DNS:'+hostname,
            '-keyout', str(ROOT/'server.key'), '-out', str(ROOT/'server.crt')], check=True, capture_output=True)


def enroll():
    p = json.loads(Path('/enrollment/enrollment.json').read_text())
    if not re.fullmatch(r'[a-f0-9]{32}', p['id']):
        raise ValueError('Invalid enrollment ID')
    generate_certificate(p['hostname'])
    url = p['manager_url']
    if not url.startswith('https://'):
        raise ValueError('Enrollment requires manager HTTPS')
    payload = json.dumps({'token': p['token'], 'certificate': (ROOT/'server.crt').read_text()}).encode()
    request = urllib.request.Request(url+'/api/replicas/'+p['id']+'/enroll', data=payload, headers={'Content-Type': 'application/json'}, method='POST')
    # System roots validate the manager/NPM certificate; optional private PKI is explicit.
    trust = '/enrollment/manager-ca.crt'
    context = ssl.create_default_context(cafile=trust if Path(trust).exists() else None)
    with urllib.request.urlopen(request, context=context, timeout=30) as response:
        result = json.load(response)
    if not re.fullmatch(r'dc=[a-z0-9-]+(?:,dc=[a-z0-9-]+)+', result['base']):
        raise ValueError('Invalid returned suffix')
    if not re.fullmatch(r'[a-f0-9]{64}', result['credential']):
        raise ValueError('Invalid returned credential')
    if result['provider'] != p['provider']:
        raise ValueError('Provider changed during enrollment')
    # Save the one-time response before configuration work so local failures can retry safely.
    (ROOT/'replica.json').write_text(json.dumps({**result, 'id': p['id'], 'hostname': p['hostname']}))
    (ROOT/'provider-ca.crt').write_bytes(Path('/enrollment/provider-ca.crt').read_bytes())


def configure():
    from urllib.parse import urlsplit
    p = json.loads((ROOT/'replica.json').read_text())
    uri = urlsplit(p['provider'])
    if uri.scheme != 'ldaps' or not uri.hostname or uri.username or uri.password or uri.path or uri.query or uri.fragment or any(c.isspace() for c in p['provider']):
        raise ValueError('Unsafe provider endpoint')
    (ROOT/'db').mkdir(exist_ok=True)
    config = f'''include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/nis.schema
include /etc/ldap/schema/inetorgperson.schema
pidfile /directory/slapd.pid
argsfile /directory/slapd.args
modulepath /usr/lib/ldap
moduleload back_mdb
moduleload argon2
TLSCACertificateFile /directory/provider-ca.crt
TLSCertificateFile /directory/server.crt
TLSCertificateKeyFile /directory/server.key
TLSProtocolMin 3.3
security simple_bind=128
password-hash {{ARGON2}}
database mdb
maxsize 1073741824
suffix "{p['base']}"
# Internal Syncrepl identity only: no root password or bindable directory entry.
rootdn "cn=replication-internal,{p['base']}"
directory /directory/db
readonly on
index objectClass eq
index uid,cn,memberUid eq
index entryUUID,entryCSN eq
access to attrs=userPassword by anonymous auth by * none
access to * by users read by * none
syncrepl rid=001 provider="{p['provider']}" searchbase="{p['base']}" type=refreshAndPersist retry="5 5 30 +" timeout=5 bindmethod=simple binddn="cn=replica-{p['id']},{p['base']}" credentials="{p['credential']}" tls_reqcert=demand tls_cacert=/directory/provider-ca.crt
'''
    (ROOT/'slapd.conf').write_text(config)
    check = subprocess.run(['slaptest', '-u', '-f', str(ROOT/'slapd.conf')], capture_output=True)
    if check.returncode:
        print('Replica configuration check failed: ' + check.stderr.decode(errors='replace').replace(p['credential'], '[redacted]')[:1200], file=sys.stderr)
        raise RuntimeError('Replica configuration refused by slaptest')
    (ROOT/'complete').write_text(p['base'])


def health():
    if not (ROOT/'complete').exists():
        return 1
    p = json.loads((ROOT/'replica.json').read_text())
    context = ssl.create_default_context(cafile=str(ROOT/'server.crt'))
    with socket.create_connection(('127.0.0.1', 636), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname=p['hostname']):
            return 0


if __name__ == '__main__':
    os.umask(0o077)
    if sys.argv[1:] == ['health']:
        sys.exit(health())
    if not (ROOT/'replica.json').exists():
        try:
            enroll()
        except Exception as exc:
            # Do not log response bodies or credentials. Tokens are never command arguments.
            print('Enrollment failed: '+type(exc).__name__+'. Check expiry, manager HTTPS and enrollment status.', file=sys.stderr)
            sys.exit(1)
    if not (ROOT/'complete').exists():
        configure()
    child = subprocess.Popen(['slapd', '-f', str(ROOT/'slapd.conf'), '-h', 'ldaps://0.0.0.0:636', '-d', '256'])
    def shutdown(*args):
        child.terminate()
        try:
            child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            child.kill()
        sys.exit(0)
    signal.signal(signal.SIGTERM, shutdown)
    sys.exit(child.wait())
