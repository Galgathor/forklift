"""Replica-only lifecycle. Native Syncrepl owns synchronization; no command API."""
import json
import hashlib
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


def atomic(path, data):
    temporary = path.with_name(path.name + '.new')
    with open(temporary, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_DIRECTORY)
    os.fsync(descriptor)
    os.close(descriptor)


def certificate_der(path):
    return subprocess.check_output(['openssl', 'x509', '-in', str(path), '-outform', 'DER'], stderr=subprocess.DEVNULL)


def matching_pair(key, cert):
    public = subprocess.check_output(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'], stderr=subprocess.DEVNULL)
    certificate_public = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'], stderr=subprocess.DEVNULL)
    certificate_public = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=certificate_public, capture_output=True, check=True).stdout
    return public == certificate_public


def generate_certificate(hostname, prefix='server'):
    if not re.fullmatch(r'[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?', hostname) or len(hostname) > 253:
        raise ValueError('Invalid hostname')
    key, cert = ROOT/(prefix+'.key'), ROOT/(prefix+'.crt')
    if key.exists() != cert.exists():
        raise ValueError('Incomplete certificate pair; preserve and inspect the volume')
    if not key.exists():
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '365', '-subj', '/CN='+hostname,
            '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
            '-addext', 'extendedKeyUsage=serverAuth', '-addext', 'subjectAltName=DNS:'+hostname,
            '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    if not matching_pair(key, cert):
        raise ValueError('Certificate and private key do not match')


def activate_certificate():
    journal = ROOT/'certificate-activation.json'
    key, cert = ROOT/'server-next.key', ROOT/'server-next.crt'
    if journal.exists():
        state = json.loads(journal.read_text())
    else:
        if not key.exists() or not cert.exists() or not matching_pair(key, cert):
            raise ValueError('No complete staged certificate')
        state = {'fingerprint': hashlib.sha256(certificate_der(cert)).hexdigest()}
        atomic(journal, json.dumps(state).encode())
    active = False
    try:
        active = matching_pair(ROOT/'server.key', ROOT/'server.crt') and hashlib.sha256(certificate_der(ROOT/'server.crt')).hexdigest() == state['fingerprint']
    except (OSError, subprocess.CalledProcessError):
        pass
    if not active:
        if not key.exists() or not cert.exists() or not matching_pair(key, cert):
            raise ValueError('Interrupted activation lacks its staged pair; restore from backup')
        if not (ROOT/'server.key.previous').exists():
            atomic(ROOT/'server.key.previous', (ROOT/'server.key').read_bytes())
            atomic(ROOT/'server.crt.previous', (ROOT/'server.crt').read_bytes())
        atomic(ROOT/'server.key', key.read_bytes())
        atomic(ROOT/'server.crt', cert.read_bytes())
        if not matching_pair(ROOT/'server.key', ROOT/'server.crt'):
            raise ValueError('Certificate activation did not produce a matching pair')
    key.unlink(missing_ok=True)
    cert.unlink(missing_ok=True)
    journal.unlink()


def apply_credential():
    data = sys.stdin.buffer.read(8193)
    if len(data) > 8192:
        raise ValueError('Credential update exceeds its size limit')
    incoming = json.loads(data)
    current = json.loads((ROOT/'replica.json').read_text())
    if any(incoming.get(k) != current.get(k) for k in ['id', 'base', 'provider']):
        raise ValueError('Credential update belongs to another replica')
    if not isinstance(incoming.get('credential'), str) or not re.fullmatch(r'[a-f0-9]{64}', incoming['credential']):
        raise ValueError('Invalid credential update')
    if not isinstance(incoming.get('credential_epoch'), int) or incoming['credential_epoch'] <= current.get('credential_epoch', 0):
        raise ValueError('Credential update is stale or has already been applied')
    current['credential'] = incoming['credential']
    current['credential_epoch'] = incoming['credential_epoch']
    atomic(ROOT/'replica.json', json.dumps(current).encode())
    configure()



def enroll():
    p = json.loads(Path('/enrollment/enrollment.json').read_text())
    if not re.fullmatch(r'[a-f0-9]{32}', p['id']):
        raise ValueError('Invalid enrollment ID')
    # Fail before redeeming the one-use token if this new machine cannot reach the primary.
    from urllib.parse import urlsplit
    provider=urlsplit(p['provider'])
    try:
        context=ssl.create_default_context(cafile='/enrollment/provider-ca.crt')
        with socket.create_connection((provider.hostname,provider.port or 636),timeout=5) as connection:
            with context.wrap_socket(connection,server_hostname=provider.hostname):pass
    except Exception:
        raise ValueError('Primary connection failed before enrollment: check the primary DNS record, private directory port/firewall and certificate hostname. Return to Add server and run the primary preparation command. The enrollment token was not used.') from None
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
    atomic(ROOT/'replica.json', json.dumps({**result, 'id': p['id'], 'hostname': p['hostname']}).encode())
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
    atomic(ROOT/'slapd.conf', config.encode())
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
    action = sys.argv[1:]
    if action in [['stage-certificate'], ['activate-certificate'], ['retire-certificate'], ['apply-credential']]:
        try:
            if action == ['stage-certificate']:
                p = json.loads((ROOT/'replica.json').read_text())
                generate_certificate(p['hostname'], 'server-next')
                print((ROOT/'server-next.crt').read_text(), end='')
            elif action == ['activate-certificate']:
                activate_certificate()
                print('Certificate activated on disk; restart the replica to load it')
            elif action == ['retire-certificate']:
                if not matching_pair(ROOT/'server.key', ROOT/'server.crt'):
                    raise ValueError('Active certificate is invalid')
                (ROOT/'server.key.previous').unlink(missing_ok=True)
                (ROOT/'server.crt.previous').unlink(missing_ok=True)
                print('Previous local certificate/key retired')
            else:
                apply_credential()
                print('Credential update written; restart the replica and verify new changes synchronize')
        except Exception as exc:
            print(str(exc) if isinstance(exc, ValueError) else type(exc).__name__, file=sys.stderr)
            sys.exit(1)
        sys.exit(0)
    if sys.argv[1:] == ['health']:
        sys.exit(health())
    if not (ROOT/'replica.json').exists():
        try:
            enroll()
        except Exception as exc:
            # Do not log response bodies or credentials. Tokens are never command arguments.
            print('Enrollment failed: '+(str(exc) if isinstance(exc,ValueError) else type(exc).__name__+'. Check expiry, manager HTTPS and enrollment status.'), file=sys.stderr)
            sys.exit(1)
    if (ROOT/'certificate-activation.json').exists():
        activate_certificate()
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
