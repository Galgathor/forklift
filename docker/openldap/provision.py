"""Constrained primary initialization and versioned offline configuration upgrades."""
import hmac
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from argon2 import PasswordHasher

ROOT = Path('/directory')
slapd = None


def secret(name):
    return Path('/run/secrets/' + name).read_text().strip()


def hashed(value):
    return '{ARGON2}' + PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1).hash(value)


def valid_base(base):
    return len(base) <= 255 and re.fullmatch(r'dc=[a-z0-9-]+(?:,dc=[a-z0-9-]+)+', base)


def replication_acl(base):
    return f'access to attrs=userPassword by dn.exact="cn=manager,{base}" write by dn.regex="^cn=replica-[0-9a-f]{{32}},{base}$" read by anonymous auth by * none'


def configuration(base):
    return f'''# Forklift primary replication v1
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/nis.schema
include /etc/ldap/schema/inetorgperson.schema
pidfile /directory/slapd.pid
argsfile /directory/slapd.args
modulepath /usr/lib/ldap
moduleload back_mdb
moduleload argon2
moduleload syncprov
TLSCACertificateFile /run/secrets/ca.crt
TLSCertificateFile /run/secrets/ldap.crt
TLSCertificateKeyFile /run/secrets/ldap.key
TLSProtocolMin 3.3
security simple_bind=128
password-hash {{ARGON2}}
database mdb
maxsize 1073741824
suffix "{base}"
directory /directory/db
index objectClass eq
index uid,cn,memberUid eq
index entryUUID,entryCSN eq
{replication_acl(base)}
access to * by dn.exact="cn=manager,{base}" write by users read by * none
overlay syncprov
syncprov-checkpoint 100 10
syncprov-sessionlog 1000
'''


def upgrade(base):
    """No online config endpoint. A released version upgrades only known Forklift configs."""
    if (ROOT/'replication-version').exists():
        return
    current = ROOT/'slapd.conf'
    old = current.read_text()
    expected = f'access to attrs=userPassword by dn.exact="cn=manager,{base}" write by anonymous auth by * none'
    if '# Forklift primary replication v1' not in old:
        if expected not in old or 'overlay ' in old or f'suffix "{base}"' not in old:
            raise RuntimeError('Unrecognized directory configuration: refusing automatic upgrade')
        new = old.replace('moduleload argon2\n', 'moduleload argon2\nmoduleload syncprov\n')
        new = new.replace(expected, replication_acl(base))
        new += '\nindex entryUUID,entryCSN eq\noverlay syncprov\nsyncprov-checkpoint 100 10\nsyncprov-sessionlog 1000\n'
        new = '# Forklift primary replication v1\n' + new
        candidate = ROOT/'slapd.conf.upgrade'
        candidate.write_text(new)
        subprocess.run(['slaptest', '-u', '-f', str(candidate)], check=True, capture_output=True)
        if not (ROOT/'slapd.conf.pre-replication').exists():
            (ROOT/'slapd.conf.pre-replication').write_text(old)
        candidate.replace(current)
    # Reindex with slapd stopped. Interrupted upgrades retry the idempotent reindex.
    subprocess.run(['slapindex', '-f', str(current), '-b', base], check=True, capture_output=True)
    (ROOT/'replication-version').write_text('1')


def start():
    return subprocess.Popen(['slapd', '-f', str(ROOT/'slapd.conf'), '-h', 'ldaps://0.0.0.0:636', '-d', '256'])


def wait_ldap():
    context = ssl.create_default_context(cafile='/run/secrets/ca.crt')
    for _ in range(100):
        try:
            with socket.create_connection(('127.0.0.1', 636), timeout=1) as raw:
                with context.wrap_socket(raw, server_hostname='ldap'):
                    return
        except (OSError, ssl.SSLError):
            if slapd.poll() is not None:
                raise RuntimeError('slapd exited')
            time.sleep(0.1)
    raise RuntimeError('LDAP startup timed out')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, value):
        data = json.dumps(value).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        initialized = (ROOT/'complete').exists()
        healthy = not initialized or (slapd is not None and slapd.poll() is None)
        self.reply(200 if healthy else 503, {'initialized': initialized})

    def do_POST(self):
        global slapd
        if self.path != '/initialize':
            return self.reply(404, {})
        if (ROOT/'complete').exists():
            return self.reply(409, {'error': 'Already initialized'})
        if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + secret('provision')):
            return self.reply(403, {})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length < 8192:
                raise ValueError()
            p = json.loads(self.rfile.read(length))
            base, user, password = p['base'], p['username'], p['password']
            if not valid_base(base) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', user) or not 14 <= len(password) <= 1024:
                raise ValueError()
            if (ROOT/'slapd.conf').exists():
                return self.reply(409, {'error': 'Partial provisioning: consult recovery documentation'})
            (ROOT/'db').mkdir(exist_ok=True)
            (ROOT/'slapd.conf').write_text(configuration(base))
            entries = [f'dn: {base}\nobjectClass: domain\ndc: {base.split(",")[0][3:]}',
                f'dn: cn=manager,{base}\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: manager\nuserPassword: {hashed(secret("service"))}',
                *[f'dn: ou={ou},{base}\nobjectClass: organizationalUnit\nou: {ou}' for ou in ['people','groups']],
                f'dn: cn=administrators,ou=groups,{base}\nobjectClass: posixGroup\ncn: administrators\ngidNumber: 10000\nmemberUid: {user}',
                f'dn: uid={user},ou=people,{base}\nobjectClass: inetOrgPerson\nobjectClass: posixAccount\nobjectClass: shadowAccount\nuid: {user}\ncn: {user}\nsn: {user}\nuidNumber: 10000\ngidNumber: 10000\nhomeDirectory: /home/{user}\nloginShell: /bin/bash\nuserPassword: {hashed(password)}']
            subprocess.run(['slapadd', '-f', str(ROOT/'slapd.conf'), '-l', '/dev/stdin'], input=('\n\n'.join(entries)+'\n').encode(), check=True, capture_output=True)
            (ROOT/'replication-version').write_text('1')
            (ROOT/'complete').write_text(base)
            slapd = start()
            wait_ldap()
            self.reply(200, {'initialized': True})
        except Exception as exc:
            print('Provisioning failed: ' + type(exc).__name__, file=sys.stderr, flush=True)
            self.reply(400, {'error': 'Provisioning failed; inspect local directory state'})


def shutdown(*args):
    if slapd is not None:
        slapd.terminate()
        try:
            slapd.wait(timeout=8)
        except subprocess.TimeoutExpired:
            slapd.kill()
    sys.exit(0)


def supervise():
    while True:
        if slapd is not None and slapd.poll() is not None:
            print('slapd exited; restarting container required', file=sys.stderr, flush=True)
            os._exit(1)
        time.sleep(1)


if __name__ == '__main__':
    os.umask(0o077)
    if (ROOT/'complete').exists():
        suffix = (ROOT/'complete').read_text().strip()
        if not valid_base(suffix):
            raise RuntimeError('Invalid stored directory suffix')
        upgrade(suffix)
        slapd = start()
    signal.signal(signal.SIGTERM, shutdown)
    threading.Thread(target=supervise, daemon=True).start()
    server = HTTPServer(('0.0.0.0', 8090), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain('/run/secrets/ldap.crt', '/run/secrets/ldap.key')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
