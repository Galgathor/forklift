"""One-shot, constrained provisioning. No shell, Docker socket or cn=config API."""
import base64, hashlib, hmac, json, os, re, subprocess, threading, ssl, time, sys, signal, socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from argon2 import PasswordHasher
ROOT = Path('/directory')

def secret(name): return Path('/run/secrets/' + name).read_text().strip()
def hashed(value):
    return '{ARGON2}' + PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1).hash(value)
def b64(value): return base64.b64encode(value.encode()).decode()
def start():
    return subprocess.Popen(['slapd', '-f', str(ROOT/'slapd.conf'), '-h', 'ldaps://0.0.0.0:636', '-d', '0'])

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self, code, value):
        data = json.dumps(value).encode(); self.send_response(code); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        initialized = (ROOT/'complete').exists()
        self.reply(200 if not initialized or (slapd is not None and slapd.poll() is None) else 503, {'initialized': initialized})
    def do_POST(self):
        if self.path != '/initialize': return self.reply(404, {})
        if (ROOT/'complete').exists(): return self.reply(409, {'error': 'Already initialized'})
        if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + secret('provision')): return self.reply(403, {})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length < 8192: raise ValueError()
            p = json.loads(self.rfile.read(length)); base = p['base']; user = p['username']; password = p['password']
            if not re.fullmatch(r'dc=[a-z0-9-]+(?:,dc=[a-z0-9-]+)+', base): raise ValueError()
            if not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', user) or len(password) < 14: raise ValueError()
            # A failed attempt may contain partial data. Never overwrite it automatically.
            if (ROOT/'slapd.conf').exists(): return self.reply(409, {'error': 'Partial provisioning: consult recovery documentation'})
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
TLSCACertificateFile /run/secrets/ca.crt
TLSCertificateFile /run/secrets/ldap.crt
TLSCertificateKeyFile /run/secrets/ldap.key
security simple_bind=128
password-hash {{ARGON2}}
database mdb
maxsize 1073741824
suffix "{base}"
directory /directory/db
index objectClass eq
index uid,cn,memberUid eq
access to attrs=userPassword by dn.exact="cn=manager,{base}" write by anonymous auth by * none
access to * by dn.exact="cn=manager,{base}" write by users read by * none
'''
            (ROOT/'slapd.conf').write_text(config)
            entries = [f'dn: {base}\nobjectClass: domain\ndc: {base.split(",")[0][3:]}',
                f'dn: cn=manager,{base}\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: manager\nuserPassword: {hashed(secret("service"))}',
                *[f'dn: ou={ou},{base}\nobjectClass: organizationalUnit\nou: {ou}' for ou in ['people','groups']],
                f'dn: cn=administrators,ou=groups,{base}\nobjectClass: posixGroup\ncn: administrators\ngidNumber: 10000\nmemberUid: {user}',
                f'dn: uid={user},ou=people,{base}\nobjectClass: inetOrgPerson\nobjectClass: posixAccount\nobjectClass: shadowAccount\nuid: {user}\ncn: {user}\nsn: {user}\nuidNumber: 10000\ngidNumber: 10000\nhomeDirectory: /home/{user}\nloginShell: /bin/bash\nuserPassword: {hashed(password)}']
            subprocess.run(['slapadd','-f',str(ROOT/'slapd.conf'),'-l','/dev/stdin'], input=('\n\n'.join(entries)+'\n').encode(), check=True, capture_output=True)
            (ROOT/'complete').write_text(base)
            global slapd
            slapd = start()
            context = ssl.create_default_context(cafile='/run/secrets/ca.crt')
            for attempt in range(100):
                try:
                    with socket.create_connection(('127.0.0.1', 636), timeout=1) as raw:
                        with context.wrap_socket(raw, server_hostname='ldap'): pass
                    break
                except (OSError, ssl.SSLError):
                    if slapd.poll() is not None: raise RuntimeError('slapd exited')
                    time.sleep(0.1)
            else: raise RuntimeError('LDAP startup timed out')
            return self.reply(200, {'initialized': True})
        except Exception as exc:
            print("Provisioning failed: " + type(exc).__name__, file=sys.stderr, flush=True)
            self.reply(400, {'error': 'Provisioning failed; inspect local directory state'})

os.umask(0o077)
slapd = start() if (ROOT/'complete').exists() else None
def shutdown(*args):
    if slapd is not None:
        slapd.terminate()
        try: slapd.wait(timeout=8)
        except subprocess.TimeoutExpired: slapd.kill()
    sys.exit(0)
signal.signal(signal.SIGTERM, shutdown)
def supervise():
    while True:
        if slapd is not None and slapd.poll() is not None:
            print('slapd exited; restarting container required', file=sys.stderr, flush=True)
            os._exit(1)
        time.sleep(1)
threading.Thread(target=supervise, daemon=True).start()
server = HTTPServer(('0.0.0.0', 8090), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain('/run/secrets/ldap.crt', '/run/secrets/ldap.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
