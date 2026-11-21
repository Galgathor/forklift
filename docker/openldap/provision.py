"""One-shot, constrained provisioning. No shell, Docker socket or cn=config API."""
import base64, hashlib, hmac, json, os, re, subprocess, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
ROOT = Path('/directory')

def secret(name): return Path('/run/secrets/' + name).read_text().strip()
def hashed(value):
    salt = os.urandom(16)
    return '{SSHA}' + base64.b64encode(hashlib.sha1(value.encode() + salt).digest() + salt).decode()
def b64(value): return base64.b64encode(value.encode()).decode()
def start():
    return subprocess.Popen(['slapd', '-f', str(ROOT/'slapd.conf'), '-h', 'ldaps://0.0.0.0:636', '-d', '0'])

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self, code, value):
        data = json.dumps(value).encode(); self.send_response(code); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(data)
    def do_GET(self): self.reply(200, {'initialized': (ROOT/'complete').exists()})
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
TLSCACertificateFile /run/secrets/ca.crt
TLSCertificateFile /run/secrets/ldap.crt
TLSCertificateKeyFile /run/secrets/ldap.key
security simple_bind=128
password-hash {{SSHA}}
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
            return self.reply(200, {'initialized': True})
        except Exception:
            self.reply(400, {'error': 'Provisioning failed; inspect local directory state'})

os.umask(0o077)
slapd = start() if (ROOT/'complete').exists() else None
HTTPServer(('0.0.0.0', 8090), Handler).serve_forever()
