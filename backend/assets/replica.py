"""Replica-only lifecycle. Native Syncrepl owns synchronization; no command API."""
import json
import hashlib
import hmac
import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
child = None
server = None
commands = threading.RLock()


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
            '-addext', 'extendedKeyUsage=serverAuth', '-addext', 'subjectAltName='+('IP:' if is_ip(hostname) else 'DNS:')+hostname,
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


def is_ip(hostname):
    try:ipaddress.ip_address(hostname);return True
    except ValueError:return False


def enroll():
    p = json.loads(Path('/enrollment/enrollment.json').read_text())
    if not re.fullmatch(r'[a-f0-9]{32}', p['id']):
        raise ValueError('Invalid enrollment ID')
    address=ipaddress.IPv4Address(p['address'])
    if not address.is_private or address.is_loopback:raise ValueError('Use the registered private interface on this Docker host')
    for port in [p['port'],p['control_port']]:
        if type(port) is not int or not 1<=port<=65535:raise ValueError('Invalid listener port')
        try:
            with socket.socket() as listener:listener.bind((str(address),port))
        except OSError:raise ValueError('The registered private address or port is not available on this host; fix the deployment address before enrollment') from None
    # Fail before redeeming the one-use token if this new machine cannot reach the primary.
    from urllib.parse import urlsplit
    provider=urlsplit(p['provider'])
    try:
        context=ssl.create_default_context(cafile='/enrollment/provider-ca.crt')
        with socket.create_connection((provider.hostname,provider.port or 636),timeout=5) as connection:
            with context.wrap_socket(connection,server_hostname=provider.hostname):pass
    except Exception:
        raise ValueError('Primary connection failed before enrollment: check the primary DNS record, private directory port/firewall and certificate hostname. Review the primary address in Forklift Settings and this machine’s private routing. The enrollment token was not used.') from None
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
    if not re.fullmatch(r'[a-f0-9]{64}',result.get('control_token','')):raise ValueError('Invalid node control credential')
    atomic(ROOT/'replica.json', json.dumps({**result,'id':p['id'],'hostname':p['hostname'],'address':p['address'],'port':p['port'],'control_port':p['control_port']}).encode())
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
    with socket.create_connection((p['address'],p['port']), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname=p['hostname']):
            return 0


def stop_directory():
    global child
    if child is not None:
        if child.poll() is None:
            child.terminate();child.wait(timeout=15)
        child=None

def start_directory():
    global child
    if child is not None and child.poll() is None:return
    configure();p=json.loads((ROOT/'replica.json').read_text())
    child=subprocess.Popen(['slapd','-f',str(ROOT/'slapd.conf'),'-h',f"ldaps://{p['address']}:{p['port']}",'-d','256'])
    for _ in range(100):
        if child.poll() is not None:raise ValueError('Directory process did not start')
        try:
            if health()==0:return
        except Exception:time.sleep(0.1)
    raise ValueError('Directory listener did not become healthy')

def credential_update(incoming):
    current=json.loads((ROOT/'replica.json').read_text())
    if any(incoming.get(k)!=current.get(k) for k in ['id','base','provider']):raise ValueError('Credential update is scoped to another node or provider')
    epoch=incoming.get('credential_epoch')
    if type(epoch) is not int or epoch<current.get('credential_epoch',0):raise ValueError('Stale credential update')
    for key in ['credential','control_token']:
        if not isinstance(incoming.get(key),str) or not re.fullmatch('[a-f0-9]{64}',incoming[key]):raise ValueError('Invalid credential update')
    if epoch==current.get('credential_epoch') and any(not hmac.compare_digest(incoming[k],current[k]) for k in ['credential','control_token']):raise ValueError('Conflicting credential epoch')
    stop_directory()
    for key in ['credential','control_token','credential_epoch']:current[key]=incoming[key]
    atomic(ROOT/'replica.json',json.dumps(current).encode());start_directory()
    return {'applied':True,'epoch':epoch}

class ControlServer(ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=True
class Handler(BaseHTTPRequestHandler):
    def setup(self):super().setup();self.connection.settimeout(15)
    def log_message(self,*args):pass
    def reply(self,status,value):
        data=json.dumps(value).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_GET(self):
        if self.path!='/health':return self.reply(404,{})
        self.reply(200,{'running':child is not None and child.poll() is None})
    def do_POST(self):
        current=json.loads((ROOT/'replica.json').read_text())
        if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+current['control_token']):return self.reply(401,{'error':'Control authorization rejected'})
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=16384:raise ValueError('Invalid payload size')
            p=json.loads(self.rfile.read(length))
            if p.get('id')!=current['id']:raise ValueError('Wrong node identifier')
            reload=False
            with commands:
                if self.path=='/v1/credential':result=credential_update(p)
                elif self.path=='/v1/provider':
                    from urllib.parse import urlsplit
                    uri=urlsplit(p.get('provider',''))
                    if uri.scheme!='ldaps' or not uri.hostname or uri.username or uri.password or uri.path or uri.query or uri.fragment or any(c.isspace() or c in '\\"' for c in p['provider']):raise ValueError('Invalid provider')
                    stop_directory();current['provider']=p['provider'];atomic(ROOT/'replica.json',json.dumps(current).encode());start_directory();result={'applied':True}
                elif self.path=='/v1/certificate/stage':
                    generate_certificate(current['hostname'],'server-next');result={'certificate':(ROOT/'server-next.crt').read_text()}
                elif self.path=='/v1/certificate/activate':
                    expected=p.get('fingerprint','')
                    active=hashlib.sha256(certificate_der(ROOT/'server.crt')).hexdigest()
                    if active!=expected:
                        if not (ROOT/'server-next.crt').exists() or hashlib.sha256(certificate_der(ROOT/'server-next.crt')).hexdigest()!=expected:raise ValueError('Staged certificate does not match this transition')
                        stop_directory();activate_certificate();start_directory()
                    result={'activated':True};reload=True
                elif self.path=='/v1/certificate/retire':
                    if not matching_pair(ROOT/'server.key',ROOT/'server.crt'):raise ValueError('Active certificate pair is inconsistent')
                    for name in ['server.key.previous','server.crt.previous']:(ROOT/name).unlink(missing_ok=True)
                    result={'retired':True}
                elif self.path=='/v1/restart':stop_directory();start_directory();result={'restarted':True}
                else:return self.reply(404,{'error':'Unknown fixed operation'})
            self.reply(200,result)
            if reload:threading.Timer(0.2,self.server.shutdown).start()
        except Exception:self.reply(400,{'error':'Replica refused this transition; retry its current operation in Forklift'})

def shutdown(*args):
    with commands:stop_directory()
    raise SystemExit(0)

if __name__=='__main__':
    os.umask(0o077)
    if sys.argv[1:]==['health']:
        try:raise SystemExit(health())
        except Exception:raise SystemExit(1)
    if not (ROOT/'replica.json').exists():
        try:enroll()
        except Exception as exc:
            print('Enrollment failed: '+(str(exc) if isinstance(exc,ValueError) else type(exc).__name__+'. Check the manager HTTPS address and enrollment status.'),file=sys.stderr,flush=True);raise SystemExit(1)
    if (ROOT/'certificate-activation.json').exists():activate_certificate()
    start_directory();signal.signal(signal.SIGTERM,shutdown)
    while True:
        p=json.loads((ROOT/'replica.json').read_text())
        server=ControlServer((p['address'],p['control_port']),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(ROOT/'server.crt'),str(ROOT/'server.key'));server.socket=context.wrap_socket(server.socket,server_side=True)
        server.serve_forever();server.server_close()
