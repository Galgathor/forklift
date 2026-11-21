"""Fixed-operation, non-root primary supervisor. Control is Unix-socket only."""
import fcntl
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from argon2 import PasswordHasher

ROOT=Path('/directory')
CONTROL=Path('/run/ldap-control')
LDAPI='ldapi://%2Frun%2Fldap-socket%2Fldap.sock'
slapd=None
lock=threading.RLock()

def secret(name):return Path('/run/secrets/'+name).read_text().strip()
def hashed(value):return '{ARGON2}'+PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1).hash(value)
def valid_base(base):return isinstance(base,str) and len(base)<=255 and re.fullmatch(r'dc=[a-z0-9-]+(?:,dc=[a-z0-9-]+)+',base)
def replication_acl(base):return f'access to attrs=userPassword by dn.exact="cn=manager,{base}" write by dn.regex="^cn=replica-[0-9a-f]{{32}},{base}$" read by anonymous auth by * none'
def atomic(path,data):
    temporary=path.with_name(path.name+'.new')
    with open(temporary,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    temporary.replace(path)
    fd=os.open(path.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)

def configuration(base):
    return f'''# Forklift primary v5
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
localSSF 256
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


def interfaces():
    result=[]
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        for _,name in socket.if_nameindex():
            try:
                data=fcntl.ioctl(sock.fileno(),0x8915,struct.pack('256s',name[:15].encode()))
                address=socket.inet_ntoa(data[20:24]);ip=ipaddress.ip_address(address)
                if ip.is_private and not ip.is_loopback and not ip.is_link_local and not ip.is_reserved:
                    result.append({'name':name,'address':address})
            except OSError:pass
    return sorted(result,key=lambda item:(item['name'].startswith(('docker','br-','veth')),item['name']))

def network(value):
    address=str(ipaddress.IPv4Address(value['address']))
    if address not in [item['address'] for item in interfaces()]:raise ValueError('Choose a private IPv4 address assigned to this Docker host')
    hostname=value.get('hostname') or address
    if len(hostname)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in hostname.split('.')):raise ValueError('Use a lowercase DNS name or this private IPv4 address')
    port=value.get('port',636)
    if type(port) is not int or not 1<=port<=65535:raise ValueError('Invalid directory port')
    try:advertised=ipaddress.IPv4Address(hostname)
    except ValueError:advertised=None
    if advertised is not None and str(advertised)!=address:raise ValueError('Use the selected interface IP or a DNS name pointing to it')
    current=json.loads((ROOT/'network.json').read_text()) if (ROOT/'network.json').exists() else {}
    own=slapd is not None and slapd.poll() is None and current.get('address')==address and current.get('port')==port
    if not own:
        try:
            with socket.socket() as listener:listener.bind((address,port))
        except OSError:raise ValueError('This port is unavailable on the selected interface; choose another port such as 1636') from None
    return {'address':address,'hostname':hostname,'port':port,'endpoint':f'ldaps://{hostname}:{port}'}

def state():
    running=slapd is not None and slapd.poll() is None
    return {'initialized':(ROOT/'complete').exists(),'running':running,'paused':(CONTROL/'offline.json').exists(),'interfaces':interfaces()}

def stop():
    global slapd
    if slapd is not None:
        if slapd.poll() is None:
            slapd.terminate()
            try:slapd.wait(timeout=20)
            except subprocess.TimeoutExpired:raise ValueError('Directory did not stop cleanly; retry recovery without modifying its database') from None
        slapd=None

def start(operation_id=None):
    global slapd
    if slapd is not None and slapd.poll() is None:return state()
    if (CONTROL/'offline.json').exists():
        marker=json.loads((CONTROL/'offline.json').read_text())
        if marker['id']!=operation_id:raise ValueError('A maintenance job must finish before starting the directory')
    if not (ROOT/'complete').exists():return state()
    if not (ROOT/'layout-v5').exists():raise ValueError('This release requires fresh version-5 directory storage')
    config=json.loads((ROOT/'network.json').read_text());network(config)
    subprocess.run(['slaptest','-u','-f',str(ROOT/'slapd.conf')],capture_output=True,check=True,timeout=20)
    Path('/run/ldap-socket/ldap.sock').unlink(missing_ok=True)
    slapd=subprocess.Popen(['slapd','-f',str(ROOT/'slapd.conf'),'-h',f"{LDAPI} ldaps://{config['address']}:{config['port']}",'-d','256'])
    for _ in range(100):
        if slapd.poll() is not None:raise ValueError('Directory process exited; check its configured interface, port and certificates')
        try:
            with socket.socket(socket.AF_UNIX) as client:client.connect('/run/ldap-socket/ldap.sock')
            return state()
        except OSError:time.sleep(0.1)
    raise ValueError('Directory startup timed out')

def initialize(p):
    if (ROOT/'complete').exists():return {'initialized':True,'existing':True}
    base,user,password=p['base'],p['username'],p['password']
    if not valid_base(base) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}',user) or not 14<=len(password)<=1024:raise ValueError('Invalid initialization values')
    journal=ROOT/'initialization.json';stage=ROOT/'initializing'
    identity={'base':base,'username':user}
    if journal.exists() and json.loads(journal.read_text())!=identity:raise ValueError('Retry setup with the original base and administrator')
    if not journal.exists():
        if (ROOT/'slapd.conf').exists() or (ROOT/'db').exists():raise ValueError('Unrecognized partial directory; restore a matching backup')
        atomic(journal,json.dumps(identity).encode())
    if not (ROOT/'network.json').exists():raise ValueError('Configure this server in setup before initializing LDAP')
    prepared=stage/'prepared'
    if not prepared.exists():
        if stage.exists():shutil.rmtree(stage)
        (stage/'db').mkdir(parents=True)
        atomic(stage/'slapd.conf',configuration(base).replace('directory /directory/db','directory /directory/initializing/db').encode())
    entries = [f'dn: {base}\nobjectClass: domain\ndc: {base.split(",")[0][3:]}',
        f'dn: cn=manager,{base}\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: manager\nuserPassword: {hashed(secret("service"))}',
        *[f'dn: ou={ou},{base}\nobjectClass: organizationalUnit\nou: {ou}' for ou in ['people','groups']],
        f'dn: cn=administrators,ou=groups,{base}\nobjectClass: posixGroup\ncn: administrators\ngidNumber: 10000\nmemberUid: {user}',
        f'dn: uid={user},ou=people,{base}\nobjectClass: inetOrgPerson\nobjectClass: posixAccount\nobjectClass: shadowAccount\nuid: {user}\ncn: {user}\nsn: {user}\nuidNumber: 10000\ngidNumber: 10000\nhomeDirectory: /home/{user}\nloginShell: /bin/bash\nuserPassword: {hashed(password)}']

    if not prepared.exists():
        subprocess.run(['slapadd','-f',str(stage/'slapd.conf'),'-l','/dev/stdin'],input=('\n\n'.join(entries)+'\n').encode(),check=True,capture_output=True,timeout=30)
        for file in (stage/'db').rglob('*'):
            if file.is_file():
                with open(file,'rb') as stream:os.fsync(stream.fileno())
        fd=os.open(stage/'db',os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        atomic(prepared,b'prepared')
    if (stage/'db').exists():(stage/'db').rename(ROOT/'db')
    atomic(ROOT/'slapd.conf',configuration(base).encode())
    atomic(ROOT/'layout-v5',b'5')
    atomic(ROOT/'complete',base.encode())
    shutil.rmtree(stage);journal.unlink()
    start()
    return {'initialized':True}

class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):daemon_threads=True
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def reply(self,code,value):
        data=json.dumps(value).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers()
        try:self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError):pass
    def do_GET(self):
        if self.path!='/health':return self.reply(404,{})
        self.reply(200,state())
    def do_POST(self):
        if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+secret('provision')):return self.reply(403,{'error':'Control authorization rejected'})
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<16384:raise ValueError('Invalid control payload size')
            p=json.loads(self.rfile.read(length))
            with lock:
                if self.path=='/initialize':result=initialize(p)
                elif self.path=='/pause':stop();result=state()
                elif self.path=='/start':result=start(p.get('operation_id'))
                elif self.path=='/validate-network':result=network(p)
                elif self.path=='/network':
                    if slapd is not None and slapd.poll() is None:raise ValueError('Pause the directory before changing its listener')
                    result=network(p);atomic(ROOT/'network.json',json.dumps(result).encode())
                else:return self.reply(404,{'error':'Unknown control operation'})
            self.reply(200,result)
        except Exception as exc:
            self.reply(400,{'error':str(exc) if isinstance(exc,ValueError) else 'Directory control failed; inspect its process and storage readiness'})

def shutdown(*args):
    with lock:stop()
    raise SystemExit(0)

if __name__=='__main__':
    os.umask(0o077)
    CONTROL.mkdir(exist_ok=True)
    (CONTROL/'primary.sock').unlink(missing_ok=True)
    if (ROOT/'complete').exists() and not (CONTROL/'offline.json').exists():
        try:start()
        except Exception:print('Directory requires attention in Forklift Settings',file=sys.stderr,flush=True)
    signal.signal(signal.SIGTERM,shutdown)
    Server(str(CONTROL/'primary.sock'),Handler).serve_forever()
