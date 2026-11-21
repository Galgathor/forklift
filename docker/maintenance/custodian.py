"""Non-root, Unix-only fixed operations. No Docker client/socket or command endpoint."""
import contextlib
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import storage

ROOTS=storage.ROOTS
WORK=Path('/work')
STATE=WORK/'job.json'
CONTROL=Path('/run/maintenance-control')
LDAP_CONTROL=Path('/run/ldap-control')
DNS_CONTROL=Path('/run/dns-control')
mutex=threading.Lock()


def atomic(path,data):storage.atomic(path,data)
def encode(value):return json.dumps(value).encode()
def read_state():return json.loads(STATE.read_text()) if STATE.exists() else None
def save(value):atomic(STATE,encode(value))
def secret(name):return (Path('/secrets')/name).read_text().strip()
def run(args,*,data=None):return subprocess.run(args,input=data,capture_output=True,check=True,timeout=120).stdout

class Local(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect('/run/ldap-control/primary.sock')
def primary(path,payload=None):
    conn=Local('localhost',timeout=40)
    try:
        conn.request('GET' if payload is None else 'POST',path,body=None if payload is None else encode(payload),headers={'Authorization':'Bearer '+secret('provision'),'Content-Type':'application/json'})
        response=conn.getresponse();value=json.load(response)
        if response.status!=200:raise ValueError(value.get('error','Directory control is unavailable'))
        return value
    finally:conn.close()


class Dns(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/run/dns-control/dns.sock')


def dns(path, job):
    connection=Dns('localhost',timeout=40)
    try:
        connection.request('POST',path,body=encode({'operation_id':job['id']}),headers={'Authorization':'Bearer '+Path('/dns-secrets/control').read_text().strip(),'Content-Type':'application/json'})
        response=connection.getresponse()
        if response.status!=200:raise ValueError('DNS recovery needs attention; check its supervisor and storage, then resume')
        return json.load(response)
    finally:connection.close()


def pause_dns(job):
    atomic(DNS_CONTROL/'offline.json',encode({'id':job['id'],'action':job['action']}))
    dns('/pause',job)


def finish_dns(job, restore=False):
    marker=DNS_CONTROL/'offline.json'
    if marker.exists():
        dns('/restore-start' if restore else '/start',job)
        marker.unlink()
        descriptor=os.open(DNS_CONTROL,os.O_DIRECTORY);os.fsync(descriptor);os.close(descriptor)


def initialize():
    for path in [*ROOTS.values(),WORK,Path('/backups'),Path('/transfers'),CONTROL,LDAP_CONTROL,Path('/run/ldap-socket')]:path.mkdir(parents=True,exist_ok=True);os.chmod(path,0o700)
    required=['bootstrap','provision','service','maintenance','node-control-key']
    if Path('/directory/complete').exists() and not Path('/secrets/initialized-v5').exists():raise ValueError('Version 0.5 requires fresh volumes; preserve old installation storage and use the previous release for old backups')
    if Path('/secrets/initialized-v5').exists() and (any(not (Path('/secrets')/name).is_file() for name in required) or not Path('/authority/ca.key').is_file()):raise ValueError('Persistent secrets are incomplete; restore a matching backup instead of regenerating credentials')
    authority=Path('/authority')
    if not (authority/'ca.crt').exists():
        if (authority/'ca.key').exists():raise ValueError('Incomplete CA initialization; preserve the authority volume')
        run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','3650','-subj','/CN=Forklift Local CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(authority/'ca.key'),'-out',str(authority/'ca.crt')])
    for name in ['provision','service','maintenance','node-control-key']:
        path=Path('/secrets')/name
        if not path.exists():atomic(path,(secrets.token_hex(48)+'\n').encode())
    bootstrap=Path('/secrets/bootstrap')
    if not bootstrap.exists():
        token=os.environ.get('FORKLIFT_BOOTSTRAP_TOKEN') or secrets.token_urlsafe(48)
        if len(token)<32:raise ValueError('Choose a one-time bootstrap token of at least 32 characters in deployment settings')
        atomic(bootstrap,(token+'\n').encode())
        if not os.environ.get('FORKLIFT_BOOTSTRAP_TOKEN'):print('One-time setup token: '+token,flush=True)
    for target in ['/secrets/ca.crt','/directory-secrets/ca.crt']:atomic(Path(target),(authority/'ca.crt').read_bytes())
    for name in ['provision','service']:atomic(Path('/directory-secrets')/name,(Path('/secrets')/name).read_bytes())
    if (WORK/'certificate-renewal.json').exists():renew(json.loads((WORK/'certificate-renewal.json').read_text()))
    elif not Path('/directory-secrets/ldap.crt').exists():renew({'hostname':'ldap','address':'127.0.0.1','port':636})
    atomic(Path('/secrets/ldap.crt'),Path('/directory-secrets/ldap.crt').read_bytes())
    atomic(Path('/secrets/initialized-v5'),b'5')
    print('Forklift storage is ready. Initial setup and ongoing management are available in the WebUI.',flush=True)


def renew(network):
    """Stage and durably publish the same validated pair after interruption."""
    journal=WORK/'certificate-renewal.json'
    if journal.exists():
        recorded=json.loads(journal.read_text())
        if recorded!=network:raise ValueError('Resume the pending certificate operation before choosing another network identity')
    else:
        names={'DNS:ldap','DNS:localhost','IP:'+network['address']}
        try:ipaddress.ip_address(network['hostname']);names.add('IP:'+network['hostname'])
        except ValueError:names.add('DNS:'+network['hostname'])
        # Retain existing DNS/IP identities so ordinary leaf renewal does not break clients.
        old=Path('/directory-secrets/ldap.crt')
        if old.exists():
            extension=run(['openssl','x509','-in',str(old),'-noout','-ext','subjectAltName']).decode()
            for kind,value in re.findall(r'(DNS|IP Address):([^,\s]+)',extension):
                if kind=='DNS' and re.fullmatch(r'[a-z0-9.-]{1,253}',value):names.add('DNS:'+value)
                elif kind=='IP Address':names.add('IP:'+str(ipaddress.ip_address(value)))
        run(['openssl','req','-new','-newkey','rsa:3072','-nodes','-subj','/CN=Forklift directory','-keyout','/work/leaf.key','-out','/work/leaf.csr'])
        atomic(WORK/'extensions',('basicConstraints=critical,CA:FALSE\nsubjectAltName='+','.join(sorted(names))+'\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n').encode())
        run(['openssl','x509','-req','-in','/work/leaf.csr','-CA','/authority/ca.crt','-CAkey','/authority/ca.key','-set_serial',str(int.from_bytes(secrets.token_bytes(16),'big') or 1),'-days','365','-extfile','/work/extensions','-out','/work/leaf.crt'])
        for file in [WORK/'leaf.key',WORK/'leaf.crt']:
            with open(file,'rb') as stream:os.fsync(stream.fileno())
        atomic(journal,encode(network))
    run(['openssl','verify','-CAfile','/authority/ca.crt','/work/leaf.crt'])
    private=run(['openssl','pkey','-in','/work/leaf.key','-pubout','-outform','DER'])
    public=run(['openssl','x509','-in','/work/leaf.crt','-pubkey','-noout'])
    if private!=run(['openssl','pkey','-pubin','-outform','DER'],data=public):raise ValueError('Certificate pair validation failed')
    atomic(Path('/directory-secrets/ldap.key'),(WORK/'leaf.key').read_bytes())
    atomic(Path('/directory-secrets/ldap.crt'),(WORK/'leaf.crt').read_bytes())
    atomic(Path('/secrets/ldap.crt'),(WORK/'leaf.crt').read_bytes())
    journal.unlink()
    for name in ['leaf.key','leaf.crt','leaf.csr','extensions']:(WORK/name).unlink(missing_ok=True)


def pause(job):
    atomic(LDAP_CONTROL/'offline.json',encode({'id':job['id'],'action':job['action']}))
    primary('/pause',{})
def start(job):primary('/start',{'operation_id':job['id']})
def finish_pause(job):
    start(job)
    (LDAP_CONTROL/'offline.json').unlink(missing_ok=True)
    fd=os.open(LDAP_CONTROL,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def configured_network():return json.loads(Path('/directory/network.json').read_text())
def configure(network,job):
    value=primary('/validate-network',network)
    pause(job);renew(value);primary('/network',value);finish_pause(job)
    return value


def snapshot(target):
    target.mkdir(parents=True,exist_ok=True)
    for prefix,root in ROOTS.items():
        destination=target/prefix;destination.mkdir(exist_ok=True)
        for file in root.rglob('*'):
            if file.is_symlink():raise ValueError('Unexpected symbolic link in managed storage')
            path=destination/file.relative_to(root)
            if file.is_dir():path.mkdir(parents=True,exist_ok=True)
            elif file.is_file():
                path.parent.mkdir(parents=True,exist_ok=True);atomic(path,file.read_bytes()) if file.stat().st_size<1024*1024 else durable_copy(file,path)
            else:raise ValueError('Unexpected file type in managed storage')
    manifest=[]
    for file in target.rglob('*'):
        if file.is_file():manifest.append({'path':file.relative_to(target).as_posix(),'sha256':storage.sha(file)})
    for folder in [target,*[p for p in target.rglob('*') if p.is_dir()]]:
        fd=os.open(folder,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    atomic(target/'apply-manifest.json',encode(manifest))

def durable_copy(source,destination):
    destination.parent.mkdir(parents=True,exist_ok=True)
    temporary=destination.with_name(destination.name+'.new')
    with open(source,'rb') as src,open(temporary,'wb') as dst:
        shutil.copyfileobj(src,dst,1024*1024);dst.flush();os.fsync(dst.fileno())
    temporary.replace(destination)
    fd=os.open(destination.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)

def apply_stage(stage):
    expected=json.loads((stage/'apply-manifest.json').read_text())
    for item in expected:
        storage.safe_name(item['path'])
        if storage.sha(stage/item['path'])!=item['sha256']:raise ValueError('Prepared recovery data is inconsistent; choose rollback')
    for prefix,root in ROOTS.items():
        source=stage/prefix
        # Retain expected files until their atomic replacements are ready; control secrets never disappear.
        for file in sorted(root.rglob('*'),key=lambda p:len(p.parts),reverse=True):
            relative=file.relative_to(root)
            if not (source/relative).exists():
                if file.is_dir() and not file.is_symlink():file.rmdir()
                else:file.unlink()
        for file in source.rglob('*'):
            path=root/file.relative_to(source)
            if file.is_dir():path.mkdir(parents=True,exist_ok=True,mode=0o700)
            else:durable_copy(file,path);os.chmod(path,0o600)
        for folder in [root,*[p for p in root.rglob('*') if p.is_dir()]]:
            fd=os.open(folder,os.O_DIRECTORY);os.fsync(fd);os.close(fd)

def prepare_restore(p):
    stage=WORK/'stage'
    floor=p['uid_floor'];manifest=json.loads((stage/'validated.json').read_text())
    if manifest.get('format')!=3:raise ValueError('This legacy LDAP-only archive does not contain DNS data. It can be verified, but full installation restore requires a DNS-inclusive backup or the matching earlier release.')
    atomic(stage/'dns-secrets/control',Path('/dns-secrets/control').read_bytes())
    if type(floor) is not int or not manifest['id_high_water']<floor<=2147483647:raise ValueError('Choose a future Unix ID floor above every archived and subsequently allocated ID')
    # Keep local control authorization and the new host's advertised address; recover directory secrets/data.
    for name in ['bootstrap','provision','maintenance']:atomic(stage/'secrets'/name,(Path('/secrets')/name).read_bytes())
    atomic(stage/'directory-secrets/provision',Path('/directory-secrets/provision').read_bytes())
    value=primary('/validate-network',p['network'])
    atomic(stage/'directory/network.json',encode(value))
    db=sqlite3.connect(stage/'metadata/forklift.db')
    db.execute('DELETE FROM sessions');db.execute('UPDATE allocator SET value=?',(floor-1,))
    db.execute("INSERT INTO settings VALUES('recovery_required','true') ON CONFLICT(key) DO UPDATE SET value='true'")
    db.execute("UPDATE directory_servers SET enrollment_hash=NULL,enrollment_expires=0,state='restore_required',pending_epoch=NULL,last_error='Restored snapshot: fence and reseed this server'")
    tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'dns_servers' in tables:
        for node_id,raw in db.execute('SELECT id,data FROM dns_servers').fetchall():
            node=json.loads(raw);node.update(state='restore_required',join_hash=None,expires_at=0,last_error='Restored snapshot: old DNS node must remain fenced and be reenrolled',report={'state':'restore_required'})
            for field in ['pending_generation','next_certificate','rotation','certificate_staged_at','certificate_retirement_pending']:node.pop(field,None)
            db.execute('UPDATE dns_servers SET data=? WHERE id=?',(json.dumps(node),node_id))
    if 'dns_changes' in tables:db.execute("UPDATE dns_changes SET status='completed',error='Restored snapshot: review ownership and replan before DNS changes' WHERE status!='completed'")
    if 'host_dns' in tables:
        for host_id,raw in db.execute('SELECT id,data FROM host_dns').fetchall():
            dns_state=json.loads(raw);dns_state['status'].update(state='needs_review',operation_id=None,error='Restored DNS state requires ownership reconciliation')
            db.execute('UPDATE host_dns SET data=? WHERE id=?',(json.dumps(dns_state),host_id))
    db.execute("DELETE FROM settings WHERE key='dns_primary'")
    db.execute("INSERT INTO settings VALUES('public_url',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps(p['public_url']),))
    directory=json.loads(db.execute("SELECT value FROM settings WHERE key='directory'").fetchone()[0]);directory['network']=value
    db.execute("UPDATE settings SET value=? WHERE key='directory'",(json.dumps(directory),))
    for host_id,data in db.execute('SELECT id,data FROM hosts').fetchall():
        host=json.loads(data);host['revision']+=1
        if host.get('directory_id')=='primary':host['hostname']=value['hostname'];host['endpoints']=[value['endpoint']]
        db.execute('UPDATE hosts SET hostname=?,data=? WHERE id=?',(host['hostname'],json.dumps(host),host_id))
    db.commit();db.execute('PRAGMA wal_checkpoint(TRUNCATE)');db.execute('PRAGMA journal_mode=DELETE');db.close()
    manifest=[]
    for prefix in ROOTS:
        for file in (stage/prefix).rglob('*'):
            if file.is_file():manifest.append({'path':file.relative_to(stage).as_posix(),'sha256':storage.sha(file)})
    atomic(stage/'apply-manifest.json',encode(manifest))
    return value


def verify(p):
    stage=WORK/'stage'
    if stage.exists():shutil.rmtree(stage)
    stage.mkdir(mode=0o700)
    if not re.fullmatch('[a-f0-9]{32}',p.get('upload_id','')):raise ValueError('Invalid upload identifier')
    if not isinstance(p.get('identity'),str) or len(p['identity'])>8192:raise ValueError('Upload a native age recovery identity')
    with tempfile.NamedTemporaryFile(dir='/tmp',mode='w',prefix='age-identity-') as identity:
        identity.write(p['identity']);identity.flush()
        return storage.unpack({'archive_path':'/transfers/'+p['upload_id']+'.age','identity_path':identity.name,'sha256':p['sha256'],'max_bytes':p.get('max_gib',8)*1024**3})


def execute(p,resume=False,rollback=False):
    job=read_state() if resume or rollback else {'id':p['id'],'action':p['action'],'actor':p['actor'],'parameters':{k:v for k,v in p.items() if k not in ['identity']},'phase':'starting'}
    if not job or job['id']!=p['id']:raise ValueError('No matching maintenance operation')
    job['status']='running';job.pop('error',None);save(job)
    params=job['parameters'];base={'operation_id':job['id'],'actor':job['actor']}
    try:
        action=job['action']
        if rollback:
            if (WORK/'rollback/apply-manifest.json').exists():pause_dns(job);pause(job);apply_stage(WORK/'rollback')
            elif job['phase'] not in ['verified','snapshotting']:raise ValueError('No complete rollback snapshot exists')
            db=sqlite3.connect('/metadata/forklift.db');db.execute('DELETE FROM sessions');db.commit();db.close()
            finish_pause(job);finish_dns(job)
            storage.event(base,'rollback','completed',detail='Previous LDAP/DNS data and credentials restored; sessions revoked')
            result={'rolled_back':True,'reauthenticate':True}
        elif action=='backup':
            pause(job);storage.event(base,'backup','started')
            filename=job['id']+'.tar.gz.age';file=Path('/backups')/filename
            if file.exists():result={'artifact':filename,'sha256':storage.sha(file),'bytes':file.stat().st_size}
            else:
                (Path('/backups')/('.'+job['id']+'.partial')).unlink(missing_ok=True)
                result=storage.pack({**base,'recipient':params['recipient'],'filename':filename,'owner_uid':10001,'owner_gid':10001,'source':{'version':'0.5.0'},'max_bytes':params.get('max_gib',8)*1024**3})
            atomic(Path('/backups')/(job['id']+'.json'),encode({**result,'id':job['id'],'at':int(time.time())}))
            storage.event(base,'backup','completed',filename,result['sha256']);finish_pause(job)
        elif action=='verify':
            result=verify(p)
            shutil.rmtree(WORK/'stage');storage.event(base,'verify backup','completed',checksum=params['sha256'])
        elif action=='restore':
            if not params.get('original_fenced') or not params.get('acknowledge'):raise ValueError('Acknowledge replacement and fence the original primary and all old replicas')
            if job['phase'] not in ['verified','snapshotting','prepared','applying','restarting']:
                result=verify(p);network=prepare_restore(params)
                for folder in [WORK/'stage',*[f for f in (WORK/'stage').rglob('*') if f.is_dir()]]:
                    fd=os.open(folder,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
                job['phase']='verified';save(job)
            if job['phase'] in ['verified','snapshotting']:
                pause_dns(job);pause(job);job['phase']='snapshotting';save(job)
                if not (WORK/'rollback/apply-manifest.json').exists():
                    if (WORK/'rollback').exists():shutil.rmtree(WORK/'rollback')
                    snapshot(WORK/'rollback')
                job['phase']='prepared';save(job)
            pause_dns(job);pause(job);job['phase']='applying';save(job)
            apply_stage(WORK/'stage')
            network=configured_network();renew(network)
            storage.validate_config(Path('/directory'),Path('/directory-secrets'))
            job['phase']='restarting';save(job);finish_dns(job,restore=True);finish_pause(job)
            storage.event(base,'restore','completed',checksum=params['sha256'],detail='Sessions revoked; directory/DNS replicas quarantined; DNS transfer rights removed; recovery review required')
            result={'restored':True,'recovery_required':True,'reauthenticate':True,'uid_floor':params['uid_floor']}
        elif action=='rotate-service':
            pause(job);storage.rotate_service(base)
            atomic(Path('/directory-secrets/service'),Path('/secrets/service').read_bytes())
            start(job)
            suffix=Path('/directory/complete').read_text().strip()
            run(['ldapwhoami','-x','-H','ldapi://%2Frun%2Fldap-socket%2Fldap.sock','-D','cn=manager,'+suffix,'-y','/dev/stdin'],data=secret('service').encode())
            Path('/secrets/service-rotation.json').unlink(missing_ok=True)
            finish_pause(job);result={'rotated':True,'reauthenticate':True}
        elif action in ['renew-primary','configure-primary']:
            if 'previous_endpoint' not in job:
                job['previous_endpoint']=configured_network().get('endpoint');save(job)
            previous=job['previous_endpoint']
            network=configure(params.get('network') or configured_network(),job)
            storage.event(base,action,'completed',detail='Primary TLS and private listener verified and restarted')
            result={'network':network,'previous_endpoint':previous}
        else:raise ValueError('Unknown maintenance operation')
        if (WORK/'dns-backup').exists():shutil.rmtree(WORK/'dns-backup')
        job.update(status='awaiting_ack',phase='awaiting_ack',result=result,finished_at=int(time.time()));save(job)
        return job
    except Exception as exc:
        recoverable=((LDAP_CONTROL/'offline.json').exists() or (DNS_CONTROL/'offline.json').exists()) and (job['action'] in ['rotate-service','restore','configure-primary','renew-primary'])
        if not recoverable:
            try:finish_pause(job)
            except Exception:recoverable=True
        job.update(status='needs_resume' if recoverable else 'failed',error=str(exc) if isinstance(exc,ValueError) else 'Maintenance failed; retry or resume the recorded operation',finished_at=int(time.time()))
        if not recoverable:
            for folder in ['stage','dns-backup']:
                if (WORK/folder).exists():shutil.rmtree(WORK/folder)
        save(job);return job


def listing():
    return [json.loads(file.read_text()) for file in sorted(Path('/backups').glob('*.json'),key=lambda f:f.stat().st_mtime,reverse=True)]

def emergency(p):
    from argon2 import PasswordHasher
    from urllib.parse import urlsplit
    username=p.get('username','');password=p.get('password','')
    if not re.fullmatch('[a-z][a-z0-9_-]{0,31}',username) or not 14<=len(password)<=1024:raise ValueError('Use an existing username and a password of 14 to 1024 characters')
    public=p.get('public_url','')
    if public:
        uri=urlsplit(public)
        if uri.scheme not in ['http','https'] or not uri.hostname or uri.username or uri.password or uri.path or uri.query or uri.fragment or any(c.isspace() for c in public):raise ValueError('Use a plain HTTP(S) origin without a path')
        host=uri.hostname.encode('idna').decode()
        if ':' in host:host='['+host+']'
        port=uri.port
        public=uri.scheme+'://'+host+(':'+str(port) if port and port!={'http':80,'https':443}[uri.scheme] else '')
    state=read_state()
    if state and state['status'] in ['running','needs_resume','awaiting_ack']:raise ValueError('Finish the recorded maintenance operation first')
    suffix=Path('/directory/complete').read_text().strip()
    if not storage.valid_base(suffix):raise ValueError('Invalid directory suffix')
    primary('/start',{})
    hashed='{ARGON2}'+PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1).hash(password)
    modify=f'dn: uid={username},ou=people,{suffix}\nchangetype: modify\nreplace: userPassword\nuserPassword: {hashed}\n-\nreplace: shadowExpire\n\n'
    group=f'dn: cn=administrators,ou=groups,{suffix}\nchangetype: modify\nadd: memberUid\nmemberUid: {username}\n'
    def apply(data,allow_existing=False):
        read,write=os.pipe();os.write(write,secret('service').encode());os.close(write)
        try:
            result=subprocess.run(['ldapmodify','-x','-H','ldapi://%2Frun%2Fldap-socket%2Fldap.sock','-D','cn=manager,'+suffix,'-y','/dev/fd/'+str(read)],input=data.encode(),pass_fds=(read,),capture_output=True,timeout=20)
            if result.returncode and not (allow_existing and result.returncode==20):raise ValueError('Existing account recovery failed; check the username and directory state')
        finally:os.close(read)
    apply(modify);apply(group,True)
    db=sqlite3.connect('/metadata/forklift.db',timeout=10)
    if public:db.execute("INSERT INTO settings VALUES('public_url',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps(public),))
    db.execute('DELETE FROM sessions');db.execute('INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)',(int(time.time()),'local-recovery','recover administrator',username));db.commit();db.close()
    return {'recovered':True}

def dispatch(path,p):
    for upload in Path('/transfers').glob('*.age'):
        if re.fullmatch(r'[a-f0-9]{32}\.age',upload.name) and time.time()-upload.stat().st_mtime>86400:upload.unlink()
    if path=='/inspect':return {**primary('/health'),'storage':{'free_bytes':shutil.disk_usage('/backups').free},'job':read_state()}
    if path=='/emergency-reset':return emergency(p)
    if path=='/keygen':
        identity=run(['age-keygen']).decode()
        recipient=next(line.removeprefix('# public key: ') for line in identity.splitlines() if line.startswith('# public key: '))
        return {'identity':identity,'recipient':recipient}
    if path=='/configure':
        state=read_state()
        if state and state['status'] in ['running','needs_resume','awaiting_ack']:raise ValueError('Finish the existing maintenance job first')
        return configure(p,{'id':secrets.token_hex(16),'action':'setup network'})
    if path=='/run':
        if not re.fullmatch('[a-f0-9]{32}',p.get('id','')):raise ValueError('Invalid maintenance identifier')
        if p.get('action') in ['resume','rollback']:
            current=read_state()
            if not current or current['status'] not in ['needs_resume','awaiting_ack']:raise ValueError('This operation does not require recovery')
            if current and current['id']==p['id'] and current['status']=='awaiting_ack' and p['action']=='resume':return current
            return execute(p,resume=p['action']=='resume',rollback=p['action']=='rollback')
        state=read_state()
        if state and state['status'] in ['running','needs_resume','awaiting_ack']:raise ValueError('An existing operation requires recovery')
        if p.get('action')=='backup':
            if not re.fullmatch('age1[0-9a-z]+',p.get('recipient','')):raise ValueError('Use a native age public recipient')
            run(['age','-r',p['recipient']],data=b'')
        if type(p.get('max_gib',8)) is not int or not 1<=p.get('max_gib',8)<=64:raise ValueError('Invalid snapshot size limit')
        return execute(p)
    if path=='/ack':
        job=read_state()
        if not job or job['id']!=p.get('id'):raise ValueError('No matching operation to acknowledge')
        if job['status']=='completed':return job
        if job['status']!='awaiting_ack':raise ValueError('The operation is not ready to acknowledge')
        for folder in ['stage','rollback','dns-backup']:
            if (WORK/folder).exists():shutil.rmtree(WORK/folder)
        job.update(status='completed',phase='completed');save(job);return job
    if path=='/delete':
        if not re.fullmatch('[a-f0-9]{32}',p.get('id','')):raise ValueError('Invalid backup identifier')
        for extension in ['.json','.tar.gz.age']:(Path('/backups')/(p['id']+extension)).unlink(missing_ok=True)
        return {'deleted':True}
    raise ValueError('Unknown fixed operation')

class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):daemon_threads=True
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def reply(self,code,value):
        data=encode(value);self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers()
        try:self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError):pass
    def authorized(self):return hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+secret('maintenance'))
    def do_GET(self):
        if self.path=='/health':return self.reply(200,{'ready':True})
        if not self.authorized():return self.reply(403,{'error':'Maintenance authorization rejected'})
        if self.path=='/status':return self.reply(200,{'job':read_state(),'backups':listing(),'busy':mutex.locked(),'offline':(LDAP_CONTROL/'offline.json').exists() or (DNS_CONTROL/'offline.json').exists()})
        return self.reply(404,{})
    def do_POST(self):
        if not self.authorized():return self.reply(403,{'error':'Maintenance authorization rejected'})
        if not mutex.acquire(blocking=False):return self.reply(409,{'error':'A maintenance worker is active; wait for its result'})
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<65536:raise ValueError('Invalid maintenance payload size')
            value=dispatch(self.path,json.loads(self.rfile.read(length)))
            self.reply(200,value)
        except Exception as exc:self.reply(400,{'error':str(exc) if isinstance(exc,ValueError) else 'Maintenance operation failed; inspect storage and readiness'})
        finally:mutex.release()

if __name__=='__main__':
    os.umask(0o077)
    if sys.argv[1:]==['init']:initialize()
    else:
        state=read_state()
        if state and state['status']=='running':
            changed=(LDAP_CONTROL/'offline.json').exists() or (DNS_CONTROL/'offline.json').exists() or state['phase'] in ['verified','snapshotting','prepared','applying','restarting']
            state['status']='needs_resume' if changed else 'failed'
            state['error']='Interrupted operation; resume or roll back in Forklift' if changed else 'Interrupted before directory replacement; select the recovery key and retry in Forklift'
            if not changed and (WORK/'stage').exists():shutil.rmtree(WORK/'stage')
            save(state)
        (CONTROL/'maintenance.sock').unlink(missing_ok=True)
        Server(str(CONTROL/'maintenance.sock'),Handler).serve_forever()
