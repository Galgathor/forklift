#!/usr/bin/env python3
"""Real HTTPS enrollment, Syncrepl and Ubuntu first-login failover, isolated storage."""
import configparser
import http.cookiejar
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import re
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from urllib.error import HTTPError,URLError

SOURCE=Path(__file__).resolve().parents[1]
os.chdir(SOURCE)
PROJECT='forklift-repl-test-'+secrets.token_hex(4)
PASSWORD=secrets.token_urlsafe(32)
BASE='dc=replication,dc=test'
workspace=tempfile.TemporaryDirectory(prefix=PROJECT+'-')
ROOT=Path(workspace.name)
checks=0

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]

def run(*args,input=None,check=True,cwd=None,env=None):
    result=subprocess.run(args,input=input,capture_output=True,cwd=cwd,env=env)
    if check and result.returncode:
        # Command arguments contain no credentials; do not dump potentially sensitive output.
        diagnostic=result.stderr.decode(errors='replace')[-2400:]
        diagnostic=re.sub(r'[a-f0-9]{64}', '[redacted]', diagnostic)
        for value in [PASSWORD,globals().get('csrf',''),globals().get('bind',''),globals().get('service',''),globals().get('updated_password','')]:
            if value: diagnostic=diagnostic.replace(value,'[redacted]')
        print(diagnostic,flush=True)
        raise RuntimeError('Command failed: '+args[0]+' '+args[1]+' (exit '+str(result.returncode)+')')
    return result

URL='https://localhost:'+str(port())
ENV={**os.environ,'FORKLIFT_PORT':str(port()),'FORKLIFT_PUBLIC_URL':URL,'FORKLIFT_BIND':'127.0.0.1'}
PRIMARY_ROOT=ROOT/'primary';PRIMARY_ROOT.mkdir()
shutil.copy2(SOURCE/'compose.yaml',PRIMARY_ROOT/'compose.yaml')
shutil.copy2(SOURCE/'.env.example',PRIMARY_ROOT/'.env.example')
(PRIMARY_ROOT/'scripts').mkdir();shutil.copy2(SOURCE/'scripts/install.sh',PRIMARY_ROOT/'scripts/install.sh')
shutil.copy2(SOURCE/'scripts/renew-ldap-certificate.sh',PRIMARY_ROOT/'scripts/renew-ldap-certificate.sh')
(PRIMARY_ROOT/'deploy/primary').mkdir(parents=True);shutil.copy2(SOURCE/'deploy/primary/clients.compose.yaml',PRIMARY_ROOT/'deploy/primary/clients.compose.yaml')
run('sh','scripts/install.sh',cwd=PRIMARY_ROOT)
(PRIMARY_ROOT/'.env').write_text('FORKLIFT_PUBLIC_URL='+URL+'\nFORKLIFT_PORT='+ENV['FORKLIFT_PORT']+'\nFORKLIFT_BIND=127.0.0.1\n')
override=ROOT/'primary.yaml'
override.write_text('services:\n  ldap:\n    image: forklift-ldap:latest\n    networks:\n      directory: {}\n      web:\n        aliases: [primary.replication.test]\n  manager:\n    image: forklift-manager:latest\n')
def compose(*args):
    return run('docker','compose','--project-directory',str(PRIMARY_ROOT),'-p',PROJECT,'-f',str(PRIMARY_ROOT/'compose.yaml'),'-f',str(override),*args,env=ENV)

def certs():
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Forklift disposable proxy CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(ROOT/'ca.key'),'-out',str(ROOT/'ca.crt'))
    run('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',str(ROOT/'server.key'),'-out',str(ROOT/'server.csr'))
    (ROOT/'extensions').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost,DNS:enrollment\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
    run('openssl','x509','-req','-in',str(ROOT/'server.csr'),'-CA',str(ROOT/'ca.crt'),'-CAkey',str(ROOT/'ca.key'),'-CAcreateserial','-days','2','-extfile',str(ROOT/'extensions'),'-out',str(ROOT/'server.crt'))

certs()
context=ssl.create_default_context(cafile=str(ROOT/'ca.crt'))
jar=http.cookiejar.CookieJar()
client=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),urllib.request.HTTPCookieProcessor(jar))
csrf=''
def request(path,method='GET',body=None,expect=200,raw=False,auth=True,use_csrf=True):
    global checks
    headers={'Content-Type':'application/json','Origin':URL}
    if use_csrf:headers['X-CSRF-Token']=csrf
    req=urllib.request.Request(URL+path,data=json.dumps(body).encode() if body is not None else None,headers=headers,method=method)
    opener=client if auth else urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
    try:r=opener.open(req,timeout=45)
    except HTTPError as exc:r=exc
    with r:status=r.code;data=r.read()
    assert status==expect,f'{method} {path}: expected {expect}, got {status}'
    checks+=1
    return data if raw else json.loads(data)

def wait_ready():
    for _ in range(90):
        try:request('/ready');return
        except (URLError,ConnectionError,AssertionError):time.sleep(1)
    raise AssertionError('Manager not ready')

def synchronized(server_id):
    for _ in range(90):
        result=request('/api/directory-servers')
        node=next(s for s in result['servers'] if s['id']==server_id)
        if node['state']=='synchronized':
            assert node['context_csn'] and node['last_sync_at']
            return node
        time.sleep(1)
    raise AssertionError('Replica did not synchronize: '+node['state']+' '+str(node.get('error')))

def user(name,password=PASSWORD,disabled=False):
    return dict(username=name,display_name=name.title(),email='',description='',shell='/bin/bash',home='/home/'+name,gid=10000,password=password,disabled=disabled)

def unpack(data,directory):
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
        assert not any('ca.key' in n for n in archive.getnames())
        archive.extractall(directory,filter='data')

replica_dir=ROOT/'replica';replica_dir.mkdir()
replica_project=PROJECT+'-secondary'
replica_env={**os.environ,'FORKLIFT_REPLICA_BIND':'127.0.0.1','FORKLIFT_REPLICA_PORT':str(port())}
def replica(*args,check=True):
    return run('docker','compose','-p',replica_project,'-f',str(replica_dir/'compose.yaml'),'-f',str(ROOT/'replica-override.yaml'),*args,env=replica_env,cwd=replica_dir,check=check)

def replica_exec(*args,input=None,check=True):
    container=replica('ps','-q','replica').stdout.decode().strip()
    return run('docker','exec','-i',container,*args,input=input,check=check)

ubuntu=PROJECT+'-ubuntu'
def client_command(*args,input=None,check=True):
    return run('docker','exec','-i',ubuntu,*args,input=input,check=check)

def ssh(name,password,allowed=True):
    script="""import os,subprocess,sys
r,w=os.pipe();os.write(w,sys.stdin.buffer.read()+b'\\n');os.close(w)
p=subprocess.run(['sshpass','-d',str(r),'ssh','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile=/tmp/known-hosts','-o','ConnectTimeout=8','-o','NumberOfPasswordPrompts=1','-o','PreferredAuthentications=password','-p','2222',sys.argv[1]+'@localhost','id -u'],pass_fds=(r,),capture_output=True,timeout=40)
os.close(r);sys.exit(p.returncode)
"""
    result=client_command('python3','-c',script,name,input=password.encode(),check=False)
    assert (result.returncode==0)==allowed,'Unexpected SSH outcome for '+name+' (exit '+str(result.returncode)+')'

try:
    compose('up','-d','--no-build','--wait')
    run('docker','run','-d','--name',PROJECT+'-proxy','--user',str(os.getuid())+':'+str(os.getgid()),'--network',PROJECT+'_web','--network-alias','enrollment','-p','127.0.0.1:'+URL.rsplit(':',1)[1]+':8443','-v',str(ROOT)+':/fixture:ro','-v',str(Path('tests/tls_proxy.py').resolve())+':/proxy.py:ro','--entrypoint','python3','forklift-ldap:latest','/proxy.py')
    wait_ready()
    bootstrap=run('docker','run','--rm','-v',str(PRIMARY_ROOT/'.secrets')+':/secrets:ro','alpine:3.22.2','cat','/secrets/bootstrap').stdout.decode().strip()
    request('/api/setup','POST',dict(token=bootstrap,name='Replication test',base=BASE,username='admin',password=PASSWORD))
    csrf=request('/api/login','POST',dict(username='admin',password=PASSWORD))['csrf']
    assert any(c.secure for c in jar),'HTTPS sessions did not receive Secure cookies'
    print('Testing guided primary preparation, persisted publication and credential-free TLS checks…',flush=True)
    request('/api/replication/setup',auth=False,expect=401)
    assert request('/api/replication/setup')['https_ready']
    probe=dict(hostname='primary.replication.test',port=636)
    request('/api/replication/primary/check','POST',probe,use_csrf=False,expect=403)
    request('/api/replication/primary/check','POST',dict(hostname='127.0.0.1',port=636),expect=400)
    request('/api/replication/primary/check','POST',probe,expect=400) # existing certificate lacks this DNS name
    bridge=json.loads(run('docker','network','inspect','bridge').stdout)[0]['IPAM']['Config'][0]['Gateway']
    published=port()
    operator=['python3',str(SOURCE/'scripts/forklift-admin.py'),'--root',str(PRIMARY_ROOT),'--project',PROJECT,'--file',str(PRIMARY_ROOT/'compose.yaml'),'--file',str(override),'prepare-replication']
    invalid=run(*operator,'--hostname','primary.replication.test','--bind','0.0.0.0','--port',str(published),check=False)
    assert invalid.returncode
    run(*operator,'--hostname','primary.replication.test','--bind',bridge,'--port',str(published))
    private=ssl.create_default_context(cafile=str(PRIMARY_ROOT/'.secrets/ca.crt'))
    with socket.create_connection((bridge,published),timeout=5) as connection:
        with private.wrap_socket(connection,server_hostname='primary.replication.test'):pass
    assert 'COMPOSE_FILE=compose.yaml:' in (PRIMARY_ROOT/'.env').read_text()
    request('/api/replication/primary/check','POST',probe)
    assert request('/api/replication/setup')['primary_endpoint']=='ldaps://primary.replication.test:636'
    if os.environ.get('FORKLIFT_TEST_BROWSER_DEPS'):
        private_output=ROOT/'wizard-private';private_output.mkdir(mode=0o700)
        browser=run('docker','run','--rm','-i','--network','host','--user',str(os.getuid())+':'+str(os.getgid()),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--tmpfs','/tmp:rw,nosuid,size=256m','--shm-size','256m','-e','NODE_PATH=/deps','-v',str(Path(os.environ['FORKLIFT_TEST_BROWSER_DEPS']).resolve())+':/deps:ro','-v',str(SOURCE/'tests/enrollment-browser.cjs')+':/test.cjs:ro','-v',str(private_output)+':/output','mcr.microsoft.com/playwright:v1.65.0-noble@sha256:6e3fb709361521eb27161606e6da6d2674e5e89fa16516cb37d6fdd91372273d','node','/test.cjs',input=json.dumps(dict(url=URL,password=PASSWORD)).encode())
        browser_node=json.loads(browser.stdout)['id']
        shutil.copy2(private_output/'wizard.png','/tmp/forklift-enrollment-wizard.png')
        with tarfile.open(private_output/'wizard.tar.gz',mode='r:gz') as archive:
            assert archive.extractfile('.env').read()==b'FORKLIFT_REPLICA_BIND=192.168.1.25\nFORKLIFT_REPLICA_PORT=636\n'
            assert archive.extractfile('start.sh') and archive.getmember('start.sh').mode==0o700
        request('/api/replicas/'+browser_node,'DELETE')
        print('PASS: real Chromium guided primary check, simple machine fields, private deployment download and installation instructions.',flush=True)
    print('Testing HTTPS enrollment authorization, token scope, expiry and certificate constraints…',flush=True)
    draft=dict(name='Secondary',endpoint='ldaps://replica:636',provider='ldaps://primary.replication.test:636')
    request('/api/directory-servers','POST',draft,auth=False,expect=401)
    request('/api/directory-servers','POST',draft,use_csrf=False,expect=403)
    request('/api/directory-servers','POST',dict(draft,provider='ldap://ldap'),expect=400)
    node=request('/api/directory-servers','POST',draft)
    request('/api/directory-servers','POST',draft,expect=400)
    request('/api/replicas/'+node['id']+'/bundle','POST',dict(acknowledge=True),use_csrf=False,expect=403)
    request('/api/replicas/'+node['id']+'/bundle','POST',dict(acknowledge=True,bind_address='0.0.0.0'),expect=400)
    bundle=request('/api/replicas/'+node['id']+'/bundle','POST',dict(acknowledge=True,bind_address='192.168.1.20'),raw=True)
    unpack(bundle,replica_dir)
    enrollment=json.loads((replica_dir/'enrollment/enrollment.json').read_text())
    payload=dict(token=enrollment['token'],certificate=(ROOT/'ca.crt').read_text())
    request('/api/replicas/'+node['id']+'/enroll','POST',dict(payload,token='0'*64),auth=False,expect=403)
    request('/api/replicas/'+node['id']+'/enroll','POST',payload,auth=False,expect=400)
    request('/api/replicas/'+node['id']+'/enroll','POST',dict(payload,certificate=(ROOT/'server.crt').read_text()),auth=False,expect=400)
    expired=request('/api/directory-servers','POST',dict(draft,name='Expired',endpoint='ldaps://expired:636'))
    expired_bundle=ROOT/'expired';expired_bundle.mkdir()
    unpack(request('/api/replicas/'+expired['id']+'/bundle','POST',dict(acknowledge=True),raw=True),expired_bundle)
    expired_token=json.loads((expired_bundle/'enrollment/enrollment.json').read_text())['token']
    mutate="import sqlite3,sys; c=sqlite3.connect('/metadata/forklift.db');c.execute('UPDATE directory_servers SET enrollment_expires=0 WHERE id=?',(sys.argv[1],));c.commit()"
    run('docker','run','--rm','--network','none','-v',PROJECT+'_metadata:/metadata','--entrypoint','python3','forklift-ldap:latest','-c',mutate,expired['id'])
    request('/api/replicas/'+expired['id']+'/enroll','POST',dict(payload,token=expired_token),auth=False,expect=403)
    request('/api/replicas/'+expired['id'],'DELETE')
    # Use the test LAN's DNS alias and private CA for the manager's real HTTPS proxy.
    enrollment['manager_url']='https://enrollment:8443'
    (replica_dir/'enrollment/enrollment.json').write_text(json.dumps(enrollment))
    (replica_dir/'enrollment/manager-ca.crt').write_bytes((ROOT/'ca.crt').read_bytes())
    assert (replica_dir/'enrollment/enrollment.json').stat().st_uid==os.getuid()
    assert (replica_dir/'.env').read_text().splitlines()==['FORKLIFT_REPLICA_BIND=192.168.1.20','FORKLIFT_REPLICA_PORT=636']
    (ROOT/'replica-override.yaml').write_text('services:\n  replica:\n    networks: [lan]\nnetworks:\n  lan:\n    external: true\n    name: '+PROJECT+'_web\n')
    print('Testing unreachable primary is diagnosed before the one-use enrollment token is spent…',flush=True)
    failed_enrollment=ROOT/'failed-enrollment';failed_enrollment.mkdir(mode=0o700)
    failed_directory=ROOT/'failed-directory';failed_directory.mkdir(mode=0o700)
    (failed_enrollment/'enrollment.json').write_text(json.dumps({**enrollment,'provider':'ldaps://ldap:1'}))
    shutil.copy2(PRIMARY_ROOT/'.secrets/ca.crt',failed_enrollment/'provider-ca.crt')
    for directory in [failed_enrollment,failed_directory]:
        run('docker','run','--rm','-v',str(directory)+':/scope','alpine:3.22.2','chown','-R','10001:10001','/scope')
    failed=run('docker','run','--rm','--network',PROJECT+'_web','--read-only','--cap-drop','ALL','--tmpfs','/tmp:rw,nosuid,size=16m','-v',str(failed_enrollment)+':/enrollment:ro','-v',str(failed_directory)+':/directory','--entrypoint','python3','forklift-ldap:latest','/replica.py',check=False)
    assert failed.returncode and b'The enrollment token was not used' in failed.stderr
    assert next(n for n in request('/api/directory-servers')['servers'] if n['id']==node['id'])['enrollment_state']=='pending'
    print('Building the generated standalone replica stack and waiting for native Syncrepl…',flush=True)
    run('./start.sh',cwd=replica_dir,env={**replica_env,'COMPOSE_PROJECT_NAME':replica_project,'COMPOSE_FILE':str(replica_dir/'compose.yaml')+':'+str(ROOT/'replica-override.yaml')})
    replica('up','-d','--no-build','--wait')
    assert (replica_dir/'enrollment/enrollment.json').stat().st_uid==os.getuid()
    synchronized(node['id'])
    certificate=replica_exec('cat','/directory/server.crt').stdout.decode()
    request('/api/replicas/'+node['id']+'/enroll','POST',dict(token=enrollment['token'],certificate=certificate),auth=False,expect=403)
    request('/api/replicas/'+node['id']+'/bundle','POST',dict(acknowledge=True),expect=400)
    primary_mounts=json.loads(run('docker','inspect',compose('ps','-q','ldap').stdout.decode().strip()).stdout)[0]['Mounts']
    secondary_mounts=json.loads(run('docker','inspect',replica('ps','-q','replica').stdout.decode().strip()).stdout)[0]['Mounts']
    assert {m.get('Name') for m in primary_mounts if m['Type']=='volume'}.isdisjoint({m.get('Name') for m in secondary_mounts if m['Type']=='volume'})
    # All data operations use LDAP, never copies of primary database files.
    request('/api/users','POST',user('firstlogin'))
    request('/api/users','POST',user('denied'))
    request('/api/users','POST',user('deleted'))
    request('/api/users','POST',user('offlinefresh'))
    request('/api/groups/ssh-access','PUT',dict(name='ssh-access',members=['firstlogin','offlinefresh']))
    request('/api/users/deleted','DELETE')
    host=request('/api/hosts','POST',dict(name='Failover client',hostname='ubuntu.test',endpoints=['ldaps://ldap:636','ldaps://replica:636'],allowed_groups=['ssh-access']))
    host_bundle=ROOT/'host';host_bundle.mkdir()
    unpack(request('/api/hosts/'+host['id']+'/bundle','POST',dict(revision=1,rotate=True),raw=True),host_bundle)
    synchronized(node['id'])
    assert certificate.strip() in (host_bundle/'ca.crt').read_text(),'Client bundle omitted the enrolled replica certificate'
    conf=configparser.ConfigParser(interpolation=None);conf.read(host_bundle/'sssd.conf')
    bind=conf['domain/forklift']['ldap_default_authtok'];bind_dn=conf['domain/forklift']['ldap_default_bind_dn']
    check_ldap="""import sys,os,json,subprocess
p=json.load(sys.stdin);r=subprocess.run(['ldapsearch','-x','-H','ldaps://replica:636','-D',p['dn'],'-y','/dev/stdin','-LLL','-b',p['base'],'(uid=deleted)','uid'],input=p['pw'].encode(),env={**os.environ,'LDAPTLS_CACERT':'/directory/server.crt'},capture_output=True)
assert r.returncode==0 and b'uid: deleted' not in r.stdout
"""
    replica_exec('python3','-c',check_ldap,input=json.dumps(dict(dn=bind_dn,pw=bind,base=BASE)).encode())
    # Readonly rejects even the primary write identity, not just an ordinary user's ACL.
    service=run('docker','run','--rm','-v',str(PRIMARY_ROOT/'.secrets')+':/secrets:ro','alpine:3.22.2','cat','/secrets/service').stdout.decode().strip()
    readonly="""import sys,os,json,subprocess
p=json.load(sys.stdin);rfd,wfd=os.pipe();os.write(wfd,p['pw'].encode());os.close(wfd)
ldif=('dn: uid=firstlogin,ou=people,'+p['base']+'\\nchangetype: modify\\nreplace: description\\ndescription: forbidden\\n').encode()
r=subprocess.run(['ldapmodify','-x','-H','ldaps://replica:636','-D','cn=manager,'+p['base'],'-y','/dev/fd/'+str(rfd)],input=ldif,pass_fds=(rfd,),env={**os.environ,'LDAPTLS_CACERT':'/directory/server.crt'},capture_output=True)
os.close(rfd);assert r.returncode==53
"""
    replica_exec('python3','-c',readonly,input=json.dumps(dict(pw=service,base=BASE)).encode())
    print('Testing replica interruption, catch-up and persistence across recreation…',flush=True)
    before=synchronized(node['id'])['last_sync_at']
    replica('stop','replica')
    request('/api/users','POST',user('catchup'))
    status=next(s for s in request('/api/directory-servers')['servers'] if s['id']==node['id'])
    assert not status['reachable'] and status['last_sync_at']==before
    replica('up','-d','--no-build','--force-recreate','--wait')
    synchronized(node['id'])
    # Set/reset and disabled-account state must arrive over Syncrepl.
    updated_password=secrets.token_urlsafe(32)
    request('/api/users','POST',user('firstlogin',updated_password))
    request('/api/users','POST',user('denied',PASSWORD,True))
    synchronized(node['id'])
    print('Testing a fresh Ubuntu SSH login with the primary stopped…',flush=True)
    run('docker','run','-d','--name',ubuntu,'--network',PROJECT+'_web','-v',str(Path('ansible').resolve())+':/workspace/ansible:ro','forklift-ubuntu-client')
    run('docker','cp',str(host_bundle)+'/.',ubuntu+':/bundle')
    client_command('sh','-c',"printf '[forklift_clients]\\nlocalhost ansible_connection=local\\n' > /tmp/inventory")
    client_command('ansible-playbook','-i','/tmp/inventory','/workspace/ansible/playbook.yml','-e','forklift_bundle_dir=/bundle','-e','forklift_manage_services=false')
    # No SSSD process, identity lookup or password cache exists before the primary is stopped.
    confirmed=synchronized(node['id'])['last_sync_at']
    compose('stop','ldap')
    client_command('sssd','-D');client_command('/usr/sbin/sshd','-p','2222')
    identity=client_command('getent','passwd','firstlogin').stdout
    assert b'/home/firstlogin' in identity
    ssh('firstlogin',updated_password)
    ssh('firstlogin',PASSWORD,False)
    ssh('denied',PASSWORD,False)
    assert request('/api/overview')['read_only'] is True
    status=request('/api/directory-servers')
    secondary=next(s for s in status['servers'] if s['id']==node['id'])
    assert secondary['state']=='primary_unavailable' and secondary['last_sync_at']==confirmed
    request('/api/users','POST',user('must-not-write'),expect=503)
    request('/api/hosts/'+host['id']+'/bundle','POST',dict(revision=1,rotate=True),expect=503)
    # New management login also authenticates against the verified replica, never promotes it.
    fresh=request('/api/login','POST',dict(username='admin',password=PASSWORD),auth=False)
    assert fresh['read_only'] is True
    request('/api/logout','POST',{},use_csrf=False,expect=403)
    request('/api/logout','POST',{})
    request('/api/overview',expect=401)
    login=request('/api/login','POST',dict(username='admin',password=PASSWORD))
    assert login['read_only'] is True
    csrf=login['csrf']
    # Recreating a configured replica cannot depend on redeeming its token or contacting the manager.
    print('Testing replica restart and fresh authentication with both primary and manager down…',flush=True)
    compose('stop','manager')
    replica('restart','replica');replica('up','-d','--no-build','--wait')
    client_command('sh','-c','if [ -f /run/sssd.pid ]; then kill "$(cat /run/sssd.pid)"; fi; sleep 1; sssd -D')
    ssh('offlinefresh',PASSWORD)
    # Compose start also schedules dependencies; start only this existing container to keep the primary stopped.
    manager_id=compose('ps','-a','-q','manager').stdout.decode().strip()
    primary_id=compose('ps','-a','-q','ldap').stdout.decode().strip()
    run('docker','start',manager_id)
    assert run('docker','inspect','--format','{{.State.Running}}',primary_id).stdout.strip()==b'false'
    for _ in range(30):
        try: request('/health');break
        except (URLError,ConnectionError):time.sleep(1)
    assert request('/api/overview')['read_only'] is True
    compose('start','ldap');wait_ready();synchronized(node['id'])
    assert request('/api/overview')['read_only'] is False
    # Reject a new certificate with the same DNS name but a different un-enrolled key.
    print('Testing pinned-certificate rejection and recovery…',flush=True)
    replica_exec('sh','-c','cp /directory/server.crt /directory/server.crt.good; cp /directory/server.key /directory/server.key.good; openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=replica -addext basicConstraints=critical,CA:FALSE -addext subjectAltName=DNS:replica -keyout /directory/server.key -out /directory/server.crt')
    replica('restart','replica')
    status=next(s for s in request('/api/directory-servers')['servers'] if s['id']==node['id'])
    assert not status['reachable'] and status['state']=='unreachable'
    replica_exec('sh','-c','cp /directory/server.crt.good /directory/server.crt; cp /directory/server.key.good /directory/server.key')
    replica('restart','replica');recovered=synchronized(node['id'])
    assert recovered['error'] is None, 'Recovered node retained an obsolete connection error'
    print('Testing staged replica certificate rotation and dual client trust…',flush=True)
    candidate=replica_exec('python3','/replica.py','stage-certificate').stdout.decode()
    assert candidate.startswith('-----BEGIN CERTIFICATE-----') and candidate != certificate
    request('/api/replicas/'+node['id']+'/certificate','POST',dict(certificate=candidate,acknowledge=True),use_csrf=False,expect=403)
    request('/api/replicas/'+node['id']+'/certificate','POST',dict(certificate=candidate,acknowledge=False),expect=400)
    request('/api/replicas/'+node['id']+'/certificate','POST',dict(certificate=candidate,acknowledge=True))
    request('/api/replicas/'+node['id']+'/certificate/finalize','POST',dict(acknowledge=True),expect=409)
    def redeploy_host():
        current=next(h for h in request('/api/hosts') if h['id']==host['id'])
        unpack(request('/api/hosts/'+host['id']+'/bundle','POST',dict(revision=current['revision'],rotate=True),raw=True),host_bundle)
        run('docker','cp',str(host_bundle)+'/.',ubuntu+':/bundle')
        client_command('ansible-playbook','-i','/tmp/inventory','/workspace/ansible/playbook.yml','-e','forklift_bundle_dir=/bundle','-e','forklift_manage_services=false')
        return current
    staged=redeploy_host()
    assert staged['revision']==2
    trust=(host_bundle/'ca.crt').read_text();assert certificate.strip() in trust and candidate.strip() in trust
    replica_exec('python3','/replica.py','activate-certificate')
    replica('restart','replica');synchronized(node['id'])
    request('/api/replicas/'+node['id']+'/certificate/finalize','POST',dict(acknowledge=True))
    final=redeploy_host();assert final['revision']==3
    trust=(host_bundle/'ca.crt').read_text();assert candidate.strip() in trust and certificate.strip() not in trust
    replica_exec('python3','/replica.py','retire-certificate')
    assert replica_exec('test','!','-e','/directory/server.key.previous',check=False).returncode==0
    print('Testing replication credential epochs and actual new provider binds…',flush=True)
    old_replication=json.loads(replica_exec('cat','/directory/replica.json').stdout)
    request('/api/replicas/'+node['id']+'/credential','POST',dict(acknowledge=True),use_csrf=False,expect=403)
    update_archive=request('/api/replicas/'+node['id']+'/credential','POST',dict(acknowledge=True),raw=True)
    with tarfile.open(fileobj=io.BytesIO(update_archive),mode='r:gz') as archive:
        update=archive.extractfile('credential-update.json').read()
    updated=json.loads(update);assert updated['credential_epoch']>old_replication.get('credential_epoch',0)
    def primary_bind(dn,password,expected):
        code="import os,sys,json,subprocess;p=json.load(sys.stdin);r=subprocess.run(['ldapwhoami','-x','-H','ldaps://ldap:636','-D',p['dn'],'-y','/dev/stdin'],input=p['pw'].encode(),env={**os.environ,'LDAPTLS_CACERT':'/run/secrets/ca.crt'},capture_output=True);assert r.returncode==p['expected']"
        cid=compose('ps','-q','ldap').stdout.decode().strip()
        run('docker','exec','-i',cid,'python3','-c',code,input=json.dumps(dict(dn=dn,pw=password,expected=expected)).encode())
    primary_bind('cn=replica-'+node['id']+','+BASE,old_replication['credential'],49)
    primary_bind('cn=replica-'+node['id']+','+BASE,updated['credential'],0)
    wrong=dict(updated,id='0'*32)
    assert replica_exec('python3','/replica.py','apply-credential',input=json.dumps(wrong).encode(),check=False).returncode
    replica_exec('python3','/replica.py','apply-credential',input=update)
    assert replica_exec('python3','/replica.py','apply-credential',input=update,check=False).returncode
    replica('restart','replica')
    request('/api/users','POST',user('afterrotation'));synchronized(node['id'])
    print('Testing primary service/monitor credential rotation with an active replica…',flush=True)
    run('python3',str(SOURCE/'scripts/forklift-admin.py'),'--root',str(PRIMARY_ROOT),'--project',PROJECT,'--file',str(PRIMARY_ROOT/'compose.yaml'),'--file',str(override),'rotate-service')
    primary_bind('cn=manager,'+BASE,service,49)
    request('/api/me',expect=401)
    csrf=request('/api/login','POST',dict(username='admin',password=PASSWORD))['csrf']
    synchronized(node['id'])
    request('/api/users','POST',user('afterservice'));synchronized(node['id'])
    compose('stop','ldap')
    client_command('sh','-c','if [ -f /run/sssd.pid ]; then kill "$(cat /run/sssd.pid)"; fi; sleep 1; sssd -D')
    ssh('firstlogin',updated_password)
    compose('start','ldap');wait_ready();synchronized(node['id'])
    # A removed identity cannot make a new provider bind; stop the replica before decommission.
    replica('stop','replica');request('/api/replicas/'+node['id'],'DELETE')
    assert len(request('/api/directory-servers')['servers'])==1
    print(f'PASS: {checks} HTTPS API checks, one-use/expired enrollment, native Syncrepl changes/deletes/passwords, independent storage, readonly enforcement, interrupted recovery, real fresh Ubuntu SSH failover, replica-backed read-only administration, certificate-pin rejection, staged certificate renewal, dual/final client trust, replication credential epochs and primary service/monitor rotation.',flush=True)
except Exception:
    if (replica_dir/'compose.yaml').exists() and (ROOT/'replica-override.yaml').exists():
        diagnostic=replica('logs','--tail','50','replica',check=False).stdout.decode(errors='replace')
        diagnostic=re.sub(r'[a-f0-9]{64}','[redacted]',diagnostic).replace(PASSWORD,'[redacted]')
        print(diagnostic,flush=True)
    raise
finally:
    run('docker','rm','-f',ubuntu,check=False)
    if (replica_dir/'compose.yaml').exists() and (ROOT/'replica-override.yaml').exists():replica('down','--volumes','--rmi','local',check=False)
    run('docker','rm','-f',PROJECT+'-proxy',check=False)
    compose('down','--volumes','--remove-orphans')
    run('docker','run','--rm','-v',str(ROOT)+':/fixture','alpine:3.22.2','chown','-R',str(os.getuid())+':'+str(os.getgid()),'/fixture',check=False)
    workspace.cleanup()
