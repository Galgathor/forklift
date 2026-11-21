#!/usr/bin/env python3
"""Real encrypted snapshots, hostile/corrupt inputs, fresh restoration and secret lifecycle."""
import http.cookiejar
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from urllib.error import HTTPError,URLError

SOURCE=Path(__file__).resolve().parents[1]
os.chdir(SOURCE)
PROJECT='forklift-hardening-test-'+secrets.token_hex(4)
workspace=tempfile.TemporaryDirectory(prefix=PROJECT+'-')
ROOT=Path(workspace.name)
PASSWORD=secrets.token_urlsafe(32)
BASE='dc=recovery,dc=test'
checks=0

def run(args,*,cwd=None,data=None,env=None,check=True):
    result=subprocess.run(args,cwd=cwd,input=data,env=env,capture_output=True)
    if check and result.returncode:
        # Operator command errors are deliberately sanitized; never print plaintext or native LDAP output.
        raise RuntimeError('Command failed: '+args[0]+' '+(args[1] if len(args)>1 else '')+' '+result.stderr.decode(errors='replace')[-700:])
    return result

def freeport():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]

def prepare(folder,port,install):
    folder.mkdir()
    shutil.copy2(SOURCE/'compose.yaml',folder/'compose.yaml')
    shutil.copy2(SOURCE/'.env.example',folder/'.env.example')
    (folder/'override.json').write_text(json.dumps({'services':{'manager':{'image':'forklift-manager:latest'},'ldap':{'image':'forklift-ldap:latest'}}}))
    if install:
        (folder/'scripts').mkdir();shutil.copy2(SOURCE/'scripts/install.sh',folder/'scripts/install.sh')
        run(['sh','scripts/install.sh'],cwd=folder)
        (folder/'.env').write_text(f'FORKLIFT_PUBLIC_URL=http://localhost:{port}\nFORKLIFT_PORT={port}\nFORKLIFT_BIND=127.0.0.1\n')

class Stack:
    def __init__(self,name,folder,port):
        self.name=name;self.folder=folder;self.port=port;self.url='http://localhost:'+str(port)
        self.command=['docker','compose','--project-directory',str(folder),'-p',name,'-f',str(folder/'compose.yaml'),'-f',str(folder/'override.json')]
        self.jar=http.cookiejar.CookieJar();self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar));self.csrf=''
    def compose(self,*args,check=True):return run(self.command+list(args),check=check)
    def request(self,path,method='GET',body=None,expect=200,csrf=True,cookie=None,raw=False):
        global checks
        headers={'Content-Type':'application/json','Origin':self.url}
        if csrf:headers['X-CSRF-Token']=self.csrf
        if cookie:headers['Cookie']=cookie
        req=urllib.request.Request(self.url+path,data=json.dumps(body).encode() if body is not None else None,headers=headers,method=method)
        try:r=self.client.open(req,timeout=20)
        except HTTPError as exc:r=exc
        with r:status=r.code;data=r.read()
        assert status==expect,f'{method} {path}: expected {expect}, got {status}'
        checks+=1;return data if raw else json.loads(data)
    def ready(self):
        for _ in range(90):
            try:self.request('/ready');return
            except (URLError,ConnectionError,AssertionError):time.sleep(1)
        raise AssertionError('Stack did not become ready')
    def login(self):self.csrf=self.request('/api/login','POST',dict(username='admin',password=PASSWORD))['csrf']
    def cli(self,*args,check=True):
        return run(['python3',str(SOURCE/'scripts/forklift-admin.py'),'--root',str(self.folder),'--project',self.name,'--file',str(self.folder/'compose.yaml'),'--file',str(self.folder/'override.json'),*args],check=check)
    def secret(self,name):
        return run(['docker','run','--rm','-v',str(self.folder/'.secrets')+':/secrets:ro','alpine:3.22.2','cat','/secrets/'+name]).stdout.decode().strip()
    def bind(self,dn,password,expected=0):
        cid=self.compose('ps','-q','ldap').stdout.decode().strip()
        code="import os,sys,json,subprocess; p=json.load(sys.stdin);r=subprocess.run(['ldapwhoami','-x','-H','ldaps://ldap:636','-D',p['dn'],'-y','/dev/stdin'],input=p['pw'].encode(),env={**os.environ,'LDAPTLS_CACERT':'/run/secrets/ca.crt'},capture_output=True);sys.exit(r.returncode)"
        r=run(['docker','exec','-i',cid,'python3','-c',code],data=json.dumps(dict(dn=dn,pw=password)).encode(),check=False)
        assert r.returncode==expected,'Unexpected actual LDAP bind result'

def user(name):return dict(username=name,display_name=name.title(),email='',description='Recovery test',shell='/bin/bash',home='/home/'+name,gid=10000,password=PASSWORD,disabled=False)

source=Stack(PROJECT,ROOT/'source',freeport())
target=Stack(PROJECT+'-restored',ROOT/'target',freeport())
prepare(source.folder,source.port,True);prepare(target.folder,target.port,False)
try:
    source.compose('up','-d','--no-build','--wait');source.ready()
    source.request('/api/setup','POST',dict(token=source.secret('bootstrap'),name='Hardening',base=BASE,username='admin',password=PASSWORD))
    source.login()
    original_cookie='; '.join(c.name+'='+c.value for c in source.jar)
    source.request('/api/users','POST',user('backupuser'))
    source.request('/api/groups/ssh-access','PUT',dict(name='ssh-access',members=['backupuser']))
    host=source.request('/api/hosts','POST',dict(name='Stored host',hostname='stored.example.test',endpoints=['ldaps://ldap:636'],allowed_groups=['ssh-access']))
    source.request('/api/hosts/'+host['id']+'/bundle','POST',dict(revision=1,rotate=True),raw=True)
    snapshot=source.request('/api/overview')
    uid=next(u for u in snapshot['users'] if u['attrs']['uid']==['backupuser'])['attrs']['uidNumber'][0]
    print('Testing operational authorization, literal audit search, cursors and NDJSON export…',flush=True)
    source.request('/api/operations',expect=200)
    first=source.request('/api/audit?limit=2');assert len(first['events'])==2 and first['next_cursor']
    second=source.request('/api/audit?limit=2&before='+str(first['next_cursor']));assert {e['id'] for e in first['events']}.isdisjoint(e['id'] for e in second['events'])
    source.request('/api/audit?limit=10000',expect=400)
    assert not source.request('/api/audit?q=%27%20OR%201%3D1--')['events']
    exported=source.request('/api/audit/export?limit=3',raw=True).decode().splitlines();assert len(exported)==3 and all('action' in json.loads(line) for line in exported)
    # Metadata-only pending enrollment fixture, never represented as a synchronized node.
    retired_id=secrets.token_hex(16);retired_token=secrets.token_hex(32)
    seed="import sqlite3,json,sys;c=sqlite3.connect('/metadata/forklift.db');p=json.load(sys.stdin);c.execute(\"INSERT INTO directory_servers(id,name,endpoint,provider,state,enrollment_hash,enrollment_expires) VALUES(?,?,?,?,'pending',?,?)\",(p['id'],'Pending recovery fixture','ldaps://pending.test:636','ldaps://ldap:636',p['digest'],int(__import__('time').time())+900));c.commit()"
    run(['docker','run','--rm','-i','--network','none','-v',source.name+'_metadata:/metadata','--entrypoint','python3','forklift-ldap','-c',seed],data=json.dumps(dict(id=retired_id,digest=hashlib.sha256(retired_token.encode()).hexdigest())).encode())
    if os.environ.get('FORKLIFT_TEST_BROWSER_DEPS'):
        deps=Path(os.environ['FORKLIFT_TEST_BROWSER_DEPS']).resolve()
        output=Path(os.environ.get('FORKLIFT_TEST_BROWSER_OUTPUT','/tmp/forklift-browser-output')).resolve();output.mkdir(parents=True,exist_ok=True)
        result=run(['docker','run','--rm','-i','--network','host','--user',str(os.getuid())+':'+str(os.getgid()),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--tmpfs','/tmp:rw,nosuid,size=256m','--shm-size','256m','-e','NODE_PATH=/deps','-v',str(deps)+':/deps:ro','-v',str(SOURCE/'tests/browser.cjs')+':/test.cjs:ro','-v',str(output)+':/output','mcr.microsoft.com/playwright:v1.65.0-noble@sha256:6e3fb709361521eb27161606e6da6d2674e5e89fa16516cb37d6fdd91372273d','node','/test.cjs'],data=json.dumps(dict(url=source.url,password=PASSWORD)).encode())
        print(result.stdout.decode().strip(),flush=True)
    print('Testing encrypted coherent snapshots and authenticated verification…',flush=True)
    key=ROOT/'keys/identity.txt';key2=ROOT/'keys/wrong.txt'
    public=json.loads(source.cli('keygen','--output',str(key)).stdout)['recipient']
    source.cli('keygen','--output',str(key2))
    backup=ROOT/'backups/snapshot.tar.gz.age'
    result=json.loads(source.cli('backup','--recipient',public,'--output',str(backup)).stdout)
    assert result['sha256']==hashlib.sha256(backup.read_bytes()).hexdigest()
    assert backup.stat().st_mode & 0o777 == 0o600
    assert PASSWORD.encode() not in backup.read_bytes()
    verified=json.loads(source.cli('verify','--archive',str(backup),'--identity',str(key),'--sha256',result['sha256']).stdout)
    assert verified['validated'] and verified['base']==BASE
    assert source.cli('verify','--archive',str(backup),'--identity',str(key2),'--sha256',result['sha256'],check=False).returncode
    assert source.cli('verify','--archive',str(backup),'--identity',str(key),'--sha256','0'*64,check=False).returncode
    corrupt=ROOT/'backups/corrupt.age';data=bytearray(backup.read_bytes());data[-20]^=1;corrupt.write_bytes(data)
    assert source.cli('verify','--archive',str(corrupt),'--identity',str(key),'--sha256',hashlib.sha256(data).hexdigest(),check=False).returncode
    print('Testing hostile archive member rejection before publication…',flush=True)
    # Build only hostile archive metadata in memory; encryption is real age, not a parser mock.
    for variant in ['traversal','symlink','duplicate']:
        archive=io.BytesIO()
        name='../escape' if variant=='traversal' else 'directory/complete'
        contents=b'dc=test,dc=invalid'
        manifest=dict(format=1,architecture=os.uname().machine,metadata_schema=4,files=[dict(path=name,size=len(contents),sha256=hashlib.sha256(contents).hexdigest())])
        with tarfile.open(fileobj=archive,mode='w:gz') as tar:
            encoded=json.dumps(manifest).encode();info=tarfile.TarInfo('manifest.json');info.size=len(encoded);tar.addfile(info,io.BytesIO(encoded))
            info=tarfile.TarInfo(name);info.size=len(contents)
            if variant=='symlink':info.type=tarfile.SYMTYPE;info.linkname='/etc/passwd';info.size=0;tar.addfile(info)
            else:
                tar.addfile(info,io.BytesIO(contents))
                if variant=='duplicate':tar.addfile(info,io.BytesIO(contents))
        encrypted=run(['docker','run','--rm','-i','--network','none','--read-only','--cap-drop','ALL','--entrypoint','age','forklift-maintenance','-r',public],data=archive.getvalue()).stdout
        hostile=ROOT/'backups'/('hostile-'+variant+'.age');hostile.write_bytes(encrypted)
        failed=source.cli('verify','--archive',str(hostile),'--identity',str(key),'--sha256',hashlib.sha256(encrypted).hexdigest(),check=False)
        assert failed.returncode and (b'archive' in failed.stderr.lower()),variant+' was not refused by archive validation'
    assert any(e['kind']=='backup' and e['status']=='completed' and e['sha256']==result['sha256'] for e in source.request('/api/operations')['maintenance'])
    print('Testing native offline service-secret rotation and session invalidation…',flush=True)
    old=source.secret('service')
    source.cli('rotate-service')
    new=source.secret('service');assert old!=new
    source.bind('cn=manager,'+BASE,old,49);source.bind('cn=manager,'+BASE,new)
    source.bind('uid=backupuser,ou=people,'+BASE,PASSWORD)
    source.request('/api/me',expect=401);source.login()
    assert not (source.folder/'.forklift-maintenance.json').exists()
    assert run(['docker','run','--rm','-v',str(source.folder/'.secrets')+':/secrets:ro','alpine:3.22.2','test','!','-e','/secrets/service-rotation.json'],check=False).returncode==0
    print('Testing interrupted native credential rotation and fail-closed startup…',flush=True)
    # Simulate power loss after native LDAP modification but before the secret-file update.
    # All mounts and credentials belong to this fresh fixture; the checkout secrets are untouched.
    import importlib.util
    from argparse import Namespace
    spec=importlib.util.spec_from_file_location('forklift_operator',SOURCE/'scripts/forklift-admin.py')
    operator=importlib.util.module_from_spec(spec);spec.loader.exec_module(operator)
    installation=operator.Installation(Namespace(root=str(source.folder),project=source.name,file=[str(source.folder/'compose.yaml'),str(source.folder/'override.json')]))
    with operator.locked(installation):
        state=installation.save_state('rotate-service',installation.containers())
        installation.stop(state)
        mounts=installation.source_mounts(state['volumes'],False)
        operator.toolbox('rotate-service',state,mounts)
        fault="""import sys,json,pathlib,os
p=json.load(sys.stdin);j=pathlib.Path('/secrets/service-rotation.json');s=json.loads(j.read_text());s['completed']=False;j.write_text(json.dumps(s));os.chmod(j,0o600)
f=pathlib.Path('/secrets/service');f.write_text(p['old']+'\\n')
for root in ['/directory','/metadata']:pathlib.Path(root+'/service-rotation-incomplete').write_text(s['operation_id'])
"""
        argv=['docker','run','--rm','-i','--network','none','--read-only','--entrypoint','python3']
        for volume,dest,readonly in mounts:argv+=['-v',str(volume)+':'+dest+(':ro' if readonly else '')]
        run(argv+['forklift-maintenance','-c',fault],data=json.dumps(dict(old=new)).encode())
        run(['docker','start',state['containers']['ldap']['id']])
        for _ in range(20):
            actual=json.loads(run(['docker','inspect',state['containers']['ldap']['id']]).stdout)[0]['State']
            diagnostic=run(['docker','logs',state['containers']['ldap']['id']],check=False)
            if b'Offline maintenance is incomplete' in diagnostic.stderr:break
            time.sleep(0.2)
        assert b'Offline maintenance is incomplete' in diagnostic.stderr,'Incomplete rotation did not refuse startup'
        assert actual.get('Health',{}).get('Status') != 'healthy'
    sentinel=PROJECT+'-active-helper'
    run(['docker','run','-d','--name',sentinel,'--label','io.forklift.operation-id='+state['operation_id'],'--network','none','--cap-drop','ALL','alpine:3.22.2','sleep','30'])
    try:
        blocked=source.cli('resume',check=False)
        assert blocked.returncode and b'helper from this operation is still active' in blocked.stderr
    finally:
        run(['docker','rm','-f',sentinel],check=False)
    source.cli('resume')
    latest=source.secret('service');assert latest!=new
    source.bind('cn=manager,'+BASE,new,49);source.bind('cn=manager,'+BASE,latest)
    source.login()
    # A later allocated/deleted identity must not be automatically reused after rollback.
    source.request('/api/users','POST',user('afterbackup'));source.request('/api/users/afterbackup','DELETE')
    print('Testing explicit restore safeguards and old-session rejection…',flush=True)
    args=['restore','--archive',str(backup),'--identity',str(key),'--sha256',result['sha256'],'--uid-floor','1000000','--original-fenced']
    assert source.cli(*args,check=False).returncode # refuse current populated installation
    source.compose('stop') # fence the original before any restored primary is started
    assert target.cli(*[v for v in args if v!='--original-fenced'],check=False).returncode
    low=args.copy();low[low.index('--uid-floor')+1]='1'
    assert target.cli(*low,check=False).returncode
    restored=json.loads(target.cli(*args).stdout);assert restored['restored'] and restored['recovery_required']
    (target.folder/'.env').write_text(f'FORKLIFT_PUBLIC_URL={target.url}\nFORKLIFT_PORT={target.port}\nFORKLIFT_BIND=127.0.0.1\n')
    target.compose('up','-d','--no-build','--wait');target.ready()
    target.request('/api/me',cookie=original_cookie,expect=401)
    target.login();target.bind('uid=backupuser,ou=people,'+BASE,PASSWORD)
    recovered=target.request('/api/overview')
    assert recovered['read_only'] and recovered['read_only_reason']=='recovery_review'
    restored_user=next(u for u in recovered['users'] if u['attrs']['uid']==['backupuser']);assert restored_user['attrs']['uidNumber']==[uid]
    assert len(recovered['hosts'])==1 and recovered['hosts'][0]['revision']>snapshot['hosts'][0]['revision']
    quarantined=next(n for n in target.request('/api/directory-servers')['servers'] if n['id']==retired_id)
    assert quarantined['enrollment_state']=='restore_required' and not quarantined['reachable']
    cleared="import sqlite3,sys;c=sqlite3.connect('/metadata/forklift.db');assert c.execute('SELECT enrollment_hash,enrollment_expires FROM directory_servers WHERE id=?',(sys.argv[1],)).fetchone()==(None,0)"
    run(['docker','run','--rm','--network','none','-v',target.name+'_metadata:/metadata:ro','--entrypoint','python3','forklift-ldap','-c',cleared,retired_id])
    target.request('/api/users','POST',user('blocked'),expect=503)
    target.request('/api/recovery/complete','POST',dict(acknowledge=True),csrf=False,expect=403)
    target.request('/api/recovery/complete','POST',dict(acknowledge=False),expect=400)
    target.request('/api/recovery/complete','POST',dict(acknowledge=True))
    target.request('/api/users','POST',user('newrange'))
    assert next(u for u in target.request('/api/overview')['users'] if u['attrs']['uid']==['newrange'])['attrs']['uidNumber']==['1000000']
    target.request('/api/sessions/revoke','POST',dict(acknowledge=True),csrf=False,expect=403)
    target.request('/api/sessions/revoke','POST',dict(acknowledge=True));target.request('/api/me',expect=401)
    print(f'PASS: {checks} HTTP checks, age encryption/decryption, wrong-key/corruption rejection, trusted checksums, native LDAP restoration, UID/session preservation boundaries, future ID floor, recovery write guard, audit export and actual service rotation.',flush=True)
finally:
    for stack in [target,source]:stack.compose('down','--volumes','--remove-orphans',check=False)
    run(['docker','run','--rm','-v',str(ROOT)+':/fixture','alpine:3.22.2','chown','-R',str(os.getuid())+':'+str(os.getgid()),'/fixture'],check=False)
    workspace.cleanup()
