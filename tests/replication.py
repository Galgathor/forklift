#!/usr/bin/env python3
"""Real HTTPS enrollment and WebUI-only replica lifecycle against Syncrepl."""
import base64,json,os,shutil,time
from fixture import Stack,SOURCE,port,run
with Stack(https=True) as s:
    s.setup();r=s.request
    primary=r('/api/overview')['hosts'][0];assert primary['directory_role']=='primary' and not primary['allowed_groups']
    r('/api/hosts/'+primary['id'],'DELETE',expect=400)
    r('/api/hosts/'+primary['id']+'/bundle','POST',dict(revision=primary['revision'],rotate=True),expect=400)
    draft=dict(name='Replica',address=s.net['address'],hostname=s.net['address'],port=port(),control_port=port())
    r('/api/directory-servers','POST',draft,authenticated=False,expect=401)
    r('/api/directory-servers','POST',draft,use_csrf=False,expect=403)
    node=r('/api/directory-servers','POST',draft);nodeid=node['id']
    assert len(r('/api/hosts'))==2
    endpoint='/api/replicas/'+nodeid+'/deployment'
    r(endpoint,'POST',dict(acknowledge=True),authenticated=False,expect=401)
    r(endpoint,'POST',dict(acknowledge=True),use_csrf=False,expect=403)
    r(endpoint,'POST',dict(acknowledge=False),expect=400)
    r(endpoint,'POST',dict(acknowledge=True,manager_ca='-----BEGIN PRIVATE KEY-----'),expect=400)
    old=r(endpoint,'POST',dict(acknowledge=True))
    joined=r(endpoint,'POST',dict(acknowledge=True,manager_ca=(s.root/'ca.crt').read_text()))
    decode=lambda v:json.loads(base64.b64decode(v.partition('=')[2],validate=True))
    envelope=decode(joined['join_config']);enrollment=envelope['enrollment']
    assert enrollment['provider']=='ldaps://'+s.net['hostname']+':'+str(s.net['port'])
    assert enrollment['token']!=decode(old['join_config'])['enrollment']['token']
    assert joined['expires_at']<=int(time.time())+900 and 'PRIVATE KEY' not in json.dumps(envelope)
    repo=s.root/'replica-repository'
    for file in ['docker/replica/Dockerfile','backend/assets/replica.py','.dockerignore']:
        target=repo/file;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(SOURCE/file,target)
    folder = repo/'tests'/'fixtures'
    folder.mkdir(parents=True)
    shutil.copyfile(SOURCE/'tests/fixtures/ldap-replica.compose.yaml', folder/'compose.yaml')
    def configure(value):
        (folder/'.env').write_text(value+'\n');os.chmod(folder/'.env',0o600)
    def encoded(value):return 'FORKLIFT_REPLICA_JOIN='+base64.b64encode(json.dumps(value).encode()).decode()
    configure(joined['join_config'])
    project=s.project+'-replica'
    def compose(*args,check=True):return run(['docker','compose','-p',project,'-f',str(folder/'compose.yaml'),*args],cwd=folder,check=check)
    def synced():
        for _ in range(90):
            node=next(v for v in r('/api/directory-servers')['servers'] if v['id']==nodeid)
            if node['state']=='synchronized':assert node['context_csn'] and node['last_sync_at'];return node
            time.sleep(.5)
        raise AssertionError('Replica did not synchronize: '+str(node))
    try:
        compose('build')
        expired=json.loads(json.dumps(envelope));expired['enrollment']['expires_at']=int(time.time())-1;configure(encoded(expired))
        failure=compose('run','--rm','-T','replica',check=False);assert failure.returncode and b'invalid or expired' in failure.stderr
        invalid_trust=json.loads(json.dumps(envelope));invalid_trust['manager_ca']=envelope['provider_ca'];configure(encoded(invalid_trust))
        failure=compose('run','--rm','-T','replica',check=False);assert failure.returncode and b'Enrollment failed' in failure.stderr
        assert enrollment['token'].encode() not in failure.stderr
        certificate=run(['docker','run','--rm','--network','none','-v',project+'_replica_data:/data:ro','--entrypoint','cat','forklift-ldap:latest','/data/server.crt']).stdout.decode()
        r('/api/replicas/'+nodeid+'/enroll','POST',dict(token=decode(old['join_config'])['enrollment']['token'],certificate=certificate),authenticated=False,expect=403)
        # Server-side expiry remains authoritative even if a copied envelope claims otherwise.
        s.compose('exec','-T','maintenance','python3','-c',"import sqlite3,sys;c=sqlite3.connect('/metadata/forklift.db');c.execute('UPDATE directory_servers SET enrollment_expires=0 WHERE id=?',[sys.argv[1]]);c.commit()",nodeid)
        r('/api/replicas/'+nodeid+'/enroll','POST',dict(token=enrollment['token'],certificate=certificate),authenticated=False,expect=403)
        joined=r(endpoint,'POST',dict(acknowledge=True,manager_ca=(s.root/'ca.crt').read_text()))
        envelope=decode(joined['join_config']);enrollment=envelope['enrollment']
        secret_check="import sys;from pathlib import Path;secret=sys.stdin.buffer.read();assert all(secret not in p.read_bytes() for p in Path('/metadata').glob('forklift.db*'))"
        s.compose('exec','-T','maintenance','python3','-c',secret_check,input=enrollment['token'].encode())
        configure(joined['join_config']);compose('up','-d','--wait');synced()
        r(endpoint,'POST',dict(acknowledge=True),expect=400)
        r('/api/replicas/'+nodeid+'/enroll','POST',dict(token=enrollment['token'],certificate=certificate),authenticated=False,expect=403)
        r('/api/replicas/'+nodeid+'/bundle','POST',dict(acknowledge=True),expect=400)
        r('/api/users','POST',s.user('replicated'));synced()
        print('PASS: automatic inventory, copyable one-use enrollment, expiry/replacement/replay rejection, private HTTPS CA validation and native Syncrepl without archives.',flush=True)
        path='/api/replicas/'+nodeid
        r(path+'/credential','POST',dict(acknowledge=True));assert synced()['credential_epoch']==2
        r(path+'/restart','POST',dict(acknowledge=True));synced()
        r(path+'/certificate','POST',dict(acknowledge=True));assert synced()['certificate_rotation_pending']
        for _ in range(5):
            result=r(path+'/certificate/finalize','POST',dict(acknowledge=True),expect=(200,400,503))
            if result.get('finalized'):break
            time.sleep(.5)
        else:raise AssertionError('Remote certificate activation failed')
        assert not synced()['certificate_rotation_pending']
        s.net['port']=port();s.job(dict(action='configure-primary',network=s.net,acknowledge=True))
        r(path+'/reconnect','POST',dict(acknowledge=True));assert not synced()['provider_needs_update']
        print('PASS: WebUI remote credential rotation, native restart, certificate generation/activation/retirement and primary address reconnection.',flush=True)
        # Configured replica can restart and authenticate while primary and manager are gone.
        s.compose('stop','manager','ldap');configure('FORKLIFT_REPLICA_JOIN=');compose('up','-d','--force-recreate')
        for _ in range(45):
            state=compose('ps','--format','json').stdout.decode()
            if 'healthy' in state:break
            time.sleep(.5)
        code="import subprocess,sys,os; r=subprocess.run(['ldapwhoami','-x','-H',sys.argv[1],'-D','uid=replicated,ou=people,dc=integration,dc=test','-y','/dev/stdin'],input=sys.stdin.buffer.read(),capture_output=True,env={**os.environ,'LDAPTLS_CACERT':'/directory/server.crt'});sys.exit(r.returncode)"
        container=compose('ps','-q','replica').stdout.decode().strip()
        run(['docker','exec','-i',container,'python3','-c',code,'ldaps://'+draft['hostname']+':'+str(draft['port'])],data=s.password.encode())
        s.compose('start','ldap','manager');s.wait();synced()
        r(path,'DELETE');assert len(r('/api/hosts'))==1
        print('PASS: secondary restart/authentication with primary and manager unavailable; removing directory also removes its unconfigured inventory.',flush=True)
    finally:compose('down','--volumes','--remove-orphans',check=False)
