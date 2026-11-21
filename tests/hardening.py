#!/usr/bin/env python3
"""Real WebUI backup, restore, rotation and interrupted-operation recovery."""
import hashlib,json,time
from fixture import Stack

with Stack() as source:
    source.setup();source.request('/api/users','POST',source.user('retained'))
    identity,headers=source.request('/api/maintenance/keys','POST',raw=True);recipient=headers['X-Age-Recipient']
    saved=source.job(dict(action='backup',recipient=recipient));archive,_=source.request('/api/maintenance/backups/'+saved['id'],raw=True)
    checksum=saved['result']['sha256'];assert hashlib.sha256(archive).hexdigest()==checksum
    uploaded=source.upload(archive)
    verify=dict(action='verify',upload_id=uploaded['id'],sha256=checksum,identity=identity.decode())
    assert source.job(verify)['result']['validated']
    assert source.job(verify|dict(sha256='0'*64),success=False)['status']=='failed'
    wrong_key,_=source.request('/api/maintenance/keys','POST',raw=True)
    assert source.job(verify|dict(identity=wrong_key.decode()),success=False)['status']=='failed'
    source.request('/api/maintenance/jobs','POST',dict(action='backup',recipient=recipient),authenticated=False,expect=401)
    source.request('/api/maintenance/jobs','POST',dict(action='backup',recipient=recipient),use_csrf=False,expect=403)
    # Public-recipient encryption alone must not permit a crafted traversal archive.
    import io,platform,tarfile
    manifest=dict(format=2,architecture=platform.machine(),metadata_schema=5,files=[dict(path='../../escaped',size=1,sha256='0'*64)])
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
        data=json.dumps(manifest).encode();entry=tarfile.TarInfo('manifest.json');entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
    malformed=source.compose('exec','-T','maintenance','age','-r',recipient,input=buffer.getvalue()).stdout
    staged=source.upload(malformed)
    assert source.job(dict(action='verify',upload_id=staged['id'],sha256=staged['sha256'],identity=identity.decode()),success=False)['status']=='failed'

    source.request('/api/me')
    source.job(dict(action='rotate-service',acknowledge=True));source.request('/api/me',expect=401);source.login()
    source.job(dict(action='renew-primary',acknowledge=True));source.bind('retained')
    print('PASS: encrypted backup, streaming transfer, native verification/checksum rejection, service rotation, session revocation and certificate renewal.',flush=True)
    # Real cold restore through the bootstrap WebUI, with no dummy LDAP directory.
    with Stack() as target:
        net=target.network();headers={'X-Bootstrap-Token':target.bootstrap}
        uploaded=target.upload(archive,headers)
        restored=target.job(dict(action='restore',upload_id=uploaded['id'],sha256=checksum,identity=identity.decode(),uid_floor=900000,original_fenced=True,acknowledge=True,network=net),headers=headers)
        assert restored['result']['restored'];target.password=source.password;target.net=net;target.login();target.bind('retained')
        users=target.request('/api/overview')['users'];assert len(users)==2
        assert target.request('/api/operations')['recovery_required']
        target.request('/api/users','POST',target.user('future'),expect=503)
        target.request('/api/recovery/complete','POST',dict(acknowledge=True))
        target.request('/api/users','POST',target.user('future'))
        future=next(u for u in target.request('/api/overview')['users'] if u['attrs']['uid']==['future'])
        assert int(future['attrs']['uidNumber'][0])>=900000
        target.compose('up','-d','--no-build','--force-recreate','--wait');target.wait();target.bind('retained');target.request('/api/me')
        print('PASS: first-launch WebUI restore, original passwords/numeric IDs, future ID floor, session replacement and durable recreation.',flush=True)
    # Stop native slapd while pause is in flight, then restart the worker and manager.
    from fixture import run
    worker=source.compose('ps','-q','maintenance').stdout.decode().strip()
    run(['docker','kill','--signal','STOP',worker])
    source.request('/api/maintenance/jobs','POST',dict(action='backup',recipient=recipient))
    time.sleep(.5) # live LDAP authorization is complete; worker has not yet paused LDAP
    source.request('/api/overview',expect=503)
    source.compose('exec','-T','ldap','python3','-c',"import os,signal;from pathlib import Path;p=next(p for p in Path('/proc').iterdir() if p.name.isdigit() and (p/'comm').read_text().strip()=='slapd');os.kill(int(p.name),signal.SIGSTOP)")
    run(['docker','kill','--signal','CONT',worker])
    for _ in range(100):
        state=source.compose('exec','-T','maintenance','python3','-c',"from pathlib import Path;print((Path('/run/ldap-control')/'offline.json').exists())").stdout
        if state.strip()==b'True':break
        time.sleep(.1)
    else:raise AssertionError('Offline fence missing')
    source.compose('restart','maintenance','manager');source.wait('/health')
    state=source.poll(success=False);assert state['status']=='needs_resume'
    source.request('/api/overview',expect=503)
    source.request('/ready',expect=503)
    source.request('/api/maintenance/keys','POST',expect=409)
    source.request('/api/maintenance/jobs','POST',dict(action='verify'),expect=409)
    source.request('/api/maintenance/recover','POST',dict(action='resume'),use_csrf=False,expect=403)
    source.compose('exec','-T','ldap','python3','-c',"import os,signal;from pathlib import Path\nfor p in Path('/proc').iterdir():\n try:\n  if p.name.isdigit() and (p/'comm').read_text().strip()=='slapd':os.kill(int(p.name),signal.SIGCONT)\n except FileNotFoundError:pass")
    time.sleep(.5);source.request('/api/maintenance/recover','POST',dict(action='resume'));source.poll();source.bind('retained')
    source.request('/api/maintenance/recover','POST',dict(action='resume'),expect=400)
    print('PASS: interrupted offline operation survives worker/manager restart; original scoped session can resume with CSRF; completed operations cannot resume.',flush=True)
    # A verified restore with damaged staging must retain a coherent rollback copy.
    source.request('/api/users','POST',source.user('afterbackup'))
    uploaded=source.upload(archive)
    run(['docker','kill','--signal','STOP',worker])
    source.request('/api/maintenance/jobs','POST',dict(action='restore',upload_id=uploaded['id'],sha256=checksum,identity=identity.decode(),uid_floor=1000000,original_fenced=True,acknowledge=True,network=source.net))
    time.sleep(.5)
    source.compose('exec','-T','ldap','python3','-c',"import os,signal;from pathlib import Path;p=next(p for p in Path('/proc').iterdir() if p.name.isdigit() and (p/'comm').read_text().strip()=='slapd');os.kill(int(p.name),signal.SIGSTOP)")
    run(['docker','kill','--signal','CONT',worker])
    for _ in range(100):
        state=source.compose('exec','-T','maintenance','python3','-c',"import json;from pathlib import Path;print(json.loads(Path('/work/job.json').read_text())['phase'])").stdout.strip()
        if state==b'verified':break
        time.sleep(.1)
    else:raise AssertionError('Restore did not reach verified staging')
    source.compose('restart','maintenance','manager');source.wait('/health');assert source.poll(success=False)['status']=='needs_resume'
    source.compose('exec','-T','ldap','python3','-c',"import os,signal;from pathlib import Path\nfor p in Path('/proc').iterdir():\n try:\n  if p.name.isdigit() and (p/'comm').read_text().strip()=='slapd':os.kill(int(p.name),signal.SIGCONT)\n except FileNotFoundError:pass")
    source.compose('exec','-T','maintenance','python3','-c',"from pathlib import Path;p=Path('/work/stage/metadata/forklift.db');p.write_bytes(p.read_bytes()+b'fault injection')")
    time.sleep(.5);source.request('/api/maintenance/recover','POST',dict(action='resume'));assert source.poll(success=False)['status']=='needs_resume'
    source.request('/api/maintenance/recover','POST',dict(action='rollback'));assert source.poll()['result']['rolled_back']
    source.request('/api/me',expect=401);source.login();source.bind('afterbackup')
    print('PASS: interrupted verified restore resumes without saved recovery key, detects changed staging, and rolls back to coherent pre-restore data/credentials.',flush=True)
    # Only a console holder can recover a locked-out existing administrator.
    source.request('/api/maintenance/jobs','POST',dict(action='emergency-reset'),expect=400)
    source.request('/api/emergency-reset','POST',{},expect=404)
    import secrets
    replacement=secrets.token_urlsafe(30)
    code="import json,sys;from emergency import call;p=json.load(sys.stdin);assert call('/emergency-reset',p)['recovered']"
    source.compose('exec','-T','maintenance','python3','-c',code,input=json.dumps(dict(username='admin',password=replacement)).encode())
    source.request('/api/me',expect=401);source.password=replacement;source.login();source.bind('admin')
    code="import sys;from pathlib import Path;private=sys.stdin.buffer.read();assert private not in Path('/work/job.json').read_bytes();assert private not in Path('/metadata/forklift.db').read_bytes()"
    source.compose('exec','-T','maintenance','python3','-c',code,input=identity)
    print('PASS: emergency recovery is local-only, restores existing administrator login, revokes sessions and leaves recovery keys out of persistent metadata/job records.',flush=True)
