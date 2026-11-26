#!/usr/bin/env python3
"""Encrypted online DNS capture, actual restoration and hostile/legacy archive rejection."""
import base64
import hashlib
import io
import json
import secrets
import sqlite3
import tarfile
import threading
import time
from fixture import Stack, run, port

with Stack(https=True) as source:
    source.setup()
    r=source.request
    forwarding=dict(enabled=False,upstreams=[dict(address='192.168.1.1',port=53)],allowed_clients=['192.168.1.0/24'])
    r('/api/dns/forwarding','PUT',forwarding)
    zone='example.test.'
    r('/api/dns/zones','POST',dict(name=zone,kind='forward',nameserver='ns1.example.test.',nameserver_address='192.168.1.2',ttl=300))
    r('/api/dns/zones','POST',dict(name='192.168.1.0/24',kind='reverse4',nameserver='ns1.example.test.',ttl=300))
    host=r('/api/hosts','POST',dict(name='DNS host',hostname='server.example.test',endpoints=['ldaps://ldap.example.test'],allowed_groups=[],dns=dict(zone=zone,fqdn='server',ipv4='192.168.1.50',ipv6=None,reverse=True)))
    r('/api/users','POST',source.user('retained'))
    r('/api/dns/primary','PUT',dict(address=source.net['address'],dns_port=int(source.env['FORKLIFT_DNS_PORT']),acknowledge=True))
    peer=r('/api/dns/servers','POST',dict(name='Archived peer',address=source.net['address'],dns_port=port(),control_port=port(),zones=[zone]))
    join=r('/api/dns/servers/'+peer['id']+'/deployment','POST',dict(acknowledge=True))
    token=json.loads(base64.b64decode(join['join_config'].partition('=')[2]))['enrollment']['token']
    key_name='forklift-dns-'+peer['id']+'-1.'
    key=base64.b64encode(secrets.token_bytes(32)).decode()
    def native(stack,method,path,body=None):
        code="import http.client,json,sys;from pathlib import Path;p=json.load(sys.stdin);c=http.client.HTTPConnection('127.0.0.1',8081);c.request(p['method'],'/api/v1/servers/localhost'+p['path'],body=json.dumps(p['body']).encode() if p['body'] is not None else None,headers={'X-API-Key':Path('/run/dns-secrets/api-key').read_text().strip(),'Content-Type':'application/json'});r=c.getresponse();b=r.read();assert 200<=r.status<300,(r.status,b);print(b.decode())"
        result=stack.compose('exec','-T','dns','python3','-c',code,input=json.dumps(dict(method=method,path=path,body=body)).encode()).stdout
        return json.loads(result) if result.strip() else None
    native(source,'POST','/tsigkeys',dict(name=key_name,algorithm='hmac-sha256',key=key))
    native(source,'PUT','/zones/'+zone,dict(kind='Primary',master_tsig_key_ids=[key_name]))
    def dig(stack,name,kind='A',value=None):
        out=run(['docker','run','--rm','--network','host','--entrypoint','dig','forklift-dns:latest','@127.0.0.1','-p',stack.env['FORKLIFT_DNS_PORT'],name,kind,'+time=1','+tries=1']).stdout.decode()
        assert 'status: NOERROR' in out and 'aa' in out.split('flags:',1)[1].split(';',1)[0].split(),out
        if value:assert value in out,out
        return out
    identity,headers=r('/api/maintenance/keys','POST',raw=True)
    recipient=headers['X-Age-Recipient']
    failures=[];observed=[];done=threading.Event()
    def query_during_backup():
        while not done.is_set():
            try:dig(source,'server.example.test.',value='192.168.1.50');observed.append(True)
            except BaseException as e:failures.append(str(e))
    thread=threading.Thread(target=query_during_backup);thread.start()
    try:saved=source.job(dict(action='backup',recipient=recipient))
    finally:done.set();thread.join()
    assert observed and not failures,failures
    assert saved['result']['dns_included']
    archive,_=r('/api/maintenance/backups/'+saved['id'],raw=True)
    checksum=saved['result']['sha256']
    assert hashlib.sha256(archive).hexdigest()==checksum
    plain=source.compose('exec','-T','maintenance','age','-d','-i','/dev/stdin','/backups/'+saved['id']+'.tar.gz.age',input=identity).stdout
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:gz') as tar:
        members={m.name:tar.extractfile(m).read() for m in tar}
    manifest=json.loads(members['manifest.json'])
    assert manifest['format']==3 and {'dns/pdns.sqlite3','dns/layout.json','dns-secrets/api-key','dns-secrets/control'}.issubset(members)
    assert not any(n.endswith(('-wal','-shm')) for n in members if n.startswith('dns/'))
    def encrypted_variant(legacy=False,malformed=False):
        entries=dict(members)
        m=json.loads(entries.pop('manifest.json'))
        if legacy:
            entries={k:v for k,v in entries.items() if not k.startswith(('dns/','dns-secrets/'))}
            m['format']=2;m.pop('dns_schema',None)
        if malformed:
            file=source.root/'untrusted.sqlite3';file.write_bytes(entries['dns/pdns.sqlite3'])
            db=sqlite3.connect(file);db.execute('CREATE VIEW unexpected AS SELECT 1');db.commit();db.close()
            entries['dns/pdns.sqlite3']=file.read_bytes();file.unlink()
        m['files']=[dict(path=n,size=len(b),sha256=hashlib.sha256(b).hexdigest()) for n,b in entries.items()]
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
            for name,data in [('manifest.json',json.dumps(m).encode()),*entries.items()]:
                entry=tarfile.TarInfo(name);entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
        return source.compose('exec','-T','maintenance','age','-r',recipient,input=buffer.getvalue()).stdout
    legacy=encrypted_variant(legacy=True)
    malformed=encrypted_variant(malformed=True)
    # Fence the original authoritative/authentication services before publishing restored data.
    source.compose('stop','ldap','dns')
    with Stack(https=True) as target:
        target.setup()
        t=target.request
        data=target.upload(malformed)
        result=target.job(dict(action='verify',upload_id=data['id'],sha256=hashlib.sha256(malformed).hexdigest(),identity=identity.decode()),success=False)
        assert result['status']=='failed' and 'schema' in result['error'].lower(),result
        data=target.upload(legacy)
        request=dict(upload_id=data['id'],sha256=hashlib.sha256(legacy).hexdigest(),identity=identity.decode())
        assert target.job(dict(request,action='verify'))['result']['dns_included'] is False
        result=target.job(dict(request,action='restore',uid_floor=900000,original_fenced=True,acknowledge=True,network=target.net),success=False)
        assert result['status']=='failed' and 'LDAP-only' in result['error'],result
        target.bind('admin')
        uploaded=target.upload(archive)
        body=dict(upload_id=uploaded['id'],sha256=checksum,identity=identity.decode())
        verified=target.job(dict(body,action='verify'))
        assert verified['result']['dns_included']
        restored=target.job(dict(body,action='restore',uid_floor=900000,original_fenced=True,acknowledge=True,network=target.net))
        assert restored['result']['restored']
        target.password=source.password;target.login();target.bind('retained')
        dig(target,'server.example.test.',value='192.168.1.50')
        dig(target,'50.1.168.192.in-addr.arpa.','PTR','server.example.test.')
        assert target.request('/api/operations')['recovery_required']
        assert not any(k['name'].startswith('forklift-dns-') for k in native(target,'GET','/tsigkeys'))
        assert all(z['kind']=='Native' for z in t('/api/dns')['zones'])
        assert t('/api/dns/forwarding')['settings']==forwarding
        server=t('/api/dns/servers')['servers'][0]
        assert server['state']=='restore_required' and server['expires_at']==0
        t('/api/dns/servers/'+peer['id']+'/enroll','POST',dict(token=token,certificate='invalid'),authenticated=False,expect=403)
        t('/api/dns/hosts/'+host['id']+'/reconcile','POST',{},expect=503)
        t('/api/recovery/complete','POST',dict(acknowledge=True))
        status=t('/api/dns/hosts/'+host['id']+'/reconcile','POST',{})
        assert status['state']=='applied',status
        # Quarantined peers must remain excluded from remote control even after a failed removal.
        target.compose('exec','-T','maintenance','python3','-c',"import json,sqlite3,sys;from pathlib import Path;d=sqlite3.connect('/metadata/forklift.db');n=json.loads(d.execute('SELECT data FROM dns_servers WHERE id=?',(sys.argv[1],)).fetchone()[0]);n['certificate']=Path('/secrets/ldap.crt').read_text();d.execute('UPDATE dns_servers SET data=? WHERE id=?',(json.dumps(n),sys.argv[1]));d.commit()",peer['id'])
        target.compose('stop','dns')
        assert not t('/api/dns/servers/'+peer['id'],'DELETE',dict(acknowledge=True))['removed']
        target.compose('up','-d','--no-build','--no-deps','--wait','dns')
        assert t('/api/dns/servers/'+peer['id'],'DELETE',dict(acknowledge=True))['removed']
        target.compose('up','-d','--no-build','--force-recreate','--wait');target.wait();target.bind('retained')
        dig(target,'server.example.test.',value='192.168.1.50')
        # Interrupt before replacement, recreate the fenced DNS container, then fail midway through apply.
        current=t('/api/dns/zones/'+zone)
        old=next(v for v in current['rrsets'] if v['name']=='server.example.test.' and v['type']=='A')
        t('/api/dns/zones/'+zone+'/records','POST',dict(name='server',type='A',ttl=300,values=['192.168.1.51'],expected_revision=old['revision']))
        worker=target.compose('ps','-q','maintenance').stdout.decode().strip()
        run(['docker','kill','--signal','STOP',worker])
        t('/api/maintenance/jobs','POST',dict(body,action='restore',uid_floor=1000000,original_fenced=True,acknowledge=True,network=target.net))
        time.sleep(.5)
        target.compose('exec','-T','ldap','python3','-c',"import os,signal;from pathlib import Path;p=next(p for p in Path('/proc').iterdir() if p.name.isdigit() and (p/'comm').read_text().strip()=='slapd');os.kill(int(p.name),signal.SIGSTOP)")
        run(['docker','kill','--signal','CONT',worker])
        for _ in range(100):
            fenced=target.compose('exec','-T','maintenance','python3','-c',"from pathlib import Path;print(Path('/run/dns-control/offline.json').exists())").stdout.strip()
            if fenced==b'True':break
            time.sleep(.1)
        else:raise AssertionError('DNS restore fence was not published')
        target.compose('restart','maintenance','manager');target.wait('/health');assert target.poll(success=False)['status']=='needs_resume'
        target.compose('up','-d','--no-build','--no-deps','--force-recreate','--wait','dns')
        def fenced_query():
            text=run(['docker','run','--rm','--network','host','--entrypoint','dig','forklift-dns:latest','@127.0.0.1','-p',target.env['FORKLIFT_DNS_PORT'],'server.example.test.','A','+time=1','+tries=1'],check=False).stdout
            assert b'status: NOERROR' not in text,'Fenced DNS unexpectedly published data'
        fenced_query()
        target.compose('exec','-T','ldap','python3','-c',"import os,signal;from pathlib import Path\nfor p in Path('/proc').iterdir():\n try:\n  if p.name.isdigit() and (p/'comm').read_text().strip()=='slapd':os.kill(int(p.name),signal.SIGCONT)\n except FileNotFoundError:pass")
        target.compose('exec','-T','dns','chmod','0555','/dns')
        time.sleep(.5);t('/api/maintenance/recover','POST',dict(action='resume'));assert target.poll(success=False)['status']=='needs_resume'
        t('/ready',expect=503);fenced_query()
        target.compose('exec','-T','dns','chmod','0700','/dns')
        target.compose('exec','-T','dns','python3','-c',"from pathlib import Path;Path('/dns/pdns.sqlite3').write_bytes(b'interrupted native file replacement')")
        target.compose('up','-d','--no-build','--no-deps','--force-recreate','--wait','dns')
        fenced_query()
        t('/api/maintenance/recover','POST',dict(action='rollback'));assert target.poll()['result']['rolled_back']
        target.login();target.bind('retained')
        dig(target,'server.example.test.',value='192.168.1.51')
        print('PASS: durable DNS fence survives recreation; partial LDAP/DNS replacement stays offline; rollback restores previous real DNS answers and LDAP credentials.',flush=True)
        print('PASS: DNS remains authoritative during encrypted online capture; schema/legacy safeguards, real LDAP+A/PTR restoration, transfer revocation, peer quarantine, host ownership and persistent recreation.',flush=True)
