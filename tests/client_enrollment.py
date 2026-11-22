#!/usr/bin/env python3
"""Native root-owned client against real HTTPS, LDAP authorization and durable metadata."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import select
import secrets
import signal
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fixture import Stack, SOURCE, run

CLIENT = Path(os.environ.get('FORKLIFT_CLIENT_BINARY', SOURCE.parent/'forklift-client/target/debug/forklift-client')).resolve()
assert CLIENT.is_file(), 'Build the native Forklift Client first'
assert (SOURCE/'docs/client-api-v1.md').read_bytes() == (SOURCE.parent/'forklift-client/docs/client-api-v1.md').read_bytes()


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


with Stack(https=True) as s:
    s.setup()
    r = s.request
    paths = []
    processes = []
    def state_dir(name):
        path = Path('/tmp')/(s.project+'-native-'+name)
        assert not path.exists()
        run(['sudo', '-n', 'mkdir', '-m', '700', str(path)])
        paths.append(path)
        return path
    def cli(path, *args, check=True, data=None):
        return run(['sudo', '-n', str(CLIENT), '--state-dir', str(path), *args], check=check, data=data)
    def exists(path):
        return run(['sudo','-n','test','-f',str(path/'state.json')],check=False).returncode==0
    def state(path):
        return json.loads(run(['sudo', '-n', 'cat', str(path/'state.json')]).stdout)
    def begin(path, hostname='client.example.test', resume=False):
        args = ['sudo', '-n', str(CLIENT), '--state-dir', str(path), 'join']
        if not resume:
            args += ['--server', s.url, '--ca-file', str(s.root/'ca.crt'), '--hostname', hostname]
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        processes.append(proc)
        seen = ''
        deadline = time.monotonic()+30
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise AssertionError('Native join failed before a pairing code: '+proc.stderr.read()[:300])
            if select.select([proc.stdout], [], [], .2)[0]:
                # Rust flushes the code block. Buffered text readline may otherwise hide following lines.
                seen += os.read(proc.stdout.fileno(), 4096).decode()
                match = re.search(r'Enrollment code: ([A-Z2-9]{4}-[A-Z2-9]{4})', seen)
                if match:
                    return proc, match[1]
        raise AssertionError('Native client did not display pairing code')
    def stop(proc):
        if proc.poll() is None:
            run(['sudo', '-n', 'kill', '-TERM', str(proc.pid)], check=False)
            proc.wait(timeout=15)
    def enrolled(proc):
        output, error = proc.communicate(timeout=25)
        assert proc.returncode == 0, error[:500]
        assert 'Enrollment successful' in output
    def approve(code, host=None):
        item = r('/api/clients/lookup', 'POST', dict(code=code))
        body = dict(name='Native client', host_id=host['id'] if host else None,
                    host_revision=host['revision'] if host else None, acknowledge=True)
        return item, r('/api/clients/'+item['id']+'/approve', 'POST', body)
    def browser(action, **fields):
        deps=Path(os.environ.get('FORKLIFT_TEST_BROWSER_DEPS','/tmp/forklift-m4-browser/node_modules')).resolve()
        result=run(['docker','run','--rm','-i','--network','host','--user',str(os.getuid())+':'+str(os.getgid()),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--tmpfs','/tmp:rw,nosuid,size=256m','--shm-size','256m','-e','NODE_PATH=/deps','-v',str(deps)+':/deps:ro','-v',str(SOURCE/'tests/client_browser.cjs')+':/test.cjs:ro','mcr.microsoft.com/playwright:v1.65.0-noble@sha256:6e3fb709361521eb27161606e6da6d2674e5e89fa16516cb37d6fdd91372273d','node','/test.cjs'],data=json.dumps(dict(url=s.url,password=s.password,action=action,**fields)).encode())
        print(result.stdout.decode(),end='',flush=True)
    def update_record(record, **changes):
        code="import json,sqlite3,sys;p=json.load(sys.stdin);d=sqlite3.connect('/metadata/forklift.db');n=json.loads(d.execute('SELECT data FROM client_enrollments WHERE id=?',(p['id'],)).fetchone()[0]);n.update(p['changes']);d.execute('UPDATE client_enrollments SET data=? WHERE id=?',(json.dumps(n),p['id']));d.commit()"
        s.compose('exec', '-T', 'maintenance', 'python3', '-c', code, input=json.dumps(dict(id=record['id'], changes=changes)).encode())
    try:
        first = state_dir('one')
        failed = cli(first, 'join', '--server', s.url, check=False)
        assert failed.returncode and not exists(first)
        failed = cli(first, 'join', '--server', s.url.replace('https:', 'http:'), check=False)
        assert failed.returncode
        proc, pairing = begin(first)
        pending = state(first)
        r('/api/clients/lookup', 'POST', dict(code=pairing), authenticated=False, expect=401)
        r('/api/clients/lookup', 'POST', dict(code=pairing), use_csrf=False, expect=403)
        r('/api/clients/lookup', 'POST', dict(code='😀😀'), expect=400)
        item = r('/api/clients/lookup', 'POST', dict(code=pairing))
        assert item['key_fingerprint'] and item['identity']['hostname']=='client.example.test'
        # Server-generated pair codes/device identities survive an interrupted root process.
        stop(proc)
        proc, same = begin(first, resume=True)
        assert same == pairing
        browser('approve',code=pairing,fingerprint=item['key_fingerprint'])
        r('/api/clients/lookup', 'POST', dict(code=pairing), expect=404)
        r('/api/clients/'+item['id']+'/approve', 'POST', dict(name='Duplicate', host_id=None, host_revision=None, acknowledge=True), expect=409)
        enrolled(proc)
        saved = state(first)
        host_id = saved['host_id']
        host = next(h for h in r('/api/hosts') if h['id']==host_id)
        assert host['client']['state']=='active' and not host['allowed_groups'] and not host['dns']
        assert host['client']['last_contact'] and host['hostname']=='client.example.test'
        status = cli(first, 'status', '--offline').stdout
        assert json.loads(status)['host_id']==host_id
        assert saved['access_token'].encode() not in status and saved['private_key'].encode() not in status
        mode = run(['sudo', '-n', 'stat', '-c', '%u:%a', str(first), str(first/'state.json')]).stdout.splitlines()
        assert mode == [b'0:700', b'0:600'], mode
        assert json.loads(cli(first, 'status').stdout)['connectivity']=='connected'
        s.compose('exec','-T','maintenance','python3','-c',"import sys;from pathlib import Path;secret=sys.stdin.buffer.read();assert all(secret not in file.read_bytes() for file in Path('/metadata').glob('forklift.db*'))",input=saved['access_token'].encode())
        s.compose('exec','-T','maintenance','python3','-c',"import sys;from pathlib import Path;secret=sys.stdin.buffer.read();assert all(secret not in file.read_bytes() for file in Path('/metadata').glob('forklift.db*'))",input=pending['grant']['device_code'].encode())

        print('PASS: verified native HTTPS/private CA, HTTP/untrusted TLS rejection, WebUI-auth pairing approval, code consumption, interrupted join, host registration, root-only credential persistence and redacted status.', flush=True)

        # Independently produce standard DPoP proofs using the actual native identity.
        key = serialization.load_pem_private_key(saved['private_key'].encode(), password=None)
        public = key.public_key().public_numbers()
        jwk = dict(kty='EC', crv='P-256', x=b64(public.x.to_bytes(32, 'big')), y=b64(public.y.to_bytes(32, 'big')))
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=s.context))
        def nonce():
            with client.open(s.url+'/api/client/v1/info') as response:
                return response.headers['DPoP-Nonce']
        def proof(path, token, private=key, jwk_value=jwk, **changes):
            claims = dict(jti=secrets.token_hex(32), htm='POST', htu=s.url+path, iat=int(time.time()), nonce=nonce())
            if token is not None:
                claims['ath']=b64(hashlib.sha256(token.encode()).digest())
            claims.update(changes)
            left=b64(json.dumps(dict(typ='dpop+jwt',alg='ES256',jwk=jwk_value),separators=(',',':')).encode())+'.'+b64(json.dumps(claims,separators=(',',':')).encode())
            signature=private.sign(left.encode(),ec.ECDSA(hashes.SHA256()))
            x,y=decode_dss_signature(signature)
            return left+'.'+b64(x.to_bytes(32,'big')+y.to_bytes(32,'big'))
        def machine(path, token, signed=None, expected=200, body=None, authorization='DPoP'):
            headers={'Content-Type':'application/json'}
            if signed:
                headers['DPoP']=signed
            if token:
                headers['Authorization']=authorization+' '+token
            request=urllib.request.Request(s.url+path,data=json.dumps(body or {}).encode(),headers=headers,method='POST')
            try:response=client.open(request)
            except urllib.error.HTTPError as error:response=error
            with response:
                value=json.load(response)
                assert response.code==expected,(response.code,value)
                return value
        path='/api/client/v1/hosts/'+host_id+'/session'
        token=saved['access_token']
        signed=proof(path,token)
        machine(path,token,signed)
        machine(path,token,signed,expected=401)
        machine(path,token,expected=401)
        machine(path,token,proof(path,token),authorization='Bearer',expected=401)
        for change in [dict(htm='GET'),dict(htu=s.url+path+'/other'),dict(iat=int(time.time())-3600),dict(nonce='invalid'),dict(ath='invalid')]:
            machine(path,token,proof(path,token,**change),expected=401)
        other_key=ec.generate_private_key(ec.SECP256R1())
        numbers=other_key.public_key().public_numbers()
        other_jwk=dict(kty='EC',crv='P-256',x=b64(numbers.x.to_bytes(32,'big')),y=b64(numbers.y.to_bytes(32,'big')))
        def replay_count():
            return int(s.compose('exec','-T','maintenance','python3','-c',"import sqlite3;print(sqlite3.connect('/metadata/forklift.db').execute('SELECT count(*) FROM client_replays').fetchone()[0])").stdout)
        before=replay_count()
        machine(path,token,proof(path,token,private=other_key,jwk_value=other_jwk),expected=401)
        assert replay_count()==before, 'An unrelated key populated the enrolled replay cache'
        foreign='/api/client/v1/hosts/'+'f'*32+'/session'
        machine(foreign,token,proof(foreign,token),expected=401)
        machine(path,token,proof(path,token),body={'command':'forbidden'},expected=422)
        s.compose('restart','manager');s.wait()
        machine(path,token,signed,expected=401)
        assert json.loads(cli(first,'status').stdout)['connectivity']=='connected'
        print('PASS: real ES256 DPoP interoperability, durable replay rejection, nonce/time/method/URL/token/key binding, cross-host isolation and no Bearer-only/command access.',flush=True)

        # Manual inventory linking is explicit and preserves DNS/login ownership and numeric host IDs.
        r('/api/groups/client-policy','PUT',dict(name='client-policy',members=[]))
        manual=r('/api/hosts','POST',dict(name='Manual Linux host',hostname='manual.example.test',endpoints=['ldaps://ldap.example.test'],allowed_groups=['client-policy']))
        assert not manual.get('client')
        second=state_dir('two')
        process2,code2=begin(second,hostname='manual.example.test')
        item2=r('/api/clients/lookup','POST',dict(code=code2))
        r('/api/clients/'+item2['id']+'/approve','POST',dict(name='Conflict',host_id=None,host_revision=None,acknowledge=True),expect=409)
        r('/api/clients/'+item2['id']+'/approve','POST',dict(name='Link',host_id=manual['id'],host_revision=manual['revision']+1,acknowledge=True),expect=409)
        approve(code2,manual)
        enrolled(process2)
        linked=next(h for h in r('/api/hosts') if h['id']==manual['id'])
        assert linked['allowed_groups']==['client-policy'] and linked['revision']==manual['revision']
        assert state(second)['host_id']==manual['id']
        cli(second,'leave')
        assert not exists(second)
        assert next(h for h in r('/api/hosts') if h['id']==manual['id'])['client']['state']=='revoked'
        print('PASS: explicit manual-host linking, hostname/stale-edit safeguards, retained manual policies and authorized remote leave without deleting inventory.',flush=True)

        cancelled=state_dir('cancelled')
        cancel_proc,cancel_code=begin(cancelled,hostname='cancelled.example.test')
        cancel_saved=state(cancelled)
        stop(cancel_proc)
        cli(cancelled,'leave')
        r('/api/clients/lookup','POST',dict(code=cancel_code),expect=404)
        assert not exists(cancelled)
        print('PASS: explicit client cancellation consumes pairing authorization and removes only its local credential.',flush=True)

        expired=state_dir('expired')
        pending_proc,expired_code=begin(expired,hostname='expired.example.test')
        item3=r('/api/clients/lookup','POST',dict(code=expired_code))
        update_record(item3,expires_at=int(time.time())-1)
        r('/api/clients/lookup','POST',dict(code=expired_code),expect=404)
        pending_proc.communicate(timeout=15)
        assert pending_proc.returncode!=0
        def daemon():
            process=subprocess.Popen(['sudo','-n',str(CLIENT),'--state-dir',str(first),'daemon'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
            processes.append(process)
            return process
        def cached(predicate):
            for _ in range(80):
                current=state(first)
                if predicate(current):return current
                time.sleep(.2)
            raise AssertionError('Native daemon did not persist the expected state')
        previous_contact=state(first)['last_contact']
        time.sleep(1)
        monitor=daemon()
        cached(lambda current:current['last_contact']>previous_contact)
        stop(monitor)
        # Local diagnostics and cached status survive management outage; default leave retains credentials.
        s.compose('stop','manager')
        monitor=daemon()
        cached(lambda current:current['last_error'] is not None)
        assert json.loads(cli(first,'status','--offline').stdout)['host_id']==host_id
        assert json.loads(cli(first,'diagnostics').stdout)['checks'][0]['status']=='pass'
        stop(monitor)
        assert cli(first,'leave',check=False).returncode and exists(first)
        s.compose('start','manager');s.wait()
        monitor=daemon()
        cached(lambda current:current['last_error'] is None)
        stop(monitor)
        assert state(first)['access_token']==token
        print('PASS: native daemon process restart, authenticated contact, bounded offline cache, graceful shutdown and recovery preserve the same credential.',flush=True)
        # Back up an active credential, revoke it in the WebUI, then restore the snapshot.

        identity,headers=r('/api/maintenance/keys','POST',raw=True)
        snapshot=s.job(dict(action='backup',recipient=headers['X-Age-Recipient']))
        archive,_=r('/api/maintenance/backups/'+snapshot['id'],raw=True)
        r('/api/clients/'+item['id']+'/revoke','POST',dict(acknowledge=True),use_csrf=False,expect=403)
        browser('revoke')
        assert json.loads(cli(first,'status').stdout)['connectivity']=='unavailable'
        upload=s.upload(archive)
        s.job(dict(action='restore',upload_id=upload['id'],sha256=snapshot['result']['sha256'],identity=identity.decode(),uid_floor=900000,original_fenced=True,acknowledge=True,network=s.net))
        s.login()
        archived=next(h for h in r('/api/hosts') if h['id']==host_id)
        assert archived['client']['state']=='restore_required'
        archived_cancel='/api/client/v1/enrollments/'+item['id']+'/cancel'
        machine(archived_cancel,None,proof(archived_cancel,None),body={'device_code':pending['grant']['device_code']},expected=403)

        assert json.loads(cli(first,'status').stdout)['connectivity']=='unavailable'
        r('/api/recovery/complete','POST',dict(acknowledge=True))
        print('PASS: real encrypted installation restore quarantines client grants and rejects archived credentials while retaining inventory.',flush=True)
        r('/api/clients/'+item['id']+'/revoke','POST',dict(acknowledge=True),use_csrf=False,expect=403)
        r('/api/clients/'+item['id']+'/revoke','POST',dict(acknowledge=True))
        assert json.loads(cli(first,'status').stdout)['connectivity']=='unavailable'
        machine(path,token,proof(path,token),expected=401)
        cli(first,'leave','--local-only',data=b'leave\n')
        assert not exists(first)
        r('/api/client/v1/enrollments','POST',dict(api_version=2,request_id=secrets.token_hex(32),identity=saved['identity']),authenticated=False,expect=400)
        throttled=False
        for _ in range(25):
            value=r('/api/clients/lookup','POST',dict(code='AAAA-AAAA'),expect=(404,429))
            throttled=throttled or 'limit' in value['error'].lower()
        assert throttled,'Pairing-code guesses were not rate limited'
        print('PASS: actual expiration, admin revocation, offline cached status/read-only diagnostics, failed remote leave retaining identity and explicit local-only removal.',flush=True)
    finally:
        for process in processes:
            stop(process)
        for directory in paths:
            assert directory.parent==Path('/tmp') and directory.name.startswith(s.project+'-native-')
            run(['sudo','-n','rm','-rf','--',str(directory)],check=False)
