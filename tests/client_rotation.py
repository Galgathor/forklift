"""Real two-key DPoP rotation, native crash recovery and restore/revocation fencing."""
import base64
import hashlib
import json
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fixture import run


def exercise(s,binary,state_dir,begin,enrolled,approve,cli,state,stop,processes,browser):
    r=s.request
    path=state_dir('rotation')
    proc,code=begin(path,'rotation.example.test');grant=state(path)['grant'];record,_=approve(code);enrolled(proc)
    original=state(path);host_id=original['host_id'];prefix='/api/client/v1/hosts/'+host_id
    def host():return next(h for h in r('/api/hosts') if h['id']==host_id)
    h=host();r('/api/hosts/'+host_id,'PUT',{k:h[k] for k in ['hostname','endpoints','allowed_groups','revision']}|dict(name='Rotation test host'))
    client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=s.context))
    def b64(data):return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    def signed(key,access,url):
        key=serialization.load_pem_private_key(key.encode(),password=None);public=key.public_key().public_numbers()
        with client.open(s.url+'/api/client/v1/info') as response:nonce=response.headers['DPoP-Nonce']
        header=dict(typ='dpop+jwt',alg='ES256',jwk=dict(kty='EC',crv='P-256',x=b64(public.x.to_bytes(32,'big')),y=b64(public.y.to_bytes(32,'big'))))
        claims=dict(jti=secrets.token_hex(32),htm='POST',htu=s.url+url,iat=int(time.time()),nonce=nonce)
        if access:claims['ath']=b64(hashlib.sha256(access.encode()).digest())
        encoded=b64(json.dumps(header,separators=(',',':')).encode())+'.'+b64(json.dumps(claims,separators=(',',':')).encode());x,y=decode_dss_signature(key.sign(encoded.encode(),ec.ECDSA(hashes.SHA256())));return encoded+'.'+b64(x.to_bytes(32,'big')+y.to_bytes(32,'big'))
    def post(url,identity,body=None,expect=200,token=None):
        access=identity['access_token'] if token is None else token
        headers={'Content-Type':'application/json','DPoP':signed(identity['private_key'],access,url)}
        if access:headers['Authorization']='DPoP '+access
        request=urllib.request.Request(s.url+url,data=json.dumps(body or {}).encode(),headers=headers,method='POST')
        try:response=client.open(request)
        except urllib.error.HTTPError as error:response=error
        with response:
            value=json.load(response);assert response.code==expect,(response.code,value);return value
    def write(identity):
        run(['sudo','-n','python3','-c',"import json,sys;from pathlib import Path;p=Path(sys.argv[1]);p.write_text(json.dumps(json.load(sys.stdin)))",str(path/'state.json')],data=json.dumps(identity).encode())
    def daemon():
        process=subprocess.Popen(['sudo','-n',str(binary),'--state-dir',str(path),'daemon'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);processes.append(process);return process
    def wait(predicate):
        for _ in range(160):
            saved=state(path)
            if predicate(saved):return saved
            time.sleep(.15)
        raise AssertionError('Native credential rotation did not reach the expected state')
    def change_registry(**changes):
        code="import json,sqlite3,sys;p=json.load(sys.stdin);d=sqlite3.connect('/metadata/forklift.db');v=json.loads(d.execute('SELECT data FROM client_enrollments WHERE id=?',(p['id'],)).fetchone()[0]);v.update(p['changes']);d.execute('UPDATE client_enrollments SET data=? WHERE id=?',(json.dumps(v),p['id']));d.commit()"
        s.compose('exec','-T','maintenance','python3','-c',code,input=json.dumps(dict(id=record['id'],changes=changes)).encode())
    def registry():
        return json.loads(s.compose('exec','-T','maintenance','python3','-c',"import json,sqlite3,sys;d=sqlite3.connect('/metadata/forklift.db');v=json.loads(d.execute('SELECT data FROM client_enrollments WHERE id=?',(sys.stdin.read(),)).fetchone()[0]);print(json.dumps({'rotation':v.get('rotation')}))",input=record['id'].encode()).stdout)
    def pending():
        key=ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
        return dict(request_id=secrets.token_hex(32),private_key=key,rotation_id=None,access_token=None,generation=None,expires_at=None)
    def prepare(saved,p):
        url=prefix+'/rotation/prepare'
        return post(url,saved,dict(request_id=p['request_id'],new_proof=signed(p['private_key'],saved['access_token'],url)))
    def local_prepare(saved,p,response):
        p.update(rotation_id=response['rotation_id'],access_token=response['access_token'],generation=response['generation'],expires_at=response['expires_at']);saved['pending_rotation']=p;write(saved)
        return saved|dict(private_key=p['private_key'],access_token=p['access_token'])
    monitor=daemon();wait(lambda v:v.get('last_report') is not None);stop(monitor)
    r('/api/clients/'+record['id']+'/rotate','POST',dict(acknowledge=True),use_csrf=False,expect=403)
    browser('rotate')
    assert host()['client']['credentials']['rotation_due']
    monitor=daemon();second=wait(lambda v:v.get('credential_generation')==2 and v.get('pending_rotation') is None);stop(monitor)
    assert second['host_id']==host_id and second['credential_id']==original['credential_id']
    assert second['private_key']!=original['private_key'] and second['access_token']!=original['access_token']
    post(prefix+'/session',original,expect=401)
    post(prefix+'/session',second|dict(private_key=original['private_key']),expect=401)
    post(prefix+'/session',second)
    assert json.loads(cli(path,'status').stdout)['connectivity']=='connected'
    # Consumed bootstrap grants cannot retrieve a rotated credential.
    post('/api/client/v1/enrollments/'+record['id']+'/token',second,dict(device_code=grant['device_code']),token='',expect=403)
    print('PASS: actual WebUI rotation request, native key/token replacement, stable host/counters, rejected old-key/token combinations and closed bootstrap credential retrieval.',flush=True)
    # Preparation reply lost before the native client persisted its provisional token.
    p=pending();receipt=prepare(second,p);second['pending_rotation']=p;write(second)
    provisional=second|dict(private_key=p['private_key'],access_token=receipt['access_token'])
    post(prefix+'/session',provisional,expect=401);post(prefix+'/session',second)
    post(prefix+'/rotation/confirm',second,dict(rotation_id=receipt['rotation_id']),expect=401)
    monitor=daemon();third=wait(lambda v:v.get('credential_generation')==3);stop(monitor)
    assert third['private_key']==p['private_key']
    # Confirmation committed, but its acknowledgement and local promotion were lost.
    p=pending();receipt=prepare(third,p);provisional=local_prepare(third,p,receipt)
    post(prefix+'/rotation/confirm',provisional,dict(rotation_id=p['rotation_id']))
    post(prefix+'/session',third,expect=401)
    third['pending_rotation']['expires_at']=int(time.time())-1;write(third)
    s.compose('restart','manager');s.wait()
    monitor=daemon();fourth=wait(lambda v:v.get('credential_generation')==4);stop(monitor)
    assert fourth['private_key']==p['private_key'] and fourth['pending_rotation'] is None
    print('PASS: lost prepare/confirm responses, new-key-only confirmation, manager restart and expired local pending metadata recover from the same durable provisional key.',flush=True)
    # Independent expiry/age/revocation scenarios start fresh minute windows.
    s.compose('exec','-T','maintenance','python3','-c',"import sqlite3;d=sqlite3.connect('/metadata/forklift.db');d.execute('DELETE FROM client_limits');d.commit()")
    # Unconfirmed expiry never invalidates the primary credential.
    p=pending();receipt=prepare(fourth,p);provisional=local_prepare(fourth,p,receipt)
    server_pending=registry()['rotation'];server_pending['expires_at']=int(time.time())-1;change_registry(rotation=server_pending)
    monitor=daemon();unchanged=wait(lambda v:v.get('pending_rotation') is None);stop(monitor)
    assert unchanged['credential_generation']==4 and unchanged['private_key']==fourth['private_key']
    post(prefix+'/session',unchanged)
    post(prefix+'/rotation/confirm',provisional,dict(rotation_id=p['rotation_id']),expect=410)
    # Rotation is also driven by server age, without a WebUI request or client-supplied clock.
    change_registry(rotated_at=int(time.time())-31*86400)
    monitor=daemon();fifth=wait(lambda v:v.get('credential_generation')==5);stop(monitor)
    assert fifth['private_key']!=fourth['private_key']
    # Revocation fences both the current and provisional credential.
    p=pending();receipt=prepare(fifth,p);provisional=local_prepare(fifth,p,receipt)
    r('/api/clients/'+record['id']+'/revoke','POST',dict(acknowledge=True))
    post(prefix+'/session',fifth,expect=401)
    post(prefix+'/rotation/confirm',provisional,dict(rotation_id=p['rotation_id']),expect=401)
    monitor=daemon();retained=wait(lambda v:v.get('rotation_error') is not None);stop(monitor)
    assert retained['private_key']==fifth['private_key'] and retained['pending_rotation']['private_key']==p['private_key']
    public=cli(path,'status','--offline').stdout
    for secret in [fifth['private_key'],fifth['access_token'],p['private_key'],p['access_token']]:assert secret.encode() not in public
    s.compose('exec','-T','maintenance','python3','-c',"import sys;from pathlib import Path;value=sys.stdin.buffer.read();assert all(value not in p.read_bytes() for p in Path('/metadata').glob('forklift.db*'))",input=p['access_token'].encode())
    print('PASS: expired unconfirmed rotation preserves primary access, automatic age-based rotation, revocation fencing, root-state retention and absence of provisional credentials from status and SQLite/WAL.',flush=True)
    # Leave an active provisional identity in the snapshot used by the parent restore drill.
    restore_path=state_dir('rotation-restore');proc,code=begin(restore_path,'rotation-restore.example.test');restore_record,_=approve(code);enrolled(proc)
    restore_saved=state(restore_path);restore_host=restore_saved['host_id'];restore_prefix='/api/client/v1/hosts/'+restore_host
    new=pending();url=restore_prefix+'/rotation/prepare';receipt=post(url,restore_saved,dict(request_id=new['request_id'],new_proof=signed(new['private_key'],restore_saved['access_token'],url)))
    candidate=restore_saved|dict(private_key=new['private_key'],access_token=receipt['access_token'])
    # The extra inventory name stays distinct from the browser fixture's main host.
    h=next(h for h in r('/api/hosts') if h['id']==restore_host);r('/api/hosts/'+restore_host,'PUT',{k:h[k] for k in ['hostname','endpoints','allowed_groups','revision']}|dict(name='Rotation restore host'))
    def restored():
        post(restore_prefix+'/session',restore_saved,expect=401)
        post(restore_prefix+'/rotation/confirm',candidate,dict(rotation_id=receipt['rotation_id']),expect=401)
    return restored
