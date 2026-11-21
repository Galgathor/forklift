#!/usr/bin/env python3
"""Real fresh 0.5 setup, LDAP authentication, CRUD, host policies and failures."""
import configparser,http.cookiejar,io,json,os,secrets,subprocess,tarfile,time,urllib.request
from urllib.error import HTTPError
from fixture import Stack
BASE='dc=integration,dc=test'
def find_user(name):return next(u for u in request('/api/overview')['users'] if u['attrs']['uid']==[name])
with Stack(https=os.environ.get('FORKLIFT_TEST_UBUNTU')=='1') as fixture:
    PROJECT=fixture.project; URL=fixture.url; PASSWORD=fixture.password
    request=fixture.request;compose=fixture.compose;wait_ready=fixture.wait;ldap_bind=fixture.bind;user=fixture.user
    jar=fixture.jar
    print('Testing setup, authentication and CRUD…', flush=True)
    assert request('/api/status')['configured'] is False
    request('/api/not-implemented', expect=404)
    request('/api/overview',expect=401,authenticated=False)
    fixture.net=fixture.network()
    payload=dict(token='wrong',name='Integration',base=BASE,username='admin',password=PASSWORD,network=fixture.net,public_url=URL)
    request('/api/setup','POST',payload,expect=401)
    payload['token']=fixture.bootstrap
    request('/api/setup','POST',payload,origin='https://evil.invalid',expect=400)
    # Simulate an interrupted initial slapadd staging directory, before publication.
    compose('exec','-T','ldap','python3','-c',"import json;from pathlib import Path;d=Path('/directory');(d/'initialization.json').write_text(json.dumps({'base':'dc=integration,dc=test','username':'admin'}));(d/'initializing/db').mkdir(parents=True);(d/'initializing/db/interrupted').write_bytes(b'incomplete')")
    request('/api/setup','POST',payload)
    request('/api/setup','POST',payload,expect=400)
    request('/api/login','POST',dict(username='admin',password='wrong'),expect=401)
    login=request('/api/login','POST',dict(username='admin',password=PASSWORD))
    fixture.csrf=login['csrf']
    assert any(c.name=='forklift_session' and c.has_nonstandard_attr('HttpOnly') for c in jar)
    data=request('/api/overview')
    assert len(data['users'])==1 and len(data['groups'])==1
    assert 'userPassword' not in json.dumps(data)
    request('/api/groups/operators','PUT',dict(name='operators',members=[]),use_csrf=False,expect=403)
    request('/api/groups/operators','PUT',dict(name='operators',members=[]),origin='https://evil.invalid',expect=403)
    request('/api/groups/operators','PUT',dict(name='operators',members=[]))
    request('/api/users','POST',user('alice'))
    uid=int(find_user('alice')['attrs']['uidNumber'][0])
    ldap_bind('alice',PASSWORD)
    request('/api/login','POST',dict(username='alice',password=PASSWORD),expect=401,authenticated=False)
    request('/api/users','POST',user('alice*)(uid=*)'),expect=400)
    request('/api/groups/operators','PUT',dict(name='operators',members=['alice']))
    request('/api/groups/operators','PUT',dict(name='renamed',members=['alice']))
    request('/api/groups/renamed','DELETE')
    request('/api/groups/administrators','DELETE',expect=400)
    request('/api/groups/administrators','PUT',dict(name='administrators',members=[]),expect=400)
    request('/api/users/admin','DELETE',expect=400)
    disabled=user('alice');disabled['disabled']=True;disabled.pop('password')
    request('/api/users','POST',disabled)
    ldap_bind('alice',PASSWORD,False)
    enabled=dict(disabled,disabled=False)
    request('/api/users','POST',enabled,expect=400)
    reset=secrets.token_urlsafe(32)
    enabled['password']=reset
    request('/api/users','POST',enabled)
    ldap_bind('alice',PASSWORD,False)
    ldap_bind('alice',reset)
    request('/api/groups/administrators','PUT',dict(name='administrators',members=['admin','alice']))
    alice=request('/api/login','POST',dict(username='alice',password=reset),authenticated=False)
    # A new authenticated client verifies immediate membership revocation.
    second_jar=http.cookiejar.CookieJar()
    second=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(second_jar),urllib.request.HTTPSHandler(context=fixture.context))
    r=second.open(urllib.request.Request(URL+'/api/login',data=json.dumps(dict(username='alice',password=reset)).encode(),headers={'Content-Type':'application/json','Origin':URL}))
    r.close()
    request('/api/groups/administrators','PUT',dict(name='administrators',members=['admin']))
    try:
        second.open(URL+'/api/overview')
        raise AssertionError('Revoked administrator retained API access')
    except HTTPError as e:
        assert e.code==403
    request('/api/users/alice','DELETE')
    request('/api/users','POST',user('bob'))
    assert int(find_user('bob')['attrs']['uidNumber'][0])>uid
    print('Testing host registration, references, export rotation and authorization…', flush=True)
    host_data=dict(name='Test host',hostname='test.integration.test',endpoints=['ldaps://'+fixture.net['hostname']+':'+str(fixture.net['port'])],allowed_groups=['administrators'])
    request('/api/hosts',expect=401,authenticated=False)
    request('/api/hosts','POST',host_data,expect=403,use_csrf=False)
    request('/api/hosts','POST',dict(host_data,endpoints=['ldap://ldap']),expect=400)
    request('/api/hosts','POST',dict(host_data,allowed_groups=[]),expect=400)
    request('/api/hosts','POST',dict(host_data,allowed_groups=['missing']),expect=400)
    h=request('/api/hosts','POST',host_data)
    request('/api/hosts','POST',host_data,expect=400)
    assert len(request('/api/hosts'))==2
    request('/api/hosts/'+h['id'],'PUT',dict(host_data,revision=99),expect=409)
    request('/api/hosts/'+h['id']+'/bundle','POST',dict(revision=1,rotate=False),expect=400)
    request('/api/hosts/'+h['id']+'/bundle','POST',dict(revision=1,rotate=True),expect=403,use_csrf=False)
    import io,tarfile,configparser
    archive,_=request('/api/hosts/'+h['id']+'/bundle','POST',dict(revision=1,rotate=True),raw=True)
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
        assert tar.getmember('sssd.conf').mode==0o600
        conf=tar.extractfile('sssd.conf').read().decode()
    assert 'ldap_tls_reqcert = demand' in conf and 'cache_credentials = false' in conf
    parsed=configparser.ConfigParser(interpolation=None);parsed.read_string(conf)
    original_password=parsed['domain/forklift']['ldap_default_authtok']
    host_dn=parsed['domain/forklift']['ldap_default_bind_dn']
    assert original_password not in json.dumps(request('/api/overview'))
    rotated,_=request('/api/hosts/'+h['id']+'/bundle','POST',dict(revision=1,rotate=True),raw=True)
    with tarfile.open(fileobj=io.BytesIO(rotated),mode='r:gz') as tar:
        parsed.read_string(tar.extractfile('sssd.conf').read().decode())
    rotated_password=parsed['domain/forklift']['ldap_default_authtok']
    assert rotated_password!=original_password
    bind_check="import sys,json,os,subprocess; p=json.load(sys.stdin); r=subprocess.run(['ldapwhoami','-x','-H','ldapi://%2Frun%2Fldap-socket%2Fldap.sock','-D',p['dn'],'-y','/dev/stdin'],input=p['password'].encode(),env={**os.environ,'LDAPTLS_CACERT':'/run/secrets/ca.crt'},capture_output=True); assert r.returncode==p['expected']"
    for pw,expected in [(original_password,49),(rotated_password,0)]:
        compose('exec','-T','ldap','python3','-c',bind_check,input=json.dumps(dict(dn=host_dn,password=pw,expected=expected)).encode())
    # No reusable host password may appear in SQLite or its WAL.
    metadata_check="import pathlib,sys; p=sys.stdin.buffer.read(); assert all(p not in f.read_bytes() for f in pathlib.Path('/metadata').glob('forklift.db*'))"
    subprocess.run(['docker','run','--rm','-i','--network','none','--read-only','--cap-drop','ALL','-v',PROJECT+'_metadata:/metadata:ro','--entrypoint','python3','forklift-ldap:latest','-c',metadata_check],input=rotated_password.encode(),check=True,capture_output=True)
    request('/api/groups/host-policy','PUT',dict(name='host-policy',members=[]))
    h=request('/api/hosts/'+h['id'],'PUT',dict(host_data,allowed_groups=['host-policy'],revision=1))
    assert h['revision']==2 and h['exported_revision']==1
    request('/api/groups/host-policy','DELETE',expect=400)
    request('/api/groups/host-policy','PUT',dict(name='renamed-policy',members=[]),expect=400)
    request('/api/hosts/'+h['id']+'/bundle','POST',dict(revision=1,rotate=True),expect=409)
    if os.environ.get('FORKLIFT_TEST_UBUNTU')=='1':
        from ubuntu.client import exercise
        exercise(PROJECT,request,compose,PASSWORD,find_user)
    print('Testing container persistence and outages…', flush=True)
    compose('up','-d','--no-build','--force-recreate','--wait')
    wait_ready()
    assert request('/api/status')['configured']
    find_user('bob')
    request('/api/me')  # session survives recreation
    assert next(e for e in request('/api/hosts') if e['id']==h['id'])['revision']==2
    request('/api/hosts/'+h['id'],'DELETE')
    request('/api/groups/host-policy','DELETE')
    compose('stop','manager')
    ldap_bind('bob',PASSWORD)  # LDAP independent of manager
    compose('start','manager')
    wait_ready()
    compose('stop','ldap')
    request('/health')
    request('/api/overview',expect=503)
    request('/ready',expect=503)
    compose('start','ldap')
    wait_ready()
    request('/api/overview')
    # Untrusted public PKI must fail against the private directory CA.
    tls_test="import ssl,socket; c=ssl.create_default_context(); c.wrap_socket(socket.create_connection(("+repr(fixture.net['address'])+","+str(fixture.net['port'])+")),server_hostname="+repr(fixture.net['hostname'])+")"
    compose('exec','-T','ldap','python3','-c',"import subprocess,sys; r=subprocess.run([sys.executable,'-c',"+repr(tls_test)+"],capture_output=True); assert r.returncode!=0 and b'CERTIFICATE_VERIFY_FAILED' in r.stderr")
    compose('stop','manager')
    edit_schema="import sqlite3,sys;c=sqlite3.connect('/metadata/forklift.db');c.execute('PRAGMA user_version='+sys.argv[1]);c.close()"
    compose('exec','-T','maintenance','python3','-c',edit_schema,'4')
    compose('start','manager');time.sleep(1)
    logs=compose('logs','--no-color','manager').stdout
    assert b'requires fresh storage' in logs
    ldap_bind('bob',PASSWORD)
    compose('exec','-T','maintenance','python3','-c',edit_schema,'5')
    compose('restart','manager');wait_ready()
    request('/api/logout','POST',{})
    request('/api/me',expect=401)
    for _ in range(20):
        request('/api/login','POST',dict(username='admin',password='bad'),expect=(401,429))
    request('/api/login','POST',dict(username='admin',password='bad'),expect=429)
    print(f'PASS: {fixture.checks} HTTP checks; direct LDAP auth, password reset/disable, administrator revocation, persistence, management/directory outages, TLS trust rejection.')
