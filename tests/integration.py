#!/usr/bin/env python3
"""Real OpenLDAP/HTTP/failure tests in a fresh, isolated Compose project.
Uses the built forklift-manager and forklift-ldap images. Never touches default volumes.
"""
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request
from urllib.error import HTTPError, URLError

os.chdir(Path(__file__).resolve().parents[1])
PROJECT = 'forklift-test-' + secrets.token_hex(4)
with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    PORT = s.getsockname()[1]
URL = f'http://localhost:{PORT}'
ENV = {**os.environ, 'FORKLIFT_PORT': str(PORT), 'FORKLIFT_BIND': '127.0.0.1', 'FORKLIFT_PUBLIC_URL': URL}
PASSWORD = secrets.token_urlsafe(32)
BASE = 'dc=integration,dc=test'
jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = ''
checks = 0

def request(path, method='GET', body=None, expect=200, authenticated=True, origin=URL, use_csrf=True, raw=False):
    global checks
    headers = {'Content-Type': 'application/json', 'Origin': origin}
    if use_csrf:
        headers['X-CSRF-Token'] = csrf
    req = urllib.request.Request(URL + path, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
    try:
        response = (client if authenticated else urllib.request.build_opener()).open(req, timeout=15)
    except HTTPError as e:
        response = e
    with response:
        status = response.code
        data = response.read()
    assert status in (expect if isinstance(expect, tuple) else (expect,)), f'{method} {path}: expected {expect}, got {status}; {data[:300]!r}'
    checks += 1
    return data if raw else json.loads(data)

def compose(*args, input=None):
    return subprocess.run(['docker','compose','-p',PROJECT,'-f','compose.yaml','-f',override.name,*args],env=ENV,check=True,capture_output=True,input=input)

def wait_ready():
    for _ in range(90):
        try:
            request('/ready')
            return
        except (URLError, ConnectionError, AssertionError):
            time.sleep(1)
    raise AssertionError('Stack did not become ready')

def ldap_bind(username, password, success=True):
    code = '''import os, subprocess, sys
r=subprocess.run(['ldapwhoami','-x','-H','ldaps://ldap:636','-D',sys.argv[1],'-y','/dev/stdin'], input=sys.stdin.buffer.read(), capture_output=True, env={**os.environ,'LDAPTLS_CACERT':'/run/secrets/ca.crt'})
sys.exit(r.returncode)
'''
    r = subprocess.run(['docker','compose','-p',PROJECT,'-f','compose.yaml','-f',override.name,'exec','-T','ldap','python3','-c',code,f'uid={username},ou=people,{BASE}'],input=password.encode(),env=ENV,capture_output=True)
    assert (r.returncode == 0) == success, 'Unexpected direct LDAP bind result'

def user(name, **changes):
    return dict(username=name, display_name=name.title(),email='',description='Integration account',shell='/bin/bash',home='/home/'+name,gid=10000,password=PASSWORD,disabled=False,**changes)

def find_user(name):
    return next(u for u in request('/api/overview')['users'] if u['attrs']['uid']==[name])

override = tempfile.NamedTemporaryFile(mode='w',suffix='.yaml',prefix='forklift-tests-',delete=False)
override.write('services:\n  manager:\n    image: forklift-manager:latest\n  ldap:\n    image: forklift-ldap:latest\n')
override.close()
try:
    compose('up','-d','--no-build','--wait')
    wait_ready()
    print('Testing setup, authentication and CRUD…', flush=True)
    assert request('/api/status')['configured'] is False
    request('/api/not-implemented', expect=404)
    request('/api/overview',expect=401,authenticated=False)
    payload=dict(token='wrong',name='Integration',base=BASE,username='admin',password=PASSWORD)
    request('/api/setup','POST',payload,expect=403)
    payload['token']=subprocess.check_output(['docker','run','--rm','-v',str(Path('.secrets').resolve())+':/secrets:ro','alpine:3.22.2','cat','/secrets/bootstrap'],text=True).strip()
    request('/api/setup','POST',payload,origin='https://evil.invalid',expect=403)
    request('/api/setup','POST',payload)
    request('/api/setup','POST',payload,expect=400)
    request('/api/login','POST',dict(username='admin',password='wrong'),expect=401)
    login=request('/api/login','POST',dict(username='admin',password=PASSWORD))
    csrf=login['csrf']
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
    second=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(second_jar))
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
    host_data=dict(name='Test host',hostname='test.integration.test',endpoints=['ldaps://ldap:636'],allowed_groups=['administrators'])
    request('/api/hosts',expect=401,authenticated=False)
    request('/api/hosts','POST',host_data,expect=403,use_csrf=False)
    request('/api/hosts','POST',dict(host_data,endpoints=['ldap://ldap']),expect=400)
    request('/api/hosts','POST',dict(host_data,allowed_groups=[]),expect=400)
    request('/api/hosts','POST',dict(host_data,allowed_groups=['missing']),expect=400)
    h=request('/api/hosts','POST',host_data)
    request('/api/hosts','POST',host_data,expect=400)
    assert len(request('/api/hosts'))==1
    request('/api/hosts/'+h['id'],'PUT',dict(host_data,revision=99),expect=409)
    request('/api/hosts/'+h['id']+'/bundle','POST',dict(revision=1,rotate=False),expect=400)
    request('/api/hosts/'+h['id']+'/bundle','POST',dict(revision=1,rotate=True),expect=403,use_csrf=False)
    import io,tarfile,configparser
    archive=request('/api/hosts/'+h['id']+'/bundle','POST',dict(revision=1,rotate=True),raw=True)
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
        assert tar.getmember('sssd.conf').mode==0o600
        conf=tar.extractfile('sssd.conf').read().decode()
    assert 'ldap_tls_reqcert = demand' in conf and 'cache_credentials = false' in conf
    parsed=configparser.ConfigParser(interpolation=None);parsed.read_string(conf)
    original_password=parsed['domain/forklift']['ldap_default_authtok']
    host_dn=parsed['domain/forklift']['ldap_default_bind_dn']
    assert original_password not in json.dumps(request('/api/overview'))
    rotated=request('/api/hosts/'+h['id']+'/bundle','POST',dict(revision=1,rotate=True),raw=True)
    with tarfile.open(fileobj=io.BytesIO(rotated),mode='r:gz') as tar:
        parsed.read_string(tar.extractfile('sssd.conf').read().decode())
    rotated_password=parsed['domain/forklift']['ldap_default_authtok']
    assert rotated_password!=original_password
    bind_check="import sys,json,os,subprocess; p=json.load(sys.stdin); r=subprocess.run(['ldapwhoami','-x','-H','ldaps://ldap:636','-D',p['dn'],'-y','/dev/stdin'],input=p['password'].encode(),env={**os.environ,'LDAPTLS_CACERT':'/run/secrets/ca.crt'},capture_output=True); assert r.returncode==p['expected']"
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
    print('Testing manager TLS validation with an unrelated trust store…', flush=True)
    original_override = Path(override.name).read_text()
    Path(override.name).write_text(original_override.replace('    image: forklift-manager:latest', '    image: forklift-manager:latest\n    environment:\n      SSL_CERT_FILE: /etc/ssl/certs/ca-certificates.crt'))
    compose('up','-d','--no-build','--force-recreate','--no-deps','manager')
    # Liveness continues, but verified LDAP access must fail in the Rust process.
    for _ in range(30):
        try:
            request('/health')
            break
        except (URLError, ConnectionError):
            time.sleep(1)
    request('/ready', expect=503)
    request('/api/overview', expect=503)
    Path(override.name).write_text(original_override)
    compose('up','-d','--no-build','--force-recreate','--no-deps','manager')
    wait_ready()
    # Certificate validation must reject an untrusted CA, without insecure flags.
    tls_test = "import ssl,socket; c=ssl.create_default_context(); c.wrap_socket(socket.create_connection(('ldap',636)),server_hostname='ldap')"
    r=compose('exec','-T','ldap','python3','-c',"import subprocess,sys; r=subprocess.run([sys.executable,'-c',"+repr(tls_test)+"],capture_output=True); assert r.returncode!=0 and b'CERTIFICATE_VERIFY_FAILED' in r.stderr")
    request('/api/logout','POST',{})
    request('/api/me',expect=401)
    for _ in range(20):
        request('/api/login','POST',dict(username='admin',password='bad'),expect=(401,429))
    request('/api/login','POST',dict(username='admin',password='bad'),expect=429)
    print(f'PASS: {checks} HTTP checks; direct LDAP auth, password reset/disable, administrator revocation, persistence, management/directory outages, TLS trust rejection.')
finally:
    compose('down','--volumes','--remove-orphans')
    Path(override.name).unlink(missing_ok=True)
