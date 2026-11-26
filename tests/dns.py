#!/usr/bin/env python3
"""Real PowerDNS REST, UDP/TCP responses, persistence and LDAP outage isolation."""
import hashlib,json,secrets,time
from fixture import Stack,run

with Stack() as s:
    r=s.request
    s.net = s.network()
    setup = dict(
        token=s.bootstrap, name='Integration', base='dc=integration,dc=test',
        username='admin', password=s.password, network=s.net, public_url=s.url,
    )
    s.compose('stop', 'dns')
    failure = r('/api/setup', 'POST', setup, expect=503)
    assert 'DNS setup failed' in failure['error'], failure
    assert not r('/api/status')['configured']
    assert not r('/api/setup/inspect', 'POST', dict(token=s.bootstrap))['initialized']
    s.compose('up', '-d', '--no-build', '--wait', 'dns')
    r('/api/setup', 'POST', setup)
    s.login()
    print('PASS: fresh setup reports unavailable DNS, leaves LDAP uninitialized and succeeds after DNS returns.', flush=True)
    dns_port=s.env['FORKLIFT_DNS_PORT']
    def get(name='example.test.'):
        return r('/api/dns/zones/'+name)
    def record(name,kind,values,zone='example.test.',**options):
        data=get(zone)
        old=next((v for v in data['rrsets'] if v['name']==(name if name.endswith('.') else zone if name=='@' else name+'.'+zone) and v['type']==kind),None)
        body=dict(name=name,type=kind,ttl=300,values=values,expected_revision=old['revision'] if old else None)|options
        result=r('/api/dns/zones/'+zone+'/records','POST',body)
        assert result['status']=='completed',result
        return result
    def dig(name,kind,contains=None,tcp=False,rcode='NOERROR',aa=True):
        # Independent DNS client queries the HOST published socket, not just the HTTP API.
        code="import subprocess,sys;args=['dig','@127.0.0.1','-p',sys.argv[1],sys.argv[2],sys.argv[3],'+time=1','+tries=1'];args+=['+tcp'] if sys.argv[4]=='1' else [];r=subprocess.run(args,capture_output=True);sys.stdout.buffer.write(r.stdout);sys.exit(r.returncode)"
        result=run(['docker','run','--rm','--network','host','--entrypoint','python3','forklift-dns:latest','-c',code,dns_port,name,kind,'1' if tcp else '0']).stdout.decode()
        assert 'status: '+rcode in result,(name,kind,result)
        if rcode=='NOERROR' and aa:assert 'aa' in result.split('flags:',1)[1].split(';',1)[0].split(),(name,kind,result)
        if contains is not None:assert contains in result,(name,kind,result)
        return result
    def native(method,path,body=None,key=None):
        code="import http.client,json,socket,sys;from pathlib import Path;p=json.load(sys.stdin)\nclass C(http.client.HTTPConnection):\n def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.connect('/run/dns-control/dns.sock')\nc=C('localhost');c.request(p['method'],p['path'],body=json.dumps(p['body']).encode() if p['body'] is not None else None,headers={'X-API-Key':p.get('key') or Path('/run/dns-secrets/api-key').read_text().strip(),'Content-Type':'application/json'});r=c.getresponse();print(json.dumps({'status':r.status,'body':r.read().decode()}))"
        return json.loads(s.compose('exec','-T','dns','python3','-c',code,input=json.dumps(dict(method=method,path='/api/v1/servers/localhost'+path,body=body,key=key)).encode()).stdout)
    r('/api/dns',authenticated=False,expect=401)
    assert r('/api/dns')['available']
    base=dict(name='example.test',kind='forward',nameserver='ns1.example.test.',nameserver_address='192.168.1.2',ttl=300)
    r('/api/dns/zones','POST',base,use_csrf=False,expect=403)
    r('/api/dns/zones','POST',base,authenticated=False,expect=401)
    r('/api/dns/zones','POST',dict(base,name='../../api'),expect=400)
    r('/api/dns/zones','POST',base)
    r('/api/dns/zones','POST',base,expect=400)
    record_path = '/api/dns/zones/example.test./records'
    submitted = dict(
        request_id=secrets.token_hex(16), name='duplicate-check', type='A',
        ttl=300, values=['192.168.1.19'],
    )
    original = r(record_path, 'POST', submitted)
    assert original['status'] == 'completed'
    serial = get()['serial']
    assert r(record_path, 'POST', submitted) == original
    assert get()['serial'] == serial
    r(record_path, 'POST', dict(submitted, values=['192.168.1.20']), expect=409)
    r(record_path, 'POST', dict(submitted, request_id='invalid'), expect=400)
    mark_interrupted = (
        "import sqlite3,sys; db=sqlite3.connect('/metadata/forklift.db'); "
        "db.execute(\"UPDATE dns_changes SET status='pending' WHERE id=?\", [sys.argv[1]]); db.commit()"
    )
    s.compose('exec', '-T', 'maintenance', 'python3', '-c', mark_interrupted, original['id'])
    assert r(record_path, 'POST', submitted) == original
    assert get()['serial'] == serial
    record('duplicate-check', 'A', [], delete=True, acknowledge=True)
    assert r(record_path, 'POST', submitted) == original
    dig('duplicate-check.example.test.', 'A', rcode='NXDOMAIN')
    print('PASS: duplicate DNS submissions retain their result and serial, resume after interruption, and preserve later deletion.', flush=True)
    reverse=dict(name='192.168.1.0/24',kind='reverse4',nameserver='ns1.example.test.',ttl=300)
    r('/api/dns/zones','POST',dict(reverse,name='192.168.1.1/24'),expect=400)
    r('/api/dns/zones','POST',dict(reverse,name='8.8.8.0/24'),expect=400)
    r('/api/dns/zones','POST',reverse)
    r('/api/dns/zones','POST',dict(reverse,name='d.f.ip6.arpa.',kind='reverse6'))
    record('monolith','A',['192.168.1.50'],auto_ptr=True)
    record('monolith','AAAA',['fd00::10'],auto_ptr=True)
    dig('monolith.example.test.','A','192.168.1.50')
    dig('monolith.example.test.','AAAA','fd00::10',tcp=True)
    dig('50.1.168.192.in-addr.arpa.','PTR','monolith.example.test.')
    dig('0.1.'+'0.'*28+'d.f.ip6.arpa.','PTR','monolith.example.test.')
    assert next(v for v in get()['rrsets'] if v['name']=='monolith.example.test.' and v['type']=='A')['auto_ptr']
    print('PASS: mandatory DNS initialization, authorizations, forward/private reverse zones, real UDP/TCP A/AAAA answers and matching IPv4/IPv6 PTR.',flush=True)
    before=get()['serial']
    for owner,kind,value in [('alias','CNAME','monolith.example.test.'),('@','MX','10 mail.example.test.'),('_ldap._tcp','SRV','0 5 389 monolith.example.test.'),('@','TXT','"v=spf1 -all"'),('delegated','NS','ns1.example.test.')]:
        record(owner,kind,[value]);dig((owner+'.' if owner!='@' else '')+'example.test.',kind,value,aa=owner!='delegated')
    assert get()['serial']>before
    record('escaped','TXT',['"\\104ello"'])
    dig('escaped.example.test.','TXT','"hello"')
    r('/api/dns/zones/example.test./records','POST',dict(name='duplicate-txt',type='TXT',ttl=300,values=['"hello"','"\\104ello"']),expect=400)

    record('@','NS',['ns1.example.test.','ns2.example.test.'])
    dig('example.test.','NS','ns2.example.test.')
    old=next(v for v in get()['rrsets'] if v['name']=='monolith.example.test.' and v['type']=='A')
    record('monolith','A',['192.168.1.11','192.168.1.12'],auto_ptr=True)
    r('/api/dns/zones/example.test./records','POST',dict(name='monolith',type='A',ttl=300,values=['192.168.1.99'],expected_revision=old['revision']),expect=409)
    dig('11.1.168.192.in-addr.arpa.','PTR','monolith.example.test.')
    dig('50.1.168.192.in-addr.arpa.','PTR',rcode='NXDOMAIN')
    # Explicit PTR edits relinquish automatic ownership; later forward changes preserve them.
    record('11','PTR',['manual.example.test.','monolith.example.test.'],zone='1.168.192.in-addr.arpa.')
    record('monolith','A',['192.168.1.12'],auto_ptr=True)
    dig('11.1.168.192.in-addr.arpa.','PTR','manual.example.test.')
    dig('11.1.168.192.in-addr.arpa.','PTR','monolith.example.test.')
    invalid=dict(name='alias',type='A',ttl=300,values=['192.168.1.50'])
    r('/api/dns/zones/example.test./records','POST',invalid,expect=400)
    r('/api/dns/zones/example.test./records','POST',dict(invalid,name='@',type='CNAME',values=['monolith.example.test.']),expect=400)
    r('/api/dns/zones/example.test./records','POST',dict(invalid,name='bad',values=['192.168.1.50','192.168.1.50']),expect=400)
    r('/api/dns/zones/example.test./records','POST',dict(invalid,name='outside.example.'),expect=400)
    r('/api/dns/zones/example.test./records','POST',dict(invalid,name='no-reverse',values=['192.168.2.1'],auto_ptr=True),expect=400)
    record('alias','CNAME',[],delete=True,acknowledge=True)
    dig('alias.example.test.','CNAME',rcode='NXDOMAIN')
    data=get();soa=next(v for v in data['rrsets'] if v['type']=='SOA')
    r('/api/dns/zones/example.test.','PUT',dict(primary='ns1.example.test.',contact='dnsadmin.example.test.',refresh=7200,retry=1800,expire=604800,minimum=300,ttl=600,expected_revision=soa['revision']))
    dig('example.test.','SOA','dnsadmin.example.test.')
    exported,_=r('/api/dns/zones/example.test./export',raw=True)
    assert b'monolith' in exported and b'192.168.1.12' in exported
    r('/api/dns/zones/example.test.','DELETE',dict(acknowledge=False,confirm_name='example.test.',expected_revision=get()['revision']),expect=400)
    r('/api/dns/zones/example.test.','DELETE',dict(acknowledge=True,confirm_name='wrong.',expected_revision=get()['revision']),expect=400)
    r('/api/dns/zones/example.test.','DELETE',dict(acknowledge=True,confirm_name='example.test.',expected_revision='stale'),expect=409)
    axfr=run(['docker','run','--rm','--network','host','--entrypoint','dig','forklift-dns:latest','@127.0.0.1','-p',dns_port,'example.test.','AXFR'],check=False)
    assert b'Transfer failed' in axfr.stdout or b'failed' in axfr.stderr.lower()
    assert native('GET','/zones',key='invalid')['status']==401
    # The native DNS UPDATE protocol is disabled, independently of WebUI authorization.
    update=run(['docker','run','--rm','-i','--network','host','--entrypoint','nsupdate','forklift-dns:latest'],data=('server 127.0.0.1 '+dns_port+'\nzone example.test.\nupdate add unauthorized.example.test. 300 A 192.168.1.250\nsend\n').encode(),check=False)
    assert update.returncode and any(code in update.stderr+update.stdout for code in [b'REFUSED',b'NOTIMP',b'NOTAUTH'])
    dig('unauthorized.example.test.','A',rcode='NXDOMAIN')
    foreign=native('POST','/zones',dict(name='foreign.test.',kind='Native',account='other-admin',nameservers=['ns1.example.test.']))
    assert foreign['status']==201
    foreign_zone=get('foreign.test.');assert not foreign_zone['managed']
    r('/api/dns/zones/foreign.test./records','POST',dict(name='host',type='A',ttl=300,values=['192.168.1.1']),expect=400)
    r('/api/dns/zones/foreign.test.','DELETE',dict(acknowledge=True,confirm_name='foreign.test.',expected_revision=foreign_zone['revision']),expect=400)
    assert native('DELETE','/zones/foreign.test.')['status']==204

    direct="from supervisor import native;assert native('GET','/api/v1/servers/localhost/zones',key='invalid')[0]==401"
    s.compose('exec','-T','dns','python3','-c',direct)
    bindings=json.loads(run(['docker','inspect',s.compose('ps','-q','dns').stdout.decode().strip()]).stdout)[0]['HostConfig']['PortBindings']
    assert '8081/tcp' not in bindings

    old_key=s.compose('exec','-T','dns','cat','/run/dns-secrets/api-key').stdout.decode().strip()
    r('/api/dns/rotate','POST',dict(acknowledge=True))
    assert native('GET','/zones',key=old_key)['status']==401
    assert old_key not in json.dumps(r('/api/dns'))
    dig('monolith.example.test.','A','192.168.1.12')
    print('PASS: CNAME/MX/TXT/SRV/NS record sets, serials, revisions, validation, PTR ownership, deletion safeguards, export, refused transfers and API-key rotation.',flush=True)
    # Seed the durable state of a process interrupted after its first actual DNS write.
    record('recover','A',['192.168.1.33'])
    rr=next(v for v in get()['rrsets'] if v['name']=='recover.example.test.' and v['type']=='A')
    rr.pop('revision');rr.pop('auto_ptr',None)
    operation=secrets.token_hex(16)
    change=dict(id=operation,key='example.test./recover.example.test./A',links=[],warnings=[],clear_ptr=None,steps=[dict(zone='example.test.',name='recover.example.test.',rr_type='A',before=None,after=rr),dict(zone='1.168.192.in-addr.arpa.',name='33.1.168.192.in-addr.arpa.',rr_type='PTR',before=None,after=dict(name='33.1.168.192.in-addr.arpa.',type='PTR',ttl=300,records=[dict(content='recover.example.test.',disabled=False)],comments=[]))])
    seed="import json,sqlite3,sys,time;p=json.load(sys.stdin);d=sqlite3.connect('/metadata/forklift.db');d.execute('INSERT INTO dns_changes VALUES(?,?,?,?,?)',(p['id'],int(time.time()),json.dumps(p),'pending',None));d.commit()"
    s.compose('exec','-T','maintenance','python3','-c',seed,input=json.dumps(change).encode())
    s.compose('stop','dns')
    assert not r('/api/dns')['available']
    assert r('/api/dns/changes/'+operation+'/retry','POST',{})['status']=='needs_retry'
    s.request('/api/overview');s.request('/ready');s.bind('admin')
    s.compose('start','dns')
    for _ in range(30):
        if r('/api/dns')['available']:break
        time.sleep(.3)
    assert r('/api/dns/changes/'+operation+'/retry','POST',{})['status']=='completed'
    dig('33.1.168.192.in-addr.arpa.','PTR','recover.example.test.')
    # An unexpected native-process exit restarts the container without losing SQLite state.
    s.compose('exec','-T','dns','python3','-c',"import os,signal;from pathlib import Path;pid=next(int(p.name) for p in Path('/proc').iterdir() if p.name.isdigit() and (p/'comm').read_text().strip()=='pdns_server');os.kill(pid,signal.SIGKILL)")
    time.sleep(1.2)
    for _ in range(60):
        if r('/api/dns')['available']:break
        time.sleep(.3)
    else:raise AssertionError('PowerDNS did not recover after native process failure')
    dig('monolith.example.test.','A','192.168.1.12')
    s.compose('up','-d','--no-build','--force-recreate','--wait')
    s.wait();r('/api/me');dig('monolith.example.test.','A','192.168.1.12')
    assert r(record_path, 'POST', submitted) == original
    dig('duplicate-check.example.test.', 'A', rcode='NXDOMAIN')
    # DNS has no runtime dependency on Forklift or LDAP.
    s.compose('stop','manager','ldap');dig('monolith.example.test.','A','192.168.1.12',tcp=True)
    s.compose('start','ldap','manager');s.wait()
    data=get('1.168.192.in-addr.arpa.')
    r('/api/dns/zones/1.168.192.in-addr.arpa.','DELETE',dict(acknowledge=True,confirm_name=data['name'],expected_revision=data['revision']))
    assert all(v['name']!='1.168.192.in-addr.arpa.' for v in r('/api/dns')['zones'])
    record('monolith','A',['192.168.1.13'])
    dig('monolith.example.test.','A','192.168.1.13')
    print('PASS: persistent data/session recreation, partial-change recovery through real REST/DNS, LDAP with DNS stopped, DNS with manager/LDAP stopped, and confirmed zone deletion.',flush=True)
