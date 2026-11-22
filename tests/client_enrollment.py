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
import socket
import socketserver
import threading
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fixture import Stack, SOURCE, run

CLIENT = Path(os.environ.get('FORKLIFT_CLIENT_BINARY', SOURCE.parent/'forklift-client/target/release/forklift-client')).resolve()
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

        # Milestone 2: inventory success, freshness and DNS outcomes are independent.
        heartbeat_path='/api/client/v1/hosts/'+host_id+'/heartbeat'
        monitoring_path='/api/hosts/'+host_id+'/monitoring'
        sequence=0
        observed=json.loads(json.dumps(saved['identity']))
        observed['hostname']='observed.example.test'
        observed['addresses']=[dict(interface='eth0',address='192.168.1.50'),dict(interface='eth0',address='fd00::50')]
        def reset_report_limit():
            s.compose('exec','-T','maintenance','python3','-c',"import sqlite3,sys;d=sqlite3.connect('/metadata/forklift.db');d.execute('DELETE FROM client_limits WHERE scope=?',('heartbeat:'+sys.stdin.read(),));d.commit()",input=item['id'].encode())
        def report(identity=None, seq=None, expected=200, **fields):
            global sequence
            reset_report_limit()
            if seq is None: sequence+=1;seq=sequence
            body=dict(api_version=1,sequence=seq,interval=300,identity=identity or observed,interfaces=['eth0'])|fields
            return machine(heartbeat_path,token,proof(heartbeat_path,token),body=body,expected=expected)
        def current_host():return next(h for h in r('/api/hosts') if h['id']==host_id)
        foreign_heartbeat='/api/client/v1/hosts/'+'f'*32+'/heartbeat'
        machine(foreign_heartbeat,token,proof(foreign_heartbeat,token),body=dict(api_version=1,sequence=1,interval=300,identity=observed,interfaces=['eth0']),expected=401)
        first_report=report()
        reset_report_limit()
        repeated=dict(api_version=1,sequence=sequence,interval=300,identity=observed,interfaces=['eth0'])
        for _ in range(6):machine(heartbeat_path,token,proof(heartbeat_path,token),body=repeated)
        machine(heartbeat_path,token,proof(heartbeat_path,token),body=repeated,expected=429)
        assert first_report['inventory']=='accepted' and first_report['dns']['state']=='disabled'
        current=current_host()
        assert current['hostname']=='client.example.test' and current['client']['monitoring']['inventory']['hostname']=='observed.example.test'
        assert current['client']['monitoring']['connectivity']=='online'
        same=report(seq=sequence)
        assert same['received_at']==first_report['received_at']
        report(seq=sequence-1,expected=400)
        report(seq=sequence,expected=409,identity=observed|dict(kernel='different'))
        report(expected=422,server_time=9999999999)
        report(identity=observed|dict(addresses=[dict(interface='eth0',address='127.0.0.1')]),expected=400)
        report(identity=observed|dict(addresses=observed['addresses']*2),expected=400)
        r(monitoring_path,authenticated=False,expect=401)
        policy=r(monitoring_path)
        r(monitoring_path,'PUT',dict(revision=policy['revision'],policy=policy['policy']),use_csrf=False,expect=403)
        r(monitoring_path,'PUT',dict(revision=policy['revision']+1,policy=policy['policy']),expect=409)
        def edit_monitor(**changes):
            settings=r(monitoring_path)
            return r(monitoring_path,'PUT',dict(revision=settings['revision'],policy=settings['policy']|changes))
        edit_monitor(offline_after=90)
        assert current_host()['client']['monitoring']['offline_after']==900
        def age_report(seconds):
            code="import json,sqlite3,sys,time;p=json.load(sys.stdin);d=sqlite3.connect('/metadata/forklift.db');m=json.loads(d.execute('SELECT data FROM client_monitoring WHERE host_id=?',(p['id'],)).fetchone()[0]);m['observation']['received_at']=int(time.time())-p['age'];d.execute('UPDATE client_monitoring SET data=? WHERE host_id=?',(json.dumps(m),p['id']));d.commit()"
            s.compose('exec','-T','maintenance','python3','-c',code,input=json.dumps(dict(id=host_id,age=seconds)).encode())
        age_report(1000)
        assert current_host()['client']['monitoring']['connectivity']=='offline'
        cli(first,'status')
        assert current_host()['client']['monitoring']['connectivity']=='offline','An interactive session faked a daemon heartbeat'
        report()
        events=r(monitoring_path)['history']
        assert sum(e['kind']=='offline' for e in events)==1 and sum(e['kind']=='connection_recovered' for e in events)==1
        report()
        assert len(r(monitoring_path)['history'])==len(events),'Unchanged reports duplicated history'
        # Confirm the independent server watcher records a missed heartbeat without a client report.
        age_report(1000)
        for _ in range(170):
            if sum(e['kind']=='offline' for e in r(monitoring_path)['history'])==2:break
            time.sleep(.2)
        else:raise AssertionError('Server did not independently detect missed heartbeats')
        report()
        print('PASS: live inventory, stable inventory hostname, bounded validated reports, idempotent/lower-sequence rejection, server-clock freshness, independent offline detection and deduplicated recovery.',flush=True)

        zone='example.test.';reverse_zone='1.168.192.in-addr.arpa.'
        for body in [dict(name=zone,kind='forward',nameserver='ns1.example.test.',nameserver_address='192.168.1.2',ttl=300),dict(name='192.168.1.0/24',kind='reverse4',nameserver='ns1.example.test.',ttl=300),dict(name='d.f.ip6.arpa.',kind='reverse6',nameserver='ns1.example.test.',ttl=300)]:r('/api/dns/zones','POST',body)
        r('/api/dns/zones/'+zone+'/records','POST',dict(name='client',type='A',values=['192.168.1.99'],ttl=600,expected_revision=None))
        def configure_dns(address, apply=True, **changes):
            host=current_host()
            return r('/api/hosts/'+host_id,'PUT',{k:host[k] for k in ['name','hostname','endpoints','allowed_groups','revision']}|dict(dns_apply=apply,dns=dict(zone=zone,fqdn='client',ipv4=address,ipv6='fd00::50',reverse=True)|changes))
        assert configure_dns('192.168.1.50')['dns_status']['state']=='applied'
        browser('monitor')
        assert r(monitoring_path)['policy']['dns_updates']
        observed['addresses']=[dict(interface='eth0',address='192.168.1.51'),dict(interface='eth0',address='fd00::51')]
        result=report()
        assert result['dns']['state']=='applied',result
        def dig(name,kind='A',value=None,absent=False):
            output=run(['docker','run','--rm','--network','host','--entrypoint','dig','forklift-dns:latest','@127.0.0.1','-p',s.env['FORKLIFT_DNS_PORT'],name,kind,'+time=1','+tries=1']).stdout.decode()
            assert 'status: NOERROR' in output or absent and 'status: NXDOMAIN' in output,output
            if value: assert (value not in output) if absent else (value in output),output
            return output
        answers=dig('client.example.test.',value='192.168.1.51');assert '192.168.1.99' in answers and '192.168.1.50' not in answers
        dig('client.example.test.','AAAA','fd00::51');dig('51.'+reverse_zone,'PTR','client.example.test.');dig('50.'+reverse_zone,'PTR','client.example.test.',absent=True)
        ptr='1.5.'+'0.'*28+'d.f.ip6.arpa.';dig(ptr,'PTR','client.example.test.')
        ambiguous=observed|dict(addresses=observed['addresses']+[dict(interface='eth0',address='192.168.1.52')])
        result=report(identity=ambiguous);assert result['inventory']=='accepted' and result['dns']['state']=='needs_retry'
        assert current_host()['dns']['ipv4']=='192.168.1.51'
        report()
        s.compose('stop','dns')
        observed['addresses']=[dict(interface='eth0',address='192.168.1.52'),dict(interface='eth0',address='fd00::52')]
        result=report();assert result['inventory']=='accepted' and result['dns']['state']=='needs_retry'
        assert current_host()['client']['monitoring']['connectivity']=='online'
        s.login() # LDAP login remains independent of DNS availability.
        s.compose('start','dns')
        for _ in range(60):
            if r('/api/dns')['available']:break
            time.sleep(.2)
        result=report();assert result['dns']['state']=='applied',result
        assert '192.168.1.99' in dig('client.example.test.',value='192.168.1.52')
        # Recover an interrupted real native transfer of one journaled record.
        native_code="import http.client,json,socket,sys;from pathlib import Path;p=json.load(sys.stdin)\nclass C(http.client.HTTPConnection):\n def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.connect('/run/dns-control/dns.sock')\nc=C('localhost');c.request('PATCH','/api/v1/servers/localhost/zones/'+p['zone'],body=json.dumps(p['body']),headers={'X-API-Key':Path('/run/dns-secrets/api-key').read_text().strip(),'Content-Type':'application/json'});r=c.getresponse();assert r.status==204,(r.status,r.read())"
        s.compose('exec','-T','dns','python3','-c',native_code,input=json.dumps(dict(zone=reverse_zone,body=dict(rrsets=[dict(name='52.'+reverse_zone,type='PTR',changetype='DELETE')]))).encode())
        seed="import json,sqlite3,sys;p=json.load(sys.stdin);d=sqlite3.connect('/metadata/forklift.db');m=json.loads(d.execute('SELECT data FROM host_dns WHERE id=?',(p['id'],)).fetchone()[0]);plans=[json.loads(row[0]) for row in d.execute('SELECT data FROM dns_changes ORDER BY rowid DESC')];c=next(c for c in plans if (c.get('host') or {}).get('host_id')==p['id'] and any(step['name']==p['owner'] and step['rr_type']=='PTR' for step in c['steps']));m['status']['operation_id']=c['id'];m['status']['state']='pending';d.execute('UPDATE host_dns SET data=? WHERE id=?',(json.dumps(m),p['id']));d.execute(\"UPDATE dns_changes SET status='pending',error=NULL WHERE id=?\",(c['id'],));d.commit()"
        s.compose('exec','-T','maintenance','python3','-c',seed,input=json.dumps(dict(id=host_id,owner='52.'+reverse_zone)).encode())
        s.compose('restart','manager');s.wait()
        result=report();assert result['dns']['state']=='applied',result
        dig('52.'+reverse_zone,'PTR','client.example.test.')
        assert current_host()['client']['monitoring']['inventory']['hostname']=='observed.example.test'
        # A deliberately deferred administrator edit must never be applied or overwritten by a heartbeat.
        deferred=configure_dns('192.168.1.54',apply=False,ipv6='fd00::52')
        result=report();assert result['dns']['state']=='needs_retry',result
        assert current_host()['dns']['ipv4']=='192.168.1.54'
        dig('client.example.test.',value='192.168.1.52');dig('client.example.test.',value='192.168.1.54',absent=True)
        configure_dns('192.168.1.52',ipv6='fd00::52')
        # A manual edit relinquishes ownership. An enrolled client must not reclaim it.
        old=next(v for v in r('/api/dns/zones/'+zone)['rrsets'] if v['name']=='client.example.test.' and v['type']=='A')
        r('/api/dns/zones/'+zone+'/records','POST',dict(name='client',type='A',values=['192.168.1.99','192.168.1.52'],ttl=600,expected_revision=old['revision']))
        observed['addresses']=[dict(interface='eth0',address='192.168.1.53'),dict(interface='eth0',address='fd00::53')]
        result=report();assert result['dns']['state']=='needs_retry' and current_host()['dns']['ipv4']=='192.168.1.52'
        dig('client.example.test.',value='192.168.1.53',absent=True)
        edit_monitor(dns_updates=False)
        result=report();assert result['dns']['state']=='disabled'
        # The native daemon resumes above the last test-submitted monotonic sequence.
        code="import json,sys;from pathlib import Path;p=Path(sys.argv[1]);d=json.loads(p.read_text());d['report_sequence']=int(sys.argv[2]);p.write_text(json.dumps(d))"
        run(['sudo','-n','python3','-c',code,str(first/'state.json'),str(sequence)])
        print('PASS: WebUI monitoring policy, actual PowerDNS A/AAAA/PTR updates, preservation of unrelated values, ambiguous-address refusal, independent LDAP/inventory during DNS outage, retry and externally changed ownership protection.',flush=True)

        # Exercise the actual native daemon end to end in private network/UTS namespaces.
        # Raw TLS is relayed over a private Unix socket; neither trust nor DPoP targets change.
        proxy_path=s.root/'client-network.sock'
        class Relay(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    with socket.create_connection(('127.0.0.1',int(s.url.rsplit(':',1)[1])),timeout=15) as remote:
                        self.request.settimeout(15)
                        while True:
                            ready,_,_=select.select([self.request,remote],[],[],1)
                            for source in ready:
                                data=source.recv(16384)
                                if not data:return
                                (remote if source is self.request else self.request).sendall(data)
                except OSError:pass
        class RelayServer(socketserver.ThreadingUnixStreamServer):daemon_threads=True
        relay=RelayServer(str(proxy_path),Relay)
        relay_thread=threading.Thread(target=relay.serve_forever,daemon=True);relay_thread.start()
        try:
            # A legacy 0.1 state lacks optional monitoring fields. Read defaults without reenrollment.
            code="import json,sys;from pathlib import Path;p=Path(sys.argv[1]);d=json.loads(p.read_text());d.pop('inventory',None);d.pop('inventory_at',None);d.pop('include_interfaces',None);d.pop('last_report',None);d['hostname_override']=None;p.write_text(json.dumps(d))"
            run(['sudo','-n','python3','-c',code,str(first/'state.json')])
            network_proc=subprocess.Popen(['sudo','-n','unshare','--net','--uts','--','python3',str(SOURCE/'tests/client_network_fixture.py'),str(CLIENT),str(first),str(proxy_path),s.url.rsplit(':',1)[1]],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
            processes.append(network_proc)
            for _ in range(230):
                live=current_host()['client']['monitoring']['inventory']
                if live['hostname']=='network-two.example.test' and any(a['interface']=='fltest0' and a['address']=='192.168.1.61' for a in live['addresses']):break
                if network_proc.poll() is not None:raise AssertionError('Isolated native network fixture failed: '+network_proc.stderr.read()[-1000:])
                time.sleep(.2)
            else:raise AssertionError('Netlink change did not reach Forklift before the 300-second periodic heartbeat')
            assert current_host()['hostname']=='client.example.test'
            assert state(first)['access_token']==token and state(first)['last_report']['inventory']=='accepted'
            stop(network_proc)
        finally:relay.shutdown();relay.server_close()
        print('PASS: actual native daemon reports network/hostname changes through verified HTTPS before its periodic heartbeat, using isolated namespaces with unchanged host networking and stable credentials.',flush=True)

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
