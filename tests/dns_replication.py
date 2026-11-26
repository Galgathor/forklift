#!/usr/bin/env python3
"""Independent PowerDNS SQLite nodes, HTTPS enrollment, TSIG and real DNS failover."""
import base64
import io
import tarfile
import ipaddress
import ssl
import urllib.request
import json
import os
import time
from fixture import Stack, SOURCE, port, run

stack = Stack()
with stack as s:
    s.setup()
    r = s.request
    # Independent peers on an isolated Docker network. Do not relax the host firewall
    # to make bridge-to-host notifications or management traffic work in a fixture.
    network_name = s.project+'_default'
    network = json.loads(run(['docker', 'network', 'inspect', network_name]).stdout)[0]
    subnet = ipaddress.IPv4Network(network['IPAM']['Config'][0]['Subnet'])
    proxy_address = str(subnet.network_address+100)
    address = str(subnet.network_address+101)
    primary_container = s.compose('ps', '-q', 'dns').stdout.decode().strip()
    primary_address = json.loads(run(['docker', 'inspect', primary_container]).stdout)[0]['NetworkSettings']['Networks'][network_name]['IPAddress']
    primary_port = 5353
    def openssl(*args):
        return run(['openssl', *args], cwd=s.root)
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=DNS test CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', 'ca.key', '-out', 'ca.crt')
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=DNS test manager', '-keyout', 'server.key', '-out', 'server.csr')
    (s.root/'extensions').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:'+proxy_address+'\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    openssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-set_serial', '2', '-days', '2', '-extfile', 'extensions', '-out', 'server.crt')
    upstream_name = s.project+'-dns-upstream'
    proxy_name = s.project+'-dns-proxy'
    run(['docker', 'run', '-d', '--name', proxy_name, '--network', network_name, '--ip', proxy_address,
         '--user', str(os.getuid())+':'+str(os.getgid()), '-e', 'PROXY_PORT=8443', '-e', 'MANAGER_HOST=manager', '-e', 'MANAGER_PORT=8080',
         '-v', str(s.root)+':/fixture:ro', '-v', str(SOURCE/'tests/tls_proxy.py')+':/proxy.py:ro', '--entrypoint', 'python3', 'forklift-ldap:latest', '/proxy.py'])
    try:
        url = 'https://'+proxy_address+':8443'
        r('/api/settings/public-url', 'POST', dict(url=url, acknowledge=True))
        s.url = url
        s.context = ssl.create_default_context(cafile=str(s.root/'ca.crt'))
        s.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(s.jar), urllib.request.HTTPSHandler(context=s.context))
        s.wait('/health'); s.login()
        secondary_port, management_port = port(), port()
        zone = 'example.test.'
        reverse = '1.168.192.in-addr.arpa.'
        r('/api/dns/zones', 'POST', dict(name=zone, kind='forward', nameserver='ns1.example.test.', nameserver_address='192.168.1.2', ttl=300))
        r('/api/dns/zones', 'POST', dict(name='192.168.1.0/24', kind='reverse4', nameserver='ns1.example.test.', ttl=300))
        def record(owner, values):
            data = r('/api/dns/zones/'+zone)
            old = next((v for v in data['rrsets'] if v['name']==owner+'.'+zone and v['type']=='A'), None)
            result = r('/api/dns/zones/'+zone+'/records', 'POST', dict(name=owner, type='A', values=values, ttl=300, expected_revision=old['revision'] if old else None, auto_ptr=True))
            assert result['status']=='completed', result
        record('server', ['192.168.1.50'])
        primary = dict(address=primary_address, dns_port=primary_port, acknowledge=True)
        r('/api/dns/primary', 'PUT', primary, authenticated=False, expect=401)
        r('/api/dns/primary', 'PUT', primary, use_csrf=False, expect=403)
        r('/api/dns/primary', 'PUT', dict(primary, address='127.0.0.1'), expect=400)
        r('/api/dns/primary', 'PUT', primary)
        draft = dict(name='Secondary DNS', address=address, dns_port=secondary_port, control_port=management_port, zones=[zone, reverse])
        r('/api/dns/servers', 'POST', draft, use_csrf=False, expect=403)
        r('/api/dns/servers', 'POST', dict(draft, dns_port=management_port), expect=400)
        r('/api/dns/servers', 'POST', dict(draft, zones=['foreign.test.']), expect=404)
        node = r('/api/dns/servers', 'POST', draft)
        path = '/api/dns/servers/'+node['id']
        r(path+'/deployment', 'POST', dict(acknowledge=False), expect=400)
        r(path+'/deployment', 'POST', dict(acknowledge=True, manager_ca='-----BEGIN PRIVATE KEY-----'), expect=400)
        old = r(path+'/deployment', 'POST', dict(acknowledge=True))
        joined = r(path+'/deployment', 'POST', dict(acknowledge=True, manager_ca=(s.root/'ca.crt').read_text()))
        decode = lambda value: json.loads(base64.b64decode(value.partition('=')[2], validate=True))
        envelope = decode(joined['join_config'])
        assert envelope['enrollment']['token'] != decode(old['join_config'])['enrollment']['token']
        assert joined['expires_at'] <= int(time.time())+900
        project = s.project+'-dns-secondary'
        override = s.root/'secondary-network.yaml'
        override.write_text('services:\n  dns-secondary:\n    network_mode: !reset null\n    networks:\n      default:\n        ipv4_address: '+address+'\nnetworks:\n  default:\n    external: true\n    name: '+network_name+'\n')
        old_source=s.root/'phase3';old_source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(run(['git','archive','e9a4b24'],cwd=SOURCE).stdout)) as archive:
            archive.extractall(old_source,filter='data')
        old_image=project+'-phase3'
        run(['docker','build','-t',old_image,'-f','docker/powerdns/Dockerfile','.'],cwd=old_source)
        image_override=s.root/'secondary-image.yaml'
        image_override.write_text('services:\n  dns-secondary:\n    image: '+old_image+'\n')
        env = {**os.environ, 'FORKLIFT_DNS_JOIN': joined['join_config'].partition('=')[2]}
        def secondary(*args, check=True, input=None):
            return run(['docker', 'compose', '-p', project, '-f', str(SOURCE/'deploy/dns-secondary/compose.yaml'), '-f', str(override), '-f', str(image_override), *args], env=env, check=check, data=input)
        second_address = str(subnet.network_address+102)
        override2 = s.root/'secondary2-network.yaml'
        override2.write_text(override.read_text().replace(address, second_address))
        env2 = {**os.environ, 'FORKLIFT_DNS_JOIN': ''}
        def second(*args, check=True):
            return run(['docker', 'compose', '-p', project+'-second', '-f', str(SOURCE/'deploy/dns-secondary/compose.yaml'), '-f', str(override2), *args], env=env2, check=check)
        def configure(envelope):
            env['FORKLIFT_DNS_JOIN'] = base64.b64encode(json.dumps(envelope).encode()).decode()
        def public_query(name, kind='A', expected=None, tcp=False, dns_port=secondary_port, dns_address=None, status='NOERROR', authoritative=True):
            result = run(['docker', 'run', '--rm', '--network', 'host', '--entrypoint', 'dig', 'forklift-dns:latest', '@'+(dns_address or (primary_address if dns_port==primary_port else address)),
                          '-p', str(dns_port), name, kind, '+time=1', '+tries=1', '+nocookie']+(['+tcp'] if tcp else []), check=False)
            text = result.stdout.decode()
            if kind=='AXFR':
                assert 'Transfer failed' in text or result.returncode, text
            else:
                assert 'status: '+status in text, text
                if authoritative:
                    assert 'aa' in text.split('flags:', 1)[1].split(';', 1)[0].split(), text
                if expected:
                    assert expected in text, text
            return text
        def synced(target=path):
            for _ in range(70):
                node = r(target+'/check', 'POST', {})
                if node['report']['state']=='synchronized':
                    assert node['last_sync_at'] and all(z['synchronized'] for z in node['report']['zones'])
                    return node
                time.sleep(.5)
            raise AssertionError('DNS zones did not synchronize: '+json.dumps(node))
        def metadata_update(expression):
            s.compose('exec', '-T', 'maintenance', 'python3', '-c', "import json,sqlite3,sys;d=sqlite3.connect('/metadata/forklift.db');n=json.loads(d.execute('SELECT data FROM dns_servers WHERE id=?',(sys.argv[1],)).fetchone()[0]);"+expression+";d.execute('UPDATE dns_servers SET data=? WHERE id=?',(json.dumps(n),sys.argv[1]));d.commit()", node['id'])
        denied_transfer="""import json,subprocess,tempfile,sys
from pathlib import Path
p=json.loads(Path('/dns/secondary.json').read_text())
with tempfile.NamedTemporaryFile(mode='w') as key:
 key.write('key "'+p['tsig_name']+'" { algorithm hmac-sha256; secret "'+p['tsig_key']+'"; };');key.flush()
 r=subprocess.run(['dig','-k',key.name,'@'+sys.argv[1],'-p',sys.argv[2],sys.argv[3],'AXFR','+time=1','+tries=1'],capture_output=True)
 assert r.returncode or any(v in r.stdout+r.stderr for v in [b'Transfer failed',b'BADKEY',b'NOTAUTH']), 'Revoked transfer credential accepted'
"""
        try:
            expired = json.loads(json.dumps(envelope)); expired['enrollment']['expires_at'] = int(time.time())-1
            configure(expired)
            failed = secondary('run', '--rm', '-T', 'dns-secondary', check=False)
            assert failed.returncode and b'DNS enrollment failed' in failed.stderr
            wrong = json.loads(json.dumps(envelope)); wrong['manager_ca'] = s.compose('exec', '-T', 'ldap', 'cat', '/run/secrets/ca.crt').stdout.decode()
            configure(wrong)
            failed = secondary('run', '--rm', '-T', 'dns-secondary', check=False)
            assert failed.returncode and envelope['enrollment']['token'].encode() not in failed.stderr
            cert = run(['docker', 'run', '--rm', '--network', 'none', '-v', project+'_dns_secondary:/dns:ro', '--entrypoint', 'cat', 'forklift-dns:latest', '/dns/server.crt']).stdout.decode()
            r(path+'/enroll', 'POST', dict(token=decode(old['join_config'])['enrollment']['token'], certificate=cert), authenticated=False, expect=403)
            metadata_update("n['expires_at']=0")
            r(path+'/enroll', 'POST', dict(token=envelope['enrollment']['token'], certificate=cert), authenticated=False, expect=403)
            joined = r(path+'/deployment', 'POST', dict(acknowledge=True, manager_ca=(s.root/'ca.crt').read_text()))
            envelope = decode(joined['join_config'])
            s.compose('exec', '-T', 'maintenance', 'python3', '-c', "import sys;from pathlib import Path;s=sys.stdin.buffer.read();assert all(s not in p.read_bytes() for p in Path('/metadata').glob('forklift.db*'))", input=envelope['enrollment']['token'].encode())
            r(path+'/enroll', 'POST', dict(token=envelope['enrollment']['token'], certificate=(s.root/'ca.crt').read_text()), authenticated=False, expect=400)
            configure(envelope)
            secondary('up', '-d', '--no-build', '--wait')
            node = synced()
            assert all(z['kind']=='Primary' for z in r('/api/dns')['zones'])
            r(path+'/enroll', 'POST', dict(token=envelope['enrollment']['token'], certificate=cert), authenticated=False, expect=403)
            r(path+'/deployment', 'POST', dict(acknowledge=True), expect=400)
            r(path+'/check', 'POST', {}, use_csrf=False, expect=403)
            public_query('server.example.test.', expected='192.168.1.50')
            public_query('50.'+reverse, 'PTR', 'server.example.test.', tcp=True)
            public_query(zone, 'AXFR', dns_port=primary_port)
            public_query(zone, 'AXFR')
            # Control is authenticated and pinned; native REST is not remotely exposed.
            request_code="import json,ssl,sys,urllib.request,urllib.error;p=json.load(sys.stdin);ctx=ssl.create_default_context(cadata=p['cert']);c=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx));r=urllib.request.Request(p['url'],data=b'{}',headers={'Authorization':'Bearer invalid'});\ntry:c.open(r);raise AssertionError('Unauthorized control accepted')\nexcept urllib.error.HTTPError as e:assert e.code==401"
            run(['python3', '-c', request_code], data=json.dumps(dict(cert=cert, url='https://'+address+':'+str(management_port)+'/configure')).encode())
            assert 'tsig_key' not in json.dumps(r('/api/dns/servers')) and 'control_token' not in json.dumps(node)
            print('PASS: private HTTPS enrollment, token expiry/replacement/replay rejection, native TSIG zone transfers, serial/UDP/TCP verification, refused unsigned AXFR and control authorization.', flush=True)
            # A second independently enrolled peer gets only the forward zone and its own key.
            peer2=r('/api/dns/servers', 'POST', dict(draft, name='Second DNS peer', address=second_address, zones=[zone]))
            path2='/api/dns/servers/'+peer2['id']
            join2=r(path2+'/deployment', 'POST', dict(acknowledge=True, manager_ca=(s.root/'ca.crt').read_text()))
            env2['FORKLIFT_DNS_JOIN']=join2['join_config'].partition('=')[2]
            second('up', '-d', '--no-build', '--wait'); synced(path2)
            second('exec', '-T', 'dns-secondary', 'python3', '-c', denied_transfer, primary_address, str(primary_port), reverse)
            public_query('server.example.test.', expected='192.168.1.50', dns_address=second_address)
            record('server', ['192.168.1.51'])
            synced(); synced(path2)
            public_query('server.example.test.', expected='192.168.1.51', tcp=True)
            public_query('51.'+reverse, 'PTR', 'server.example.test.')
            host_dns=dict(zone=zone, fqdn='managed', ipv4='192.168.1.60', ipv6=None, reverse=True)
            host=r('/api/hosts', 'POST', dict(name='DNS host', hostname='managed.example.test', endpoints=['ldaps://ldap.example.test'], allowed_groups=[], dns=host_dns))
            assert host['dns_status']['state']=='applied', host
            synced(); public_query('managed.example.test.', expected='192.168.1.60')
            public_query('60.'+reverse, 'PTR', 'managed.example.test.')
            host_dns['ipv4']='192.168.1.61'
            host=r('/api/hosts/'+host['id'], 'PUT', {k:host[k] for k in ['name','hostname','endpoints','allowed_groups','revision']} | dict(dns=host_dns))
            assert host['dns_status']['state']=='applied', host
            synced(); public_query('managed.example.test.', expected='192.168.1.61')
            r('/api/dns/rotate', 'POST', dict(acknowledge=True)); synced()
            # A real Phase 3 secondary keeps serving existing zones and is gated before rotation.
            secondary('exec','-T','dns-secondary','python3','-c',"import json;from pathlib import Path;p=Path('/dns/secondary.json');v=json.loads(p.read_text());v.pop('credential_epoch',None);p.write_text(json.dumps(v))")
            pending=r(path+'/credentials','POST',dict(acknowledge=True))
            assert not pending['rotation'] and not pending['pending_epoch'] and 'Update the DNS secondary' in pending['error'],pending
            r(path+'/certificate','POST',dict(acknowledge=True),expect=400)
            old_pin=secondary('exec','-T','dns-secondary','cat','/dns/server.crt').stdout
            image_override.write_text('services:\n  dns-secondary:\n    image: forklift-dns:latest\n')
            secondary('up','-d','--no-build','--force-recreate','--wait')
            synced();public_query('managed.example.test.',expected='192.168.1.61')
            assert secondary('exec','-T','dns-secondary','cat','/dns/server.crt').stdout==old_pin
            print('PASS: populated Phase 3 secondary upgrade preserves SQLite zones, enrollment, certificate and signed transfers; old helper rotation is rejected before identity changes.',flush=True)
            # Rotate real transfer/control credentials; neither old secret remains usable.
            def node_row():
                return json.loads(s.compose('exec','-T','maintenance','python3','-c',"import sqlite3,sys;d=sqlite3.connect('/metadata/forklift.db');print(d.execute('SELECT data FROM dns_servers WHERE id=?',(sys.argv[1],)).fetchone()[0])",node['id']).stdout)
            before_rotation=node_row()
            previous_config=json.loads(secondary('exec','-T','dns-secondary','cat','/dns/secondary.json').stdout)
            r(path+'/credentials','POST',dict(acknowledge=False),expect=400)
            r(path+'/credentials','POST',dict(acknowledge=True),use_csrf=False,expect=403)
            rotated=r(path+'/credentials','POST',dict(acknowledge=True))
            assert rotated['credential_epoch']==before_rotation['generation']+1 and not rotated['rotation'],rotated
            synced();synced(path2)
            rejection="""import json,ssl,sys,urllib.request,urllib.error
from pathlib import Path
p=json.load(sys.stdin);current=json.loads(Path('/dns/secondary.json').read_text());context=ssl.create_default_context(cafile='/dns/server.crt');client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context));request=urllib.request.Request('https://'+current['address']+':'+str(current['control_port'])+'/health',data=json.dumps(dict(id=current['id'])).encode(),headers={'Authorization':'Bearer '+p['control_token']})
try:client.open(request);raise AssertionError('Old DNS control token was accepted')
except urllib.error.HTTPError as e:assert e.code==401
"""
            secondary('exec','-T','dns-secondary','python3','-c',rejection,input=json.dumps(previous_config).encode())
            signed_old="""import json,subprocess,tempfile,sys
p=json.load(sys.stdin)
with tempfile.NamedTemporaryFile(mode='w') as key:
 key.write('key "'+p['tsig_name']+'" { algorithm hmac-sha256; secret "'+p['tsig_key']+'"; };');key.flush()
 r=subprocess.run(['dig','-k',key.name,'@'+p['primary']['address'],'-p',str(p['primary']['dns_port']),'example.test.','AXFR','+time=1','+tries=1'],capture_output=True)
 assert r.returncode or any(v in r.stdout+r.stderr for v in [b'Transfer failed',b'BADKEY',b'NOTAUTH']), 'Old transfer key was accepted'
"""
            secondary('exec','-T','dns-secondary','python3','-c',signed_old,input=json.dumps(previous_config).encode())
            # Reconstruct a lost acknowledgement after the peer applied the new credential.
            after_rotation=node_row()
            interrupted=dict(before_rotation,pending_generation=after_rotation['generation'],rotation='prepare',revision=after_rotation['revision'])
            s.compose('exec','-T','maintenance','python3','-c',"import sqlite3,json,sys;p=json.load(sys.stdin);d=sqlite3.connect('/metadata/forklift.db');d.execute('UPDATE dns_servers SET data=? WHERE id=?',(json.dumps(p),p['id']));d.commit()",input=json.dumps(interrupted).encode())
            secondary('up','-d','--no-build','--force-recreate','--wait')
            resumed=r(path+'/credentials','POST',dict(acknowledge=True))
            assert resumed['credential_epoch']==after_rotation['generation'] and not resumed['pending_epoch'] and not resumed['rotation'],resumed
            synced()
            old_certificate=secondary('exec','-T','dns-secondary','cat','/dns/server.crt').stdout.decode()
            r(path+'/certificate','POST',dict(acknowledge=True),use_csrf=False,expect=403)
            staged=r(path+'/certificate','POST',dict(acknowledge=True))
            assert staged['certificate_rotation_pending']
            # Crash between publishing the new key and certificate. Startup must finish its journal.
            interrupt="""import hashlib,json;from pathlib import Path
import supervisor,secondary
secondary.supervisor=supervisor
expected=secondary.fingerprint(Path('/dns/server-next.crt'))
supervisor.atomic(Path('/dns/certificate-activation.json'),json.dumps(dict(fingerprint=expected)).encode())
supervisor.atomic(Path('/dns/server-previous.key'),Path('/dns/server.key').read_bytes())
supervisor.atomic(Path('/dns/server-previous.crt'),Path('/dns/server.crt').read_bytes())
supervisor.atomic(Path('/dns/server.key'),Path('/dns/server-next.key').read_bytes())
"""
            secondary('exec','-T','dns-secondary','python3','-c',interrupt)
            secondary('up','-d','--no-build','--force-recreate','--wait')
            finalized=r(path+'/certificate/finalize','POST',dict(acknowledge=True))
            assert not finalized['certificate_rotation_pending'],finalized
            new_certificate=secondary('exec','-T','dns-secondary','cat','/dns/server.crt').stdout.decode()
            assert old_certificate!=new_certificate
            secondary('exec','-T','dns-secondary','python3','-c',"from pathlib import Path;assert not any((Path('/dns')/n).exists() for n in ['server-next.key','server-next.crt','server-previous.key','server-previous.crt','certificate-activation.json'])")
            pinned_rejection="""import json,ssl,socket,sys
p=json.load(sys.stdin);context=ssl.create_default_context(cadata=p['certificate'])
try:
 with socket.create_connection((p['address'],p['port']),timeout=5) as s:
  with context.wrap_socket(s,server_hostname=p['address']):raise AssertionError('Old certificate pin accepted the new identity')
except ssl.SSLCertVerificationError:pass
"""
            run(['python3','-c',pinned_rejection],data=json.dumps(dict(certificate=old_certificate,address=address,port=management_port)).encode())
            synced();synced(path2)
            print('PASS: actual credential rotation/new signed-transfer proof, old token/key rejection, lost-ack recovery, interrupted TLS pair activation and retirement of old pins/files.',flush=True)
            node=synced()
            # New zones require explicit assignments; stale edits are rejected.
            new_zone = 'other.test.'
            r('/api/dns/zones', 'POST', dict(name=new_zone, kind='forward', nameserver='ns1.example.test.', ttl=300))
            previous_revision = node['revision']
            node = r(path+'/assignments', 'PUT', dict(zones=[zone, reverse, new_zone], revision=node['revision']))
            r(path+'/assignments', 'PUT', dict(zones=[zone], revision=previous_revision), expect=409)
            assert node['report']['state']=='needs_reconcile'
            node = r(path+'/reconcile', 'POST', {})
            assert not node.get('error'), node
            synced()
            public_query(new_zone, 'SOA', tcp=True)
            # Confirmed deletion propagates to only enrolled secondary-owned zones.
            data = r('/api/dns/zones/'+new_zone)
            r('/api/dns/zones/'+new_zone, 'DELETE', dict(acknowledge=True, confirm_name=new_zone, expected_revision=data['revision']))
            node = synced()
            assert new_zone not in node['zones']
            upstream_address = str(subnet.network_address+103)
            upstream_config = s.root/'upstream.conf'
            upstream_config.write_text('setLocal("0.0.0.0:5353")\nsetSecurityPollSuffix("")\nsetACL({"'+str(subnet)+'"})\naddAction(QTypeRule(DNSQType.SOA), RCodeAction(DNSRCode.REFUSED))\naddAction(AllRule(), SpoofAction("192.168.1.80"))\n')
            run(['docker','run','-d','--name',upstream_name,'--network',network_name,'--ip',upstream_address,
                 '--mount','type=bind,src='+str(upstream_config)+',dst=/upstream.conf,readonly',
                 '--entrypoint','dnsdist','forklift-dns:latest','--supervised','--disable-syslog','-C','/upstream.conf'])
            policy = dict(enabled=True, upstreams=[dict(address=upstream_address,port=5353)], allowed_clients=[str(subnet)])
            r('/api/dns/forwarding','PUT',policy)
            for _ in range(40):
                if r(path+'/check', 'POST', {})['report']['forwarding_current'] is True:
                    break
                time.sleep(.5)
            else:
                raise AssertionError('DNS peer did not receive forwarding settings')
            def forwarded(tcp=False):
                for attempt in range(10):
                    try:
                        return public_query('outside.test.', expected='192.168.1.80', tcp=tcp, authoritative=False)
                    except AssertionError:
                        if attempt == 9:
                            raise
                        time.sleep(1)
            forwarded()
            public_query('missing.example.test.', status='NXDOMAIN')
            # Secondary restart works with no join and primary/manager offline, using independent storage.
            s.compose('stop', 'dns')
            unavailable = r(path+'/check', 'POST', {})
            assert unavailable['report']['state']=='primary_unavailable' and unavailable['last_sync_at']
            public_query('server.example.test.', expected='192.168.1.51')
            s.bind('admin')
            s.compose('stop', 'manager')
            env['FORKLIFT_DNS_JOIN'] = ''
            secondary('up', '-d', '--no-build', '--force-recreate', '--wait')
            public_query('server.example.test.', expected='192.168.1.51', tcp=True)
            public_query('51.'+reverse, 'PTR', 'server.example.test.')
            forwarded(tcp=True)
            s.compose('start', 'dns', 'manager'); s.wait()
            synced()
            record('server', ['192.168.1.52']); synced()
            public_query('server.example.test.', expected='192.168.1.52')
            # An offline management node is not reported synchronized; removal revokes transfer keys first.
            secondary('stop')
            assert r(path+'/check', 'POST', {})['report']['state']=='management_unavailable'
            result = r(path, 'DELETE', dict(acknowledge=True))
            assert not result['removed'] and result['server']['transfers_revoked'], result
            secondary('start')
            for _ in range(50):
                result = r(path, 'DELETE', dict(acknowledge=True))
                if result['removed']:break
                time.sleep(.3)
            assert result['removed'], result
            remaining=r('/api/dns/servers')['servers']
            assert len(remaining)==1 and remaining[0]['id']==peer2['id']
            record('server', ['192.168.1.53']); synced(path2)
            public_query('server.example.test.', expected='192.168.1.53', dns_address=second_address)
            # The retired peer's still-present secret can no longer authorize an AXFR.
            secondary('exec', '-T', 'dns-secondary', 'python3', '-c', denied_transfer, primary_address, str(primary_port), zone)
            assert r(path2, 'DELETE', dict(acknowledge=True))['removed']
            assert not r('/api/dns/servers')['servers']
            assert all(z['kind']=='Native' for z in r('/api/dns')['zones'])
            print('PASS: live updates, reverse records, assignments, stale edits, confirmed zone deletion, offline primary/manager restart, recovery, management outages, independent peer assignments and actual signed-transfer revocation/removal.', flush=True)
        finally:
            second('down', '--volumes', '--remove-orphans', check=False)
            secondary('down', '--volumes', '--remove-orphans', check=False)
            run(['docker','image','rm',old_image],check=False)
    finally:
        run(['docker', 'rm', '-f', proxy_name, upstream_name], check=False)
