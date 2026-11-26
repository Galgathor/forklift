#!/usr/bin/env python3
"""Actual verified server publisher -> native client DNS-SD discovery on a local interface."""
import http.cookiejar
import json
import os
import re
import select
import subprocess
import time
import urllib.request
from pathlib import Path
from fixture import SOURCE, Stack, run

client=Path(os.environ.get('FORKLIFT_CLIENT_BINARY',SOURCE.parent/'forklift-client/target/release/forklift-client')).resolve()
assert client.is_file()
# Use an existing private interface and a dedicated TLS port; never alter network configuration.
interfaces=json.loads(run(['ip','-j','-4','address','show','docker0']).stdout)
address=next(a['local'] for i in interfaces for a in i['addr_info'] if a['family']=='inet')
s=Stack(https=True)
s.url='https://'+address+':'+s.url.rsplit(':',1)[1]
s.env['FORKLIFT_PUBLIC_URL']=s.url
(s.root/'extensions').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:'+address+'\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
run(['openssl','x509','-req','-in','server.csr','-CA','ca.crt','-CAkey','ca.key','-set_serial','3','-days','2','-extfile','extensions','-out','server.crt'],cwd=s.root)
s.client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(s.jar),urllib.request.HTTPSHandler(context=s.context))
with s:
    s.setup()
    descriptor=s.request('/api/client/v1/info')
    publisher=s.project+'-discovery'
    run(['docker','run','-d','--name',publisher,'--network','host','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','-e','FORKLIFT_PUBLIC_URL='+s.url,'-e','FORKLIFT_DISCOVERY_CA_FILE=/ca.crt','-v',str(s.root/'ca.crt')+':/ca.crt:ro','--entrypoint','/app/forklift','forklift-manager:latest','publish-discovery'])
    try:
        found=None
        for _ in range(3):
            choices=json.loads(run([str(client),'discover','--json','--timeout','5']).stdout)
            found=next((c for c in choices if c['instance_id']==descriptor['instance_id']),None)
            if found:break
        if not found:
            logs=run(['docker','logs',publisher],check=False).stderr.decode()[-600:]
            raise AssertionError('Published Forklift instance was not discovered: '+logs)
        assert found['url']==s.url and found['api_version']==1
        assert found['service_hostname'].endswith('.local.')
        state = Path('/tmp') / (s.project + '-discovered-client')
        run(['sudo', '-n', 'mkdir', '-m', '700', str(state)])
        command = ['sudo', '-n', str(client), '--state-dir', str(state)]
        join = subprocess.Popen(
            [*command, 'join', '--ca-file', str(s.root / 'ca.crt'), '--hostname', 'discovered-client'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        try:
            def read_until(pattern):
                text = ''
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if select.select([join.stdout], [], [], .25)[0]:
                        chunk = os.read(join.stdout.fileno(), 4096).decode()
                        if not chunk:
                            raise AssertionError('Client join exited before the expected prompt')
                        text += chunk
                        match = re.search(pattern, text, re.MULTILINE)
                        if match:
                            return match
                raise AssertionError('Client join did not reach the expected prompt')

            choice = read_until(r'^([0-9]+)\. [^\n]+\n   ' + re.escape(s.url) + r'$')
            join.stdin.write(choice[1] + '\n')
            join.stdin.flush()
            code = read_until(r'Enrollment code: ([A-Z2-9]{4}-[A-Z2-9]{4})')[1]
            s.request('/api/dns/zones', 'POST', dict(
                name='enrollment.test', kind='forward', nameserver='ns.enrollment.test.',
                nameserver_address='192.168.1.2', ttl=300,
            ))
            requested = s.request('/api/clients/lookup', 'POST', dict(code=code))
            approved = s.request('/api/clients/' + requested['id'] + '/approve', 'POST',
                                 dict(name='Discovered client', acknowledge=True, dns=dict(
                                     zone='enrollment.test.', fqdn='discovered-client',
                                     ipv4='192.168.1.75', ipv6=None, reverse=False,
                                 )))
            output, error = join.communicate(timeout=25)
            assert join.returncode == 0 and 'Enrollment successful' in output, error[:300]
            status = json.loads(run([*command, 'status', '--offline']).stdout)
            assert status['server'] == s.url and status['instance_id'] == descriptor['instance_id']
            assert status['client_version'] == '0.6.0' and status['host_id'] == approved['host_id']
            assert s.request('/api/status')['version'] == '0.6.0'
            host = next(item for item in s.request('/api/hosts') if item['id'] == approved['host_id'])
            assert host['dns_status']['state'] == 'applied'
            print('PASS: client 0.6 discovered the manager, verified HTTPS and joined server 0.6.', flush=True)
        finally:
            if join.poll() is None:
                run(['sudo', '-n', 'kill', '-TERM', '--', '-' + str(join.pid)], check=False)
                join.wait(timeout=15)
            run(['sudo', '-n', 'rm', '-r', '--', str(state)])
        run(['docker','stop','--time','10',publisher])
        choices=json.loads(run([str(client),'discover','--json','--timeout','3']).stdout)
        assert not any(c['instance_id']==descriptor['instance_id'] for c in choices)
        print('PASS: real LAN publisher verifies the HTTPS descriptor, native multicast discovery returns the correct origin/version/instance, and stopped publication disappears without changing host networking.',flush=True)
    finally:
        run(['docker','rm','-f',publisher],check=False)
