#!/usr/bin/env python3
"""Real HTTPS DNS edits and authoritative answers across identical Compose stacks."""
import json
import secrets
import time
from pathlib import Path
from fixture import Stack, run


def until(check, message):
    for _ in range(60):
        if check():
            return
        time.sleep(1)
    raise AssertionError(message)


def answer(machine, owner, kind, wanted):
    result = run([
        'docker', 'run', '--rm', '--network', 'host', '--entrypoint', 'dig',
        'forklift-dns:latest', '@127.0.0.1', '-p', machine.env['FORKLIFT_DNS_PORT'],
        owner, kind, '+time=1', '+tries=1',
    ], check=False)
    return wanted in result.stdout.decode()


with Stack(dns_bind='0.0.0.0') as upstream, Stack(https=True) as coordinator:
    upstream.setup()
    upstream.request('/api/dns/zones', 'POST', dict(
        name='upstream.test', kind='forward', nameserver='ns.upstream.test.',
        nameserver_address='192.168.1.81', ttl=300,
    ))
    coordinator.setup()
    r = coordinator.request
    zone = dict(name='shared.test', kind='forward', nameserver='ns.shared.test.',
                nameserver_address='192.168.1.2', ttl=300)
    r('/api/dns/zones', 'POST', zone)
    invitation = r('/api/dns/peers', 'POST')
    key_header = {'x-forklift-dns-key': invitation['key']}
    r('/api/dns/peer/snapshot', headers=key_header, authenticated=False, expect=401)
    with Stack(https=True) as peer:
        peer.setup()
        p = peer.request
        join = dict(url=invitation['url'], key=invitation['key'])
        assert 'verified HTTPS' in p('/api/dns/peer/join','POST',join,expect=503)['error']
        bundle = peer.root/'manager-trust.pem'
        bundle.write_bytes(Path('/etc/ssl/certs/ca-certificates.crt').read_bytes() + (coordinator.root/'ca.crt').read_bytes())
        override = peer.root/'manager-trust.yaml'
        override.write_text(
            'services:\n  manager:\n    volumes:\n'
            f'      - {bundle}:/etc/ssl/certs/ca-certificates.crt:ro\n'
        )
        peer.files += ['-f',str(override)]
        peer.compose('up','-d','--no-build','--wait','manager')
        p('/api/dns/peer/join','POST',join)
        r('/api/dns/peer/snapshot', headers=key_header, authenticated=False, expect=401)
        r('/api/dns/peer/redeem','POST',dict(access_key=secrets.token_hex(32)),
          headers=key_header,authenticated=False,expect=401)
        until(lambda: answer(peer, 'ns.shared.test.', 'A', '192.168.1.2'), 'Peer did not seed')
        endpoint = '/api/dns/zones/shared.test./records'
        edit = dict(name='host', type='A', ttl=300, values=['192.168.1.50'],
                    request_id=secrets.token_hex(16))
        p(endpoint,'POST',edit,expect=403,use_csrf=False)
        saved = p(endpoint,'POST',edit)
        assert saved['status'] == 'completed'
        assert p(endpoint,'POST',edit) == saved
        until(lambda: answer(peer, 'host.shared.test.', 'A', '192.168.1.50'),
              'Peer did not apply its edit')
        assert answer(coordinator, 'host.shared.test.', 'A', '192.168.1.50')
        forwarding_path = '/api/dns/forwarding'
        allowed = ['127.0.0.0/8']
        for node in (coordinator, peer):
            network = json.loads(run(['docker', 'network', 'inspect', node.project + '_default']).stdout)[0]
            allowed.extend([network['IPAM']['Config'][0]['Subnet'], node.net['address'] + '/32'])
        policy = dict(
            enabled=True,
            upstreams=[dict(address=upstream.net['address'], port=int(upstream.env['FORKLIFT_DNS_PORT']))],
            allowed_clients=list(dict.fromkeys(allowed)),
        )
        p(forwarding_path, 'PUT', policy, use_csrf=False, expect=403)
        p(forwarding_path, 'PUT', policy)
        assert r(forwarding_path)['settings'] == p(forwarding_path)['settings'] == policy
        until(lambda: answer(peer, 'ns.upstream.test.', 'A', '192.168.1.81'),
              'Peer did not apply shared forwarding')
        assert answer(coordinator, 'ns.upstream.test.', 'A', '192.168.1.81')
        coordinator.compose('stop','manager')
        p(endpoint,'POST',edit,expect=503)
        assert answer(peer,'host.shared.test.','A','192.168.1.50')
        peer.compose('up', '-d', '--no-build', '--force-recreate', '--no-deps', '--wait', 'dns')
        assert answer(peer, 'ns.upstream.test.', 'A', '192.168.1.81')
        coordinator.compose('start','manager')
        coordinator.wait()
        r(forwarding_path, 'PUT', dict(policy, enabled=False))
        until(lambda: answer(peer, 'ns.upstream.test.', 'A', 'REFUSED'),
              'Peer did not apply forwarding disable after reconnection')
        print('PASS: shared forwarding edits, offline persistence and reconnection.', flush=True)
        rrset = next(v for v in r('/api/dns/zones/shared.test.')['rrsets'] if v['name']=='host.shared.test.')
        r(endpoint,'POST',dict(name='host',type='A',ttl=300,values=[],
          expected_revision=rrset['revision'],delete=True,acknowledge=True))
        until(lambda: answer(peer,'host.shared.test.','A','NXDOMAIN'), 'Peer retained deleted record')
        assert p(endpoint,'POST',edit) == saved
        assert answer(peer,'host.shared.test.','A','NXDOMAIN')
        r(endpoint,'POST',dict(name='switch',type='A',ttl=300,values=['192.168.1.51']))
        until(lambda: answer(peer,'switch.shared.test.','A','192.168.1.51'), 'Initial A record did not synchronize')
        peer.compose('stop','manager')
        switch = next(v for v in r('/api/dns/zones/shared.test.')['rrsets'] if v['name']=='switch.shared.test.')
        r(endpoint,'POST',dict(name='switch',type='A',ttl=300,values=[],
          expected_revision=switch['revision'],delete=True,acknowledge=True))
        r(endpoint,'POST',dict(name='switch',type='CNAME',ttl=300,values=['ns.shared.test.']))
        peer.compose('start','manager')
        peer.wait()
        until(lambda: answer(peer,'switch.shared.test.','CNAME','ns.shared.test.'), 'CNAME did not replace a stale address set')
        assert not answer(peer,'switch.shared.test.','A','192.168.1.51')
        secondary_zone = p('/api/dns/zones','POST',dict(zone, name='other.test.', nameserver='ns.other.test.'))
        until(lambda: answer(peer,'ns.other.test.','A','192.168.1.2'), 'Peer zone creation did not replicate')
        p('/api/dns/zones/other.test.','DELETE',dict(acknowledge=True,confirm_name='other.test.',
          expected_revision=secondary_zone['revision']))
        until(lambda: answer(peer,'ns.other.test.','A','REFUSED'), 'Peer retained a deleted zone')
        r('/api/dns/peers/'+invitation['id'],'DELETE')
        p(endpoint,'POST',edit,expect=503)
        assert answer(peer,'ns.shared.test.','A','192.168.1.2')
        replacement = r('/api/dns/peers','POST')
        p('/api/dns/peer/join','POST',dict(url=replacement['url'],key=replacement['key']))
        assert p('/api/dns/zones/shared.test.')['managed']
        print('PASS: approved TLS pairing, edits through peer, independent authoritative answers, outage and reconnection, and revocation.', flush=True)
