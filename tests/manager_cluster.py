#!/usr/bin/env python3
"""Same-Compose directory and DNS enrollment, native peer writes and outage recovery."""
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


def trust_coordinator(peer, coordinator):
    bundle = peer.root / 'manager-trust.pem'
    bundle.write_bytes(
        Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()
        + (coordinator.root / 'ca.crt').read_bytes()
    )
    override = peer.root / 'manager-trust.yaml'
    override.write_text(
        'services:\n  manager:\n    volumes:\n'
        f'      - {bundle}:/etc/ssl/certs/ca-certificates.crt:ro\n'
    )
    peer.files += ['-f', str(override)]
    peer.compose('up', '-d', '--no-build', '--wait', 'manager')


def user(machine, name):
    return next(
        (value['attrs'] for value in machine.request('/api/overview')['users']
         if value['attrs']['uid'] == [name]),
        None,
    )


def group(machine, name):
    return next(
        (value['attrs'] for value in machine.request('/api/overview')['groups']
         if value['attrs']['cn'] == [name]),
        None,
    )


def password_works(machine, username, password):
    try:
        machine.bind(username, password)
        return True
    except AssertionError:
        return False


def dns_answer(machine, owner, expected):
    result = run([
        'docker', 'run', '--rm', '--network', 'host', '--entrypoint', 'dig',
        'forklift-dns:latest', '@127.0.0.1', '-p', machine.env['FORKLIFT_DNS_PORT'],
        owner, 'A', '+time=1', '+tries=1',
    ], check=False)
    return expected.encode() in result.stdout


with Stack(https=True) as first, Stack(https=True) as peer:
    first.setup()
    r = first.request
    p = peer.request
    r('/api/users', 'POST', first.user('before'))
    r('/api/dns/zones', 'POST', dict(
        name='cluster.test', kind='forward', nameserver='ns.cluster.test.',
        nameserver_address='192.168.1.2', ttl=300,
    ))
    invite = r('/api/directory/peers/invite', 'POST')
    peer.net = peer.network()
    draft = dict(token=peer.bootstrap, public_url=peer.url, network=peer.net,
                 coordinator=invite['url'], key=invite['key'])
    p('/api/setup/join', 'POST', draft, expect=503)
    assert not p('/api/status')['configured']
    trust_coordinator(peer, first)
    first.compose('stop', 'dns')
    assert 'DNS has not synchronized' in p('/api/setup/join', 'POST', draft, expect=503)['error']
    assert not p('/api/status')['configured']
    first.compose('up', '-d', '--no-build', '--wait', 'dns')
    p('/api/setup/join', 'POST', draft)
    p('/api/setup/join', 'POST', draft, expect=400)
    peer.password = first.password
    peer.login()
    paired = next(item for item in r('/api/dns/peers')['peers'] if item['id'] == invite['id'])
    assert paired['active'] and paired['server_id'] == 'provider-2'
    peer.bind('before')
    assert dns_answer(peer, 'ns.cluster.test.', '192.168.1.2')
    print('PASS: approved same-Compose join seeded existing native LDAP and DNS data.', flush=True)
    p('/api/users', 'POST', peer.user('created-on-peer'))
    until(lambda: user(first, 'created-on-peer'), 'Peer user did not reach first node')
    r('/api/users', 'POST', first.user('created-on-first'))
    until(lambda: user(peer, 'created-on-first'), 'First node user did not reach peer')
    assert user(first, 'created-on-peer')['uidNumber'] != user(first, 'created-on-first')['uidNumber']
    p('/api/groups/team', 'PUT', dict(name='team', members=['created-on-peer']))
    until(lambda: (group(first, 'team') or {}).get('memberUid') == ['created-on-peer'],
          'Group membership did not replicate')
    p('/api/groups/team', 'PUT', dict(name='team', members=['created-on-peer', 'created-on-first']))
    until(lambda: set((group(first, 'team') or {}).get('memberUid', [])) == {'created-on-peer', 'created-on-first'},
          'Group membership update did not replicate')
    reset = secrets.token_urlsafe(18)
    p('/api/users', 'POST', peer.user('created-on-peer', password=reset, display_name='Updated'))
    until(lambda: (user(first, 'created-on-peer') or {}).get('cn') == ['Updated'],
          'Peer profile did not replicate')
    until(lambda: password_works(first, 'created-on-peer', reset),
          'Peer password change did not replicate')
    first.compose('stop', 'ldap', 'manager')
    peer.bind('created-on-peer', reset)
    p('/api/users', 'POST', peer.user('while-disconnected'))
    p('/api/users/before', 'DELETE')
    first.compose('start', 'ldap', 'manager')
    first.wait()
    until(lambda: user(first, 'while-disconnected') and not user(first, 'before'),
          'Disconnected changes did not converge')
    first.bind('while-disconnected')
    print('PASS: writable Syncrepl on both LDAP nodes, group and password updates, offline writes, deletion and reconnection.', flush=True)
    peer.compose('up', '-d', '--no-build', '--force-recreate', '--wait')
    peer.wait()
    peer.bind('while-disconnected')
    assert user(peer, 'while-disconnected')
    assert dns_answer(peer, 'ns.cluster.test.', '192.168.1.2')

    with Stack(https=True) as third:
        other_invite = r('/api/directory/peers/invite', 'POST')
        third.net = third.network()
        trust_coordinator(third, first)
        third.request('/api/setup/join', 'POST', dict(
            token=third.bootstrap, public_url=third.url, network=third.net,
            coordinator=other_invite['url'], key=other_invite['key'],
        ))
        third.password = first.password
        third.login()
        until(lambda: any(
            node['id'] == 'provider-3' and node['state'] == 'synchronized'
            for node in p('/api/overview')['directory_servers']['servers']
        ), 'Peer did not establish a direct verified relationship with the third node')
        first.compose('stop', 'ldap', 'manager')
        p('/api/users', 'POST', peer.user('second-while-first-down'))
        third.request('/api/users', 'POST', third.user('third-while-first-down'))
        until(lambda: user(third, 'second-while-first-down')
              and user(peer, 'third-while-first-down'),
              'Remaining LDAP nodes did not synchronize directly')
        first.compose('start', 'ldap', 'manager')
        first.wait()
        until(lambda: user(first, 'second-while-first-down')
              and user(first, 'third-while-first-down'), 'First node did not catch up')
        assert user(first, 'second-while-first-down')['uidNumber'] != user(first, 'third-while-first-down')['uidNumber']
        print('PASS: three nodes synchronize directly while the first node is down, and a recreated node retains its local database.', flush=True)
        identity, headers = p('/api/maintenance/keys', 'POST', raw=True)
        backup = peer.job(dict(action='backup', recipient=headers['X-Age-Recipient']))
        archive, _ = p('/api/maintenance/backups/' + backup['id'], raw=True)
        uploaded = peer.upload(archive)
        first.compose('stop', 'ldap', 'dns', 'manager')
        third.compose('stop', 'ldap', 'dns', 'manager')
        result = peer.job(dict(
            action='restore', upload_id=uploaded['id'], sha256=backup['result']['sha256'],
            identity=identity.decode(), original_fenced=True, acknowledge=True,
            uid_floor=10_000_000, network=peer.net,
        ))
        assert result['result']['restored']
        peer.login()
        peer.bind('while-disconnected')
        assert not p('/api/dns/peers')['coordinator']
        assert p('/api/dns/zones/cluster.test.')['managed']
        assert dns_answer(peer, 'ns.cluster.test.', '192.168.1.2')
        print('PASS: encrypted recovery from a peer retains directory and DNS while fencing the old cluster.', flush=True)
