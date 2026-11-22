"""Configured-path probes with actual TCP listeners and PowerDNS responses; no host firewall changes."""
import json
import socket
from fixture import run


def exercise(s,host_id,browser=None):
    s.compose('up','-d','--no-build','manager');s.wait()
    r=s.request
    r('/api/network/checks','POST',{},authenticated=False,expect=401)
    r('/api/network/checks','POST',{},use_csrf=False,expect=403)
    r('/api/network/checks','POST',dict(address='192.168.1.1',port=22),expect=422,raw=True)
    dns=json.loads(run(['docker','inspect',s.compose('ps','-q','dns').stdout.decode().strip()]).stdout)[0]
    address=next(iter(dns['NetworkSettings']['Networks'].values()))['IPAddress']
    r('/api/dns/primary','PUT',dict(address=address,dns_port=5353,acknowledge=True))
    reply=r('/api/network/checks','POST',{})
    assert all(c['status']=='pass' for c in reply['checks']),reply
    assert {c['transport'] for c in reply['checks'] if c['label'].startswith('DNS server')}=={'DNS/TCP','DNS/UDP'}
    assert all(c['source']=='Forklift manager network namespace' and c['checked_at']>0 for c in reply['checks'])
    s.compose('stop','dns')
    try:
        failed=r('/api/network/checks','POST',{})
        assert all(c['status']=='failure' for c in failed['checks'] if c['label'].startswith('DNS server'))
        assert all(c['status']=='pass' for c in failed['checks'] if not c['label'].startswith('DNS server'))
    finally:s.compose('start','dns')
    # The standalone HTTPS fixture uses host networking; only its disposable selected TCP port is tested.
    with socket.socket() as listener:
        listener.bind(('0.0.0.0',0));listener.listen();port=listener.getsockname()[1]
        monitoring=r('/api/hosts/'+host_id+'/monitoring');policy=monitoring['policy'];policy['diagnostics'].update(ssh=True,ssh_local=s.net['address'],ssh_port=port)
        r('/api/hosts/'+host_id+'/monitoring','PUT',dict(revision=monitoring['revision'],policy=policy))
        host_path='/api/hosts/'+host_id+'/network-checks'
        assert r(host_path,'POST',{})['checks'][0]['status']=='pass'
    assert r(host_path,'POST',{})['checks'][0]['status']=='failure'
    monitoring=r('/api/hosts/'+host_id+'/monitoring');policy=monitoring['policy'];policy['diagnostics'].update(ssh_local='127.0.0.1')
    r('/api/hosts/'+host_id+'/monitoring','PUT',dict(revision=monitoring['revision'],policy=policy))
    r(host_path,'POST',{},expect=400)
    r('/api/hosts/'+'f'*32+'/network-checks','POST',{},expect=404)
    monitoring=r('/api/hosts/'+host_id+'/monitoring');policy=monitoring['policy'];policy['diagnostics'].update(ssh=False,ssh_local=None,ssh_port=22)
    r('/api/hosts/'+host_id+'/monitoring','PUT',dict(revision=monitoring['revision'],policy=policy))
    # Separate UI cases start with a fresh test rate-limit window.
    s.compose('exec','-T','maintenance','python3','-c',"import sqlite3;d=sqlite3.connect('/metadata/forklift.db');d.execute(\"DELETE FROM client_limits WHERE scope='network-checks'\");d.commit()")
    if browser:browser('network')
    print('PASS: authenticated/CSRF-protected configured-service probes, rejected arbitrary scan input, actual PowerDNS TCP/UDP failure and recovery, independent LDAP/HTTPS, selected inbound host TCP port and loopback/unknown-host safeguards.',flush=True)

if __name__=='__main__':
    from fixture import Stack
    with Stack(https=True) as s:
        s.setup()
        s.request('/api/groups/network-test','PUT',dict(name='network-test',members=[]))
        endpoint=s.request('/api/overview')['directory']['network']['endpoint']
        host=s.request('/api/hosts','POST',dict(name='Network test',hostname='network.example.test',endpoints=[endpoint],allowed_groups=['network-test']))
        exercise(s,host['id'])
