#!/usr/bin/env python3
"""Host-owned DNS lifecycle against real PowerDNS, SQLite and OpenLDAP."""
import json
import time
from fixture import Stack, run


with Stack() as s:
    s.setup()
    r = s.request
    zone = 'example.test.'
    reverse_zone = '1.168.192.in-addr.arpa.'
    for body in [dict(name=zone, kind='forward', nameserver='ns1.example.test.', nameserver_address='192.168.1.2', ttl=300),
                 dict(name='192.168.1.0/24', kind='reverse4', nameserver='ns1.example.test.', ttl=300),
                 dict(name='d.f.ip6.arpa.', kind='reverse6', nameserver='ns1.example.test.', ttl=300)]:
        r('/api/dns/zones', 'POST', body)

    def dig(name, kind='A', value=None, absent=False):
        output = run(['docker', 'run', '--rm', '--network', 'host', '--entrypoint', 'dig',
                      'forklift-dns:latest', '@127.0.0.1', '-p', s.env['FORKLIFT_DNS_PORT'], name, kind,
                      '+time=1', '+tries=1']).stdout.decode()
        assert 'status: NOERROR' in output or absent and 'status: NXDOMAIN' in output, output
        if value:
            assert (value not in output) if absent else (value in output), output
        elif absent:
            assert 'ANSWER: 0' in output, output
        return output

    def config(name, address='192.168.1.50', **changes):
        return dict(zone=zone, fqdn=name, ipv4=address, ipv6=None, reverse=True) | changes

    def create(name, dns=None, **changes):
        return r('/api/hosts', 'POST', dict(name=name, hostname=name+'.example.test',
                 endpoints=['ldaps://ldap.example.test:636'], allowed_groups=[], dns=dns) | changes)

    def update(host, **changes):
        return r('/api/hosts/'+host['id'], 'PUT', {k: host[k] for k in ['name', 'hostname', 'endpoints', 'allowed_groups', 'revision']} | changes)

    def delete(host, choice='delete'):
        return r('/api/hosts/'+host['id']+'?revision='+str(host['revision'])+'&dns='+choice, 'DELETE')

    def reconcile(host):
        return r('/api/dns/hosts/'+host['id']+'/reconcile', 'POST', {})

    def hosts():
        return r('/api/hosts')

    def get_record(name, kind='A', z=zone):
        return next((v for v in r('/api/dns/zones/'+z)['rrsets'] if v['name']==name and v['type']==kind), None)

    def manual(name, values, kind='A', z=zone):
        old = get_record(name, kind, z)
        return r('/api/dns/zones/'+z+'/records', 'POST', dict(name=name, type=kind, values=values,
                 ttl=600, expected_revision=old['revision'] if old else None))

    def native(path, payload):
        code = "import http.client,json,socket,sys;from pathlib import Path;p=json.load(sys.stdin)\nclass C(http.client.HTTPConnection):\n def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.connect('/run/dns-control/dns.sock')\nc=C('localhost');c.request('PATCH',p['path'],body=json.dumps(p['body']),headers={'X-API-Key':Path('/run/dns-secrets/api-key').read_text().strip(),'Content-Type':'application/json'});r=c.getresponse();assert r.status==204,(r.status,r.read())"
        s.compose('exec', '-T', 'dns', 'python3', '-c', code,
                  input=json.dumps(dict(path='/api/v1/servers/localhost/zones/'+path, body=payload)).encode())

    def start_dns():
        s.compose('start', 'dns')
        for _ in range(60):
            if r('/api/dns')['available']:
                return
            time.sleep(.2)
        raise AssertionError('DNS did not start')

    # Syntax errors and duplicate names never create a host.
    baseline = len(hosts())
    for cfg in [config('outside.invalid.'), config('bad\nname'), config('bad', ipv4='not-an-address'),
                config('bad', ipv4='0.0.0.0'), config('_service')]:
        r('/api/hosts', 'POST', dict(name='Invalid', hostname='invalid.example.test', endpoints=['ldaps://ldap.example.test'], allowed_groups=[], dns=cfg), expect=(400, 422), raw=True)
    assert len(hosts()) == baseline
    h = create('server', config('server', ipv6='fd00::50'))
    assert h['dns']['fqdn'] == 'server.example.test.' and h['dns_status']['state'] == 'applied', h
    assert h['dns_status']['managed_values'] == 4, h
    dig('server.example.test.', value='192.168.1.50')
    dig('server.example.test.', 'AAAA', 'fd00::50')
    dig('50.'+reverse_zone, 'PTR', 'server.example.test.')
    dig('0.5.'+'0.'*28+'d.f.ip6.arpa.', 'PTR', 'server.example.test.')
    r('/api/dns/hosts/'+h['id']+'/reconcile', 'POST', {}, authenticated=False, expect=401)
    r('/api/dns/hosts/'+h['id']+'/reconcile', 'POST', {}, use_csrf=False, expect=403)
    r('/api/hosts', 'POST', dict(name='Duplicate', hostname='duplicate.example.test', endpoints=h['endpoints'], allowed_groups=[], dns=config('server')), expect=400)
    r('/api/hosts/'+h['id'], 'DELETE', expect=400)
    r('/api/hosts/'+h['id']+'?dns=delete&revision=0', 'DELETE', expect=400)
    assert reconcile(h)['managed_values'] == 4
    # A record not owned by the host is merged, retaining TTL and values.
    manual('shared.example.test.', ['192.168.1.90'])
    shared = create('shared', config('shared', '192.168.1.51'))
    assert get_record('shared.example.test.')['ttl'] == 600
    output = dig('shared.example.test.', value='192.168.1.51')
    assert '192.168.1.90' in output
    shared = update(shared, dns=config('shared', '192.168.1.52'))
    assert shared['dns_status']['state'] == 'applied', shared
    output = dig('shared.example.test.', value='192.168.1.52')
    assert '192.168.1.90' in output and '192.168.1.51' not in output
    delete(shared)
    output = dig('shared.example.test.', value='192.168.1.90')
    assert '192.168.1.52' not in output
    dig('52.'+reverse_zone, 'PTR', absent=True)
    # Preexisting identical values are never adopted or later deleted.
    manual('existing.example.test.', ['192.168.1.53'])
    manual('53.'+reverse_zone, ['existing.example.test.'], 'PTR', reverse_zone)
    existing = create('existing', config('existing', '192.168.1.53'))
    assert existing['dns_status']['managed_values'] == 0 and existing['dns_status']['warnings'], existing
    delete(existing)
    dig('existing.example.test.', value='192.168.1.53')
    dig('53.'+reverse_zone, 'PTR', 'existing.example.test.')
    # Manual edits relinquish ownership without removing other values.
    manual('server.example.test.', ['192.168.1.50', '192.168.1.91'])
    current = next(x for x in hosts() if x['id']==h['id'])
    assert current['dns_status']['state'] == 'needs_review', current
    h = update(current, dns=config('renamed', '192.168.1.54'), hostname='renamed.example.test')
    dig('renamed.example.test.', value='192.168.1.54')
    dig('server.example.test.', value='192.168.1.50')
    dig('server.example.test.', value='192.168.1.91')
    dig('50.'+reverse_zone, 'PTR', absent=True)
    dig('54.'+reverse_zone, 'PTR', 'renamed.example.test.')
    dig('server.example.test.', 'AAAA', absent=True)
    stale = dict(h)
    h = update(h, dns=config('renamed', '192.168.1.55'), dns_apply=False)
    assert h['dns_status']['state']=='applied'
    dig('renamed.example.test.', value='192.168.1.55')
    r('/api/hosts/'+h['id'], 'PUT', {k: stale[k] for k in ['name', 'hostname', 'endpoints', 'allowed_groups', 'revision']}, expect=409)
    assert reconcile(h)['state']=='applied'
    output=dig('renamed.example.test.', value='192.168.1.55')
    assert '192.168.1.54' not in output
    # Old clients omitting DNS preserve the desired name.
    h=update(h, hostname='inventory.example.test')
    assert h['dns']['fqdn']=='renamed.example.test.' and h['dns_status']['state']=='applied'
    # Disabling requires an explicit retain/delete policy.
    r('/api/hosts/'+h['id'], 'PUT', {k: h[k] for k in ['name', 'hostname', 'endpoints', 'allowed_groups', 'revision']} | dict(dns=None), expect=400)
    h=update(h, dns=None, dns_cleanup='keep')
    assert h['dns_status']['state']=='retained'
    delete(h)
    dig('renamed.example.test.', value='192.168.1.55')
    print('PASS: real A/AAAA/IPv4+IPv6 PTR, validation, authorization, shared values/TTL, manual ownership, rename, automatic saves, stale updates and explicit keep/delete.', flush=True)

    # Native changes without our marker are retained, even when metadata says owned.
    drift=create('drift', config('drift', '192.168.1.56', reverse=False))
    native(zone, dict(rrsets=[dict(name='drift.example.test.', type='A', ttl=300, changetype='REPLACE', records=[dict(content='192.168.1.56', disabled=False)], comments=[])]))
    delete(drift)
    dig('drift.example.test.', value='192.168.1.56')
    disabled=create('disabled', config('disabled', '192.168.1.66', reverse=False))
    # Disable the value while retaining its ownership marker: cleanup must still preserve it.
    ownership=dict(account='forklift-host:'+disabled['id'], content='A 192.168.1.66', modified_at=int(time.time()))
    native(zone, dict(rrsets=[dict(name='disabled.example.test.', type='A', ttl=300, changetype='REPLACE', records=[dict(content='192.168.1.66', disabled=True)], comments=[ownership])]))
    assert reconcile(disabled)['state']=='needs_retry'
    delete(disabled)
    assert get_record('disabled.example.test.')['records'][0]['disabled']
    # Failed validation of a reverse boundary saves a retryable host, not partial records.
    missing=create('missing', config('missing', '192.168.2.1'))
    assert missing['dns_status']['state']=='needs_retry' and 'reverse zone' in missing['dns_status']['error'], missing
    dig('missing.example.test.', absent=True)
    missing=update(missing, dns=config('missing', '192.168.1.57'))
    assert missing['dns_status']['state']=='applied'
    # LDAP and host metadata survive a DNS outage; retry is persistent across recreation.
    s.compose('stop', 'dns')
    offline=create('offline', config('offline', '192.168.1.58'))
    assert offline['dns_status']['state']=='needs_retry', offline
    s.bind('admin')
    s.compose('up', '-d', '--no-build', '--force-recreate', '--wait', 'manager')
    s.wait()
    assert next(x for x in hosts() if x['id']==offline['id'])['dns_status']['state']=='needs_retry'
    start_dns()
    assert reconcile(offline)['state']=='applied'
    offline=next(x for x in hosts() if x['id']==offline['id'])
    dig('offline.example.test.', value='192.168.1.58')
    s.compose('stop', 'dns')
    result=delete(offline)
    assert result['dns_status']['state']=='needs_retry', result
    assert not any(x['id']==offline['id'] for x in hosts())
    assert any(x['id']==offline['id'] and x['deleted'] for x in r('/api/dns')['host_tasks'])
    start_dns()
    assert reconcile(offline)['state']=='removed'
    dig('offline.example.test.', absent=True)
    dig('58.'+reverse_zone, 'PTR', absent=True)
    # Explicit keep leaves DNS intact; disabling+delete removes only owned values.
    keep=create('keep', config('keep', '192.168.1.59'))
    delete(keep, 'keep')
    dig('keep.example.test.', value='192.168.1.59')
    remove=create('remove', config('remove', '192.168.1.60'))
    remove=update(remove, dns=None, dns_cleanup='delete')
    assert remove['dns_status']['state']=='removed', remove
    dig('remove.example.test.', absent=True)
    # Two hosts sharing one address own separate PTR values.
    first=create('first', config('first', '192.168.1.62'))
    second=create('second', config('second', '192.168.1.62'))
    dig('62.'+reverse_zone, 'PTR', 'first.example.test.')
    dig('62.'+reverse_zone, 'PTR', 'second.example.test.')
    delete(first)
    output=dig('62.'+reverse_zone, 'PTR', 'second.example.test.')
    assert 'first.example.test.' not in output
    delete(second)
    dig('62.'+reverse_zone, 'PTR', absent=True)
    # Reconstruct an actual interruption with one planned write missing, not mock responses.
    partial=create('partial', config('partial', '192.168.1.63'))
    seed="""import json,sqlite3,sys
p=json.load(sys.stdin);d=sqlite3.connect('/metadata/forklift.db');state=json.loads(d.execute('SELECT data FROM host_dns WHERE id=?',(p['id'],)).fetchone()[0]);changes=[json.loads(row[0]) for row in d.execute('SELECT data FROM dns_changes ORDER BY rowid DESC')];c=next(c for c in changes if (c.get('host') or {}).get('host_id')==p['id']);state['status']['operation_id']=c['id'];state['status']['state']='pending';d.execute('UPDATE host_dns SET data=? WHERE id=?',(json.dumps(state),p['id']));d.execute("UPDATE dns_changes SET status='pending',error=NULL WHERE id=?",(c['id'],));d.commit();print(c['id'])"""
    def seed_partial(host):
        return s.compose('exec', '-T', 'maintenance', 'python3', '-c', seed, input=json.dumps(dict(id=host['id'])).encode()).stdout.decode().strip()
    native(zone, dict(rrsets=[dict(name='partial.example.test.', type='A', changetype='DELETE')]))
    operation=seed_partial(partial)
    s.compose('restart', 'manager')
    s.wait()
    assert r('/api/dns/changes/'+operation+'/retry', 'POST', {})['status']=='completed'
    dig('partial.example.test.', value='192.168.1.63')
    dig('63.'+reverse_zone, 'PTR', 'partial.example.test.')
    # A conflict blocks the old plan; changing intent cancels it and preserves manual data.
    native(zone, dict(rrsets=[dict(name='partial.example.test.', type='A', ttl=300, changetype='REPLACE', records=[dict(content='192.168.1.94', disabled=False)], comments=[])]))
    operation=seed_partial(partial)
    assert r('/api/dns/changes/'+operation+'/retry', 'POST', {})['status']=='needs_retry'
    r('/api/dns/changes/'+operation+'/abandon', 'POST', dict(acknowledge=True), expect=400)
    partial=update(partial, dns=config('partial', '192.168.1.64'))
    assert partial['dns_status']['state']=='applied', partial
    r('/api/dns/changes/'+operation+'/retry', 'POST', {}, expect=400)
    output=dig('partial.example.test.', value='192.168.1.64')
    assert '192.168.1.94' in output and '192.168.1.63' not in output
    delete(partial)
    dig('partial.example.test.', value='192.168.1.94')
    # A deleted host's deferred cleanup can be explicitly retained during an outage.
    abandoned=create('abandoned', config('abandoned', '192.168.1.65'))
    s.compose('stop', 'dns')
    delete(abandoned)
    r('/api/dns/hosts/'+abandoned['id']+'/retain', 'POST', dict(acknowledge=False), expect=400)
    r('/api/dns/hosts/'+abandoned['id']+'/retain', 'POST', dict(acknowledge=True))
    start_dns()
    dig('abandoned.example.test.', value='192.168.1.65')
    assert not any(t['id']==abandoned['id'] for t in r('/api/dns')['host_tasks'])
    # Directory inventory can manage DNS without granting login.
    primary=next(x for x in hosts() if x['directory_id']=='primary')
    primary=update(primary, dns=config('directory', '192.168.1.61'))
    assert not primary['allowed_groups'] and primary['dns_status']['state']=='applied'
    r('/api/hosts/'+primary['id'], 'DELETE', expect=400)
    s.compose('up', '-d', '--no-build', '--force-recreate', '--wait')
    s.wait()
    assert next(x for x in hosts() if x['id']==primary['id'])['dns_status']['state']=='applied'
    dig('directory.example.test.', value='192.168.1.61')
    dig('missing.example.test.', value='192.168.1.57')
    print('PASS: external drift protection, missing reverse coverage, LDAP during DNS outage, durable retries/deleted-host cleanup, retention, shared PTRs, interrupted/conflicting plans, supersession, directory hosts and recreation.', flush=True)
