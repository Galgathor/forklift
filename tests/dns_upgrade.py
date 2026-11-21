#!/usr/bin/env python3
"""Upgrade populated pre-DNS/Phase 3 installations without resetting LDAP or DNS."""
import io
import tarfile
from fixture import Stack, SOURCE, run


def upgrade(commit, with_dns=False):
    with Stack() as fixture:
        fixture.compose('down', '--volumes', '--remove-orphans')
        source = fixture.root/'old-source'
        source.mkdir()
        archive = run(['git', 'archive', commit], cwd=SOURCE).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(source, filter='data')
        image = fixture.project+'-old-manager'
        dns_image = fixture.project+'-old-dns'
        maintenance_image = fixture.project+'-old-maintenance'
        run(['docker', 'build', '-t', image, '-f', 'docker/manager/Dockerfile', '.'], cwd=source)
        run(['docker', 'build', '-t', maintenance_image, '-f', 'docker/maintenance/Dockerfile', '.'], cwd=source)
        override = fixture.root/'old-image.yaml'
        content = 'services:\n  manager:\n    image: '+image+'\n  initialize:\n    image: '+maintenance_image+'\n  maintenance:\n    image: '+maintenance_image+'\n'
        if with_dns:
            run(['docker', 'build', '-t', dns_image, '-f', 'docker/powerdns/Dockerfile', '.'], cwd=source)
            content += '  dns:\n    image: '+dns_image+'\n'
        override.write_text(content)
        try:
            fixture.files = ['-f', str(source/'compose.yaml'), '-f', str(override)]
            fixture.compose('up', '-d', '--no-build', '--wait')
            fixture.wait('/health')
            fixture.setup()
            r = fixture.request
            r('/api/users', 'POST', fixture.user('preserved'))
            r('/api/groups/existing-policy', 'PUT', dict(name='existing-policy', members=['preserved']))
            draft = dict(name='Existing Linux host', hostname='existing.example.test', endpoints=['ldaps://'+fixture.net['address']+':'+str(fixture.net['port'])], allowed_groups=['existing-policy'])
            zone = 'example.test.'
            if with_dns:
                r('/api/dns/zones', 'POST', dict(name=zone, kind='forward', nameserver='ns1.example.test.', nameserver_address='192.168.1.2', ttl=300))
                r('/api/dns/zones', 'POST', dict(name='192.168.1.0/24', kind='reverse4', nameserver='ns1.example.test.', ttl=300))
                draft['dns'] = dict(zone=zone, fqdn='existing', ipv4='192.168.1.50', ipv6=None, reverse=True)
            host = r('/api/hosts', 'POST', draft)
            before = r('/api/overview')
            key = fixture.compose('exec', '-T', 'dns', 'cat', '/run/dns-secrets/api-key').stdout if with_dns else None
            fixture.files = ['-f', str(SOURCE/'compose.yaml')]
            fixture.compose('up', '-d', '--no-build', '--force-recreate', '--wait')
            fixture.wait()
            r('/api/me')
            fixture.bind('preserved')
            after = r('/api/overview')
            assert before['users'] == after['users'] and before['groups'] == after['groups']
            saved = next(h for h in after['hosts'] if h['id'] == host['id'])
            assert saved['allowed_groups'] == ['existing-policy']
            assert r('/api/dns')['available']
            schema = fixture.compose('exec', '-T', 'maintenance', 'python3', '-c', "import sqlite3;d=sqlite3.connect('/metadata/forklift.db');print(d.execute('PRAGMA user_version').fetchone()[0])").stdout.strip()
            assert schema == b'5'
            if with_dns:
                assert key == fixture.compose('exec', '-T', 'dns', 'cat', '/run/dns-secrets/api-key').stdout
                assert saved['dns'] == host['dns']
                def dig(owner, kind, value):
                    text = run(['docker', 'run', '--rm', '--network', 'host', '--entrypoint', 'dig', 'forklift-dns:latest', '@127.0.0.1', '-p', fixture.env['FORKLIFT_DNS_PORT'], owner, kind, '+time=1', '+tries=1']).stdout.decode()
                    assert 'status: NOERROR' in text and value in text, text
                dig('existing.example.test.', 'A', '192.168.1.50')
                dig('50.1.168.192.in-addr.arpa.', 'PTR', 'existing.example.test.')
                desired = dict(host['dns'], ipv4='192.168.1.51')
                updated = r('/api/hosts/'+host['id'], 'PUT', {k:saved[k] for k in ['name', 'hostname', 'endpoints', 'allowed_groups', 'revision']} | dict(dns=desired))
                assert updated['dns_status']['state'] == 'applied', updated
                dig('existing.example.test.', 'A', '192.168.1.51')
                assert not any(v['name'] == '50.1.168.192.in-addr.arpa.' for v in r('/api/dns/zones/1.168.192.in-addr.arpa.')['rrsets'])
            print('PASS: actual '+('Phase 3 manager/primary DNS' if with_dns else 'pre-DNS')+' upgrade preserves LDAP credentials, IDs, groups, host policies, sessions and schema-5 metadata'+('; DNS SQLite, credentials and forward/PTR ownership survive and reconcile.' if with_dns else '; DNS initializes without resetting LDAP.'), flush=True)
        finally:
            fixture.files = ['-f', str(SOURCE/'compose.yaml')]
            fixture.compose('down', '--remove-orphans', check=False)
            run(['docker', 'image', 'rm', image, maintenance_image, *([dns_image] if with_dns else [])], check=False)


upgrade('804bb40')
upgrade('e9a4b24', with_dns=True)
