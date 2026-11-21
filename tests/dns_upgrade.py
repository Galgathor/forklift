#!/usr/bin/env python3
"""Upgrade a populated pre-DNS schema-5 installation without resetting LDAP/metadata."""
import io,tarfile
from fixture import Stack,SOURCE,run

with Stack() as fixture:
    # Replace the initially empty fixture with the committed pre-DNS deployment.
    fixture.compose('down','--volumes','--remove-orphans')
    source=fixture.root/'pre-dns';source.mkdir()
    archive=run(['git','archive','804bb40'],cwd=SOURCE).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:tar.extractall(source,filter='data')
    image=fixture.project+'-pre-dns-manager'
    run(['docker','build','-t',image,'-f','docker/manager/Dockerfile','.'],cwd=source)
    override=fixture.root/'old-image.yaml';override.write_text('services:\n  manager:\n    image: '+image+'\n')
    old_files=['-f',str(source/'compose.yaml'),'-f',str(override)]
    try:
        fixture.files=old_files;fixture.compose('up','-d','--no-build','--wait');fixture.wait('/health');fixture.setup()
        fixture.request('/api/users','POST',fixture.user('preserved'))
        fixture.request('/api/groups/existing-policy','PUT',dict(name='existing-policy',members=['preserved']))
        host=fixture.request('/api/hosts','POST',dict(name='Existing Linux host',hostname='existing.test',endpoints=['ldaps://'+fixture.net['address']+':'+str(fixture.net['port'])],allowed_groups=['existing-policy']))
        before=fixture.request('/api/overview')
        fixture.files=['-f',str(SOURCE/'compose.yaml')]
        fixture.compose('up','-d','--no-build','--force-recreate','--wait');fixture.wait();fixture.request('/api/me');fixture.bind('preserved')
        after=fixture.request('/api/overview')
        assert before['users']==after['users'] and before['groups']==after['groups']
        assert next(h for h in after['hosts'] if h['id']==host['id'])['allowed_groups']==['existing-policy']
        assert fixture.request('/api/dns')['available']
        schema=fixture.compose('exec','-T','maintenance','python3','-c',"import sqlite3;d=sqlite3.connect('/metadata/forklift.db');print(d.execute('PRAGMA user_version').fetchone()[0])").stdout.strip()
        assert schema==b'5'
        print('PASS: actual pre-DNS installation upgrade preserves passwords, numeric IDs, groups, host policies, session, schema-5 metadata and initializes DNS without resetting LDAP.',flush=True)
    finally:
        fixture.files=['-f',str(SOURCE/'compose.yaml')]
        run(['docker','image','rm',image],check=False)
