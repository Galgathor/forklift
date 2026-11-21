#!/usr/bin/env python3
"""Verify local LDAPS renewal using a disposable CA, never installation secrets."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
def run(*args, cwd):
    result=subprocess.run(args,cwd=cwd,capture_output=True)
    if result.returncode:
        raise RuntimeError('Certificate fixture command failed: '+result.stderr.decode(errors='replace')[-500:])
    return result
old_umask=os.umask(0o077)
try:
    with tempfile.TemporaryDirectory(prefix='forklift-cert-test-') as folder:
        root=Path(folder);(root/'scripts').mkdir();(root/'.secrets').mkdir()
        shutil.copy2(ROOT/'scripts/renew-ldap-certificate.sh',root/'scripts/renew-ldap-certificate.sh')
        run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Disposable Test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout','.secrets/ca.key','-out','.secrets/ca.crt',cwd=root)
        run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=old','-keyout','.secrets/ldap.key','-out','.secrets/ldap.crt',cwd=root)
        ca=(root/'.secrets/ca.crt').read_bytes();previous=(root/'.secrets/ldap.crt').read_bytes()
        run('./scripts/renew-ldap-certificate.sh','ldap.integration.test',cwd=root)
        assert (root/'.secrets/ca.crt').read_bytes()==ca,'Renewal replaced CA trust'
        assert (root/'.secrets/ldap.crt').read_bytes()!=previous,'Certificate was not replaced'
        assert (root/'.secrets/ldap.key').stat().st_mode & 0o777 == 0o600
        assert (root/'.secrets/ldap.key').stat().st_uid == 10001
        run('./scripts/renew-ldap-certificate.sh','ldap.second.test',cwd=root)
        for name in ['ldap','ldap.integration.test','ldap.second.test']:
            run('openssl','verify','-CAfile','.secrets/ca.crt','-verify_hostname',name,'.secrets/ldap.crt',cwd=root)
        # An interrupted in-place publication must roll the validated candidate forward.
        fault="import json,pathlib; r=pathlib.Path('/secrets');[(r/(n+'.new')).write_bytes((r/n).read_bytes()) for n in ['ldap.key','ldap.crt']];(r/'certificate-renewal.json').write_text(json.dumps(dict(requested='ldap.second.test',names=['ldap','ldap.integration.test','ldap.second.test'])));(r/'ldap.key').write_bytes(b'interrupted')"
        run('docker','run','--rm','--network','none','--user','0:0','--entrypoint','python3','-v',str(root/'.secrets')+':/secrets','forklift-ldap','-c',fault,cwd=root)
        run('./scripts/renew-ldap-certificate.sh','ldap.second.test',cwd=root)
        assert not (root/'.secrets/certificate-renewal.json').exists()
        run('openssl','verify','-CAfile','.secrets/ca.crt','-verify_hostname','ldap.integration.test','.secrets/ldap.crt',cwd=root)
        invalid=subprocess.run(['./scripts/renew-ldap-certificate.sh','bad\nDNS:evil'],cwd=root,capture_output=True)
        assert invalid.returncode!=0
        print('PASS: certificate renewal preserves CA, validates internal/external DNS SANs, restricts key permissions, resumes interrupted pair publication and rejects injected SAN input.')
finally:
    os.umask(old_umask)
