#!/usr/bin/env python3
"""Verify local LDAPS renewal using a disposable CA, never installation secrets."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
def run(*args, cwd):
    return subprocess.run(args,cwd=cwd,check=True,capture_output=True)
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
        for name in ['ldap','ldap.integration.test']:
            run('openssl','verify','-CAfile','.secrets/ca.crt','-verify_hostname',name,'.secrets/ldap.crt',cwd=root)
        invalid=subprocess.run(['./scripts/renew-ldap-certificate.sh','bad\nDNS:evil'],cwd=root,capture_output=True)
        assert invalid.returncode!=0
        print('PASS: certificate renewal preserves CA, validates internal/external DNS SANs, restricts key permissions and rejects injected SAN input.')
finally:
    os.umask(old_umask)
