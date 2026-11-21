#!/bin/sh
# Local operator action; the WebUI has no CA signing key or command access.
set -eu
cd "$(dirname "$0")/.."
ldap_dns=${1:?Usage: scripts/renew-ldap-certificate.sh ldap.example.com}
case "$ldap_dns" in *[!a-z0-9.-]*|'') echo 'Use a lowercase DNS hostname.' >&2; exit 1;; esac
[ ${#ldap_dns} -le 253 ] || exit 1
umask 077
exec 9> .forklift-maintenance.lock
flock -n 9 || { echo 'Another maintenance operation is active.' >&2; exit 1; }
[ ! -f .forklift-maintenance.json ] || { echo 'Resume pending maintenance first.' >&2; exit 1; }
docker run --rm -i --user 0:0 --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER --security-opt no-new-privileges:true --entrypoint python3 -e LDAP_DNS="$ldap_dns" -v "$PWD/.secrets:/secrets" forklift-ldap:latest - <<'PY'
import json, os, re, subprocess
from pathlib import Path
root=Path('/secrets')
os.umask(0o077)
def run(*args,data=None):
    return subprocess.run(args,input=data,capture_output=True,check=True).stdout

def atomic(path,data):
    temporary=path.with_name(path.name+'.tmp')
    with open(temporary,'wb') as out:
        out.write(data);out.flush();os.fsync(out.fileno())
    temporary.replace(path)
    fd=os.open(root,os.O_DIRECTORY);os.fsync(fd);os.close(fd)

def hostname(name):
    return len(name)<=253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in name.split('.'))
try:
    requested=os.environ['LDAP_DNS']
    if not hostname(requested):raise ValueError('Invalid DNS hostname')
    if (root/'service-rotation.json').exists():raise ValueError('Resume service rotation first')
    journal=root/'certificate-renewal.json'
    if journal.exists():
        state=json.loads(journal.read_text())
        if state['requested']!=requested:raise ValueError('Resume renewal with the original requested DNS name')
    else:
        extension=run('openssl','x509','-in',str(root/'ldap.crt'),'-noout','-ext','subjectAltName').decode()
        names={'ldap',requested}
        for name in re.findall(r'DNS:([^,\s]+)',extension):
            if not hostname(name):raise ValueError('Unsupported existing DNS SAN')
            names.add(name)
        if 'IP Address:' in extension or 'URI:' in extension or 'email:' in extension:raise ValueError('Custom SAN types require a reviewed renewal procedure')
        run('openssl','req','-new','-newkey','rsa:3072','-nodes','-subj','/CN=ldap','-keyout',str(root/'ldap.key.new'),'-out',str(root/'ldap.csr.new'))
        atomic(root/'extensions.new',('basicConstraints=critical,CA:FALSE\nsubjectAltName='+','.join('DNS:'+name for name in sorted(names))+'\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n').encode())
        run('openssl','x509','-req','-in',str(root/'ldap.csr.new'),'-CA',str(root/'ca.crt'),'-CAkey',str(root/'ca.key'),'-CAcreateserial','-days','365','-extfile',str(root/'extensions.new'),'-out',str(root/'ldap.crt.new'))
        for name in names:run('openssl','verify','-CAfile',str(root/'ca.crt'),'-verify_hostname',name,str(root/'ldap.crt.new'))
        atomic(root/'ldap.key.previous',(root/'ldap.key').read_bytes())
        atomic(root/'ldap.crt.previous',(root/'ldap.crt').read_bytes())
        for name in ['ldap.key.new','ldap.crt.new']:
            with open(root/name,'rb') as durable:os.fsync(durable.fileno())
        state={'requested':requested,'names':sorted(names)}
        atomic(journal,json.dumps(state).encode())
    # Roll forward the same validated pair after interrupted in-place publication.
    for name in state['names']:run('openssl','verify','-CAfile',str(root/'ca.crt'),'-verify_hostname',name,str(root/'ldap.crt.new'))
    key=run('openssl','pkey','-in',str(root/'ldap.key.new'),'-pubout','-outform','DER')
    cert_key=run('openssl','x509','-in',str(root/'ldap.crt.new'),'-pubkey','-noout')
    if key != run('openssl','pkey','-pubin','-outform','DER',data=cert_key):raise ValueError('Candidate pair does not match')
    for name in ['ldap.key','ldap.crt']:
        with open(root/name,'wb') as stream:
            stream.write((root/(name+'.new')).read_bytes());stream.flush();os.fsync(stream.fileno())
        os.chown(root/name,10001,10001);os.chmod(root/name,0o600 if name.endswith('key') else 0o644)
    # Candidate files remain until publication has been durably acknowledged.
    journal.unlink();fd=os.open(root,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    for name in ['ldap.key.new','ldap.crt.new','ldap.csr.new','extensions.new']:(root/name).unlink(missing_ok=True)
except Exception as exc:
    print(str(exc) if isinstance(exc,ValueError) else 'Certificate renewal failed ('+type(exc).__name__+'); preserve files and rerun with the same hostname',file=__import__('sys').stderr)
    raise SystemExit(1)
PY
printf '\nCertificate updated. Restart LDAP during a maintenance window and verify actual client binds.\n'
