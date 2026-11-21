"""Runs inside the integration harness; no passwords in arguments, files, or logs."""
import configparser
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time


def exercise(project, request, compose, password, find_user):
    name = project + '-ubuntu'
    directory = tempfile.TemporaryDirectory(prefix='forklift-client-')
    bundle = Path(directory.name)
    def docker(*args, input=None, check=True):
        return subprocess.run(['docker', *args],input=input,capture_output=True,check=check)
    def command(*args, input=None, check=True):
        return docker('exec','-i',name,*args,input=input,check=check)
    def ansible():
        r=command('ansible-playbook','-i','/tmp/inventory','/workspace/ansible/playbook.yml','-e','forklift_bundle_dir=/bundle','-e','forklift_manage_services=false')
        return r.stdout.decode()
    def restart_sssd():
        command('sh','-c','if [ -f /run/sssd.pid ]; then kill "$(cat /run/sssd.pid)"; fi; sleep 1; sssd -D')
    def ssh(username, passwd, allowed=True):
        # sshpass reads the password from a pipe, never from argv or environment.
        code='''import os,subprocess,sys
password=sys.stdin.buffer.read()
r,w=os.pipe();os.write(w,password+b'\\n');os.close(w)
try:
 p=subprocess.run(['sshpass','-d',str(r),'ssh','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile=/tmp/forklift-known-hosts','-o','ConnectTimeout=8','-o','NumberOfPasswordPrompts=1','-o','PreferredAuthentications=password','-p','2222',sys.argv[1]+'@127.0.0.1','id -u'],pass_fds=(r,),capture_output=True,timeout=25)
 sys.exit(p.returncode)
finally: os.close(r)
'''
        r=command('python3','-c',code,username,input=passwd.encode(),check=False)
        assert (r.returncode==0)==allowed, f'Unexpected SSH result for {username} (exit {r.returncode})'
    try:
        print('Testing Ubuntu 24.04 Ansible, NSS, PAM and actual SSH passwords…',flush=True)
        request('/api/groups/ssh-allowed','PUT',dict(name='ssh-allowed',members=['bob']))
        host=request('/api/hosts','POST',dict(name='Ubuntu client',hostname='ubuntu.integration.test',endpoints=['ldaps://ldap:1636','ldaps://ldap:636'],allowed_groups=['ssh-allowed']))
        data=request(f"/api/hosts/{host['id']}/bundle",'POST',dict(revision=1,rotate=True),raw=True)
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
            archive.extractall(bundle,filter='data')
        assert (bundle/'sssd.conf').stat().st_mode & 0o777 == 0o600
        conf=configparser.ConfigParser(interpolation=None);conf.read(bundle/'sssd.conf')
        bind=conf['domain/forklift']['ldap_default_authtok']
        dn=conf['domain/forklift']['ldap_default_bind_dn']
        # Ensure this identity is read-only and cannot read password hashes.
        code='''import json,subprocess,sys,os
p=json.load(sys.stdin)
base=['-x','-H','ldaps://ldap:636','-D',p['dn'],'-y','/dev/stdin']
env={**os.environ,'LDAPTLS_CACERT':'/run/secrets/ca.crt'}
r=subprocess.run(['ldapsearch',*base,'-LLL','-b',p['base'],'(uid=bob)','userPassword'],input=p['pw'].encode(),env=env,capture_output=True)
assert r.returncode==0 and b'userPassword:' not in r.stdout
ldif=('dn: uid=bob,ou=people,'+p['base']+'\\nchangetype: modify\\nreplace: description\\ndescription: forbidden\\n').encode()
# Separate password and LDIF streams using a private pipe inherited only by ldapmodify.
rfd,wfd=os.pipe();os.write(wfd,p['pw'].encode());os.close(wfd)
base[-1]='/dev/fd/'+str(rfd)
r=subprocess.run(['ldapmodify',*base],input=ldif,pass_fds=(rfd,),env=env,capture_output=True)
os.close(rfd)
assert r.returncode==50
'''
        compose('exec','-T','ldap','python3','-c',code,input=json.dumps(dict(dn=dn,pw=bind,base='dc=integration,dc=test')).encode())
        docker('run','-d','--name',name,'--network',project+'_directory','-v',str(Path('ansible').resolve())+':/workspace/ansible:ro','forklift-ubuntu-client')
        docker('network','connect',project+'_web',name)
        docker('cp',str(bundle)+'/.',name+':/bundle')
        command('sh','-c',"printf '[forklift_clients]\\nlocalhost ansible_connection=local\\n' > /tmp/inventory")
        ansible()
        second=ansible()
        assert 'changed=0' in second, 'Ansible role was not idempotent'
        command('sssctl','config-check')
        command('sssd','-D')
        command('/usr/sbin/sshd','-p','2222')
        for _ in range(30):
            r=command('getent','passwd','bob',check=False)
            if r.returncode==0: break
            time.sleep(1)
        assert r.returncode==0 and b'/home/bob' in r.stdout, 'NSS did not resolve the LDAP account'
        uid=int(find_user('bob')['attrs']['uidNumber'][0])
        assert f':{uid}:'.encode() in r.stdout
        assert b'ssh-allowed' in command('id','bob').stdout, 'Supplemental LDAP group was not resolved'
        ssh('bob',password)
        ssh('bob','wrong-password',False)
        command('test','-d','/home/bob')
        # A valid directory password without the allowed group must fail at the host.
        request('/api/users','POST',dict(username='charlie',display_name='Charlie',email='',description='',shell='/bin/bash',home='/home/charlie',gid=10000,password=password,disabled=False))
        ssh('charlie',password,False)
        # Membership changes require no new export. Restart only to clear identity caches in this fast test.
        request('/api/groups/ssh-allowed','PUT',dict(name='ssh-allowed',members=['charlie']))
        command('sss_cache','-E')
        restart_sssd()
        ssh('bob',password,False)
        ssh('charlie',password)
        record=dict(username='charlie',display_name='Charlie',email='',description='',shell='/bin/bash',home='/home/charlie',gid=10000,disabled=True)
        request('/api/users','POST',record)
        command('sss_cache','-E')
        restart_sssd()
        ssh('charlie',password,False)
        # Account phase alone must deny expired users, even without a password authentication step.
        r=command('pamtester','sshd','charlie','acct_mgmt',check=False)
        assert r.returncode!=0, 'Expired account passed PAM account checks'
        # Wrong CA must make a new SSSD lookup/authentication fail closed.
        record.update(disabled=False,password=password);request('/api/users','POST',record)
        command('sh','-c','cp /etc/sssd/forklift-ca.crt /tmp/real-ca.crt; cp /etc/ssl/certs/ca-certificates.crt /etc/sssd/forklift-ca.crt')
        command('sss_cache','-E');restart_sssd();ssh('charlie',password,False)
        command('cp','/tmp/real-ca.crt','/etc/sssd/forklift-ca.crt');restart_sssd()
        ssh('charlie',password)
        # Local recovery accounts retain access independently of LDAP groups.
        command('useradd','-m','-s','/bin/bash','localrecovery')
        command('chpasswd',input=('localrecovery:'+password+'\n').encode())
        ssh('localrecovery',password)
        # Existing host configuration remains usable with the manager stopped.
        compose('stop','manager');ssh('charlie',password);compose('start','manager')
        for _ in range(30):
            try: request('/ready');break
            except Exception: time.sleep(1)
        # No cached password login while the directory is down (default offline policy).
        compose('stop','ldap');restart_sssd();ssh('charlie',password,False);ssh('localrecovery',password);compose('start','ldap')
        for _ in range(30):
            try: request('/ready');break
            except Exception: time.sleep(1)
        restart_sssd();ssh('charlie',password)
        # A host read credential is not a host authentication ban: users have their own LDAP credentials.
        request(f"/api/hosts/{host['id']}",'DELETE')
        revoked_test = "import subprocess,sys,os,json; p=json.load(sys.stdin); r=subprocess.run(['ldapwhoami','-x','-H','ldaps://ldap:636','-D',p['dn'],'-y','/dev/stdin'],input=p['pw'].encode(),env={**os.environ,'LDAPTLS_CACERT':'/run/secrets/ca.crt'},capture_output=True); assert r.returncode==49"
        compose('exec','-T','ldap','python3','-c',revoked_test,input=json.dumps(dict(dn=dn,pw=bind)).encode())
        print('PASS: Ubuntu Ansible idempotence, UID/GID/NSS, home creation, SSH allow/deny, membership updates, account expiry, CA rejection, local recovery, endpoint fallback, outages and host credential revocation.',flush=True)
    finally:
        docker('rm','-f',name,check=False)
        directory.cleanup()
