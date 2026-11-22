"""Milestone 3 checks against real Linux tools, LDAP/TLS and DNS, plus authoritative issue lifecycle."""
import io
import json
import secrets
import tarfile
import time
from pathlib import Path
from fixture import SOURCE, run


def exercise(s, client_binary, local_dir, saved, machine, proof, token, host_id, cli, state, browser, current_host, edit_monitor):
    r=s.request
    prefix='/api/client/v1/hosts/'+host_id
    profile_path=prefix+'/diagnostic-profile'
    report_path=prefix+'/diagnostics'
    detail_path='/api/hosts/'+host_id+'/diagnostics'
    def reset_limit():
        s.compose('exec','-T','maintenance','python3','-c',"import sqlite3,sys;d=sqlite3.connect('/metadata/forklift.db');d.execute('DELETE FROM client_limits WHERE scope=?',('diagnostics:'+sys.stdin.read(),));d.commit()",input=host_id.encode())
    def profile():return machine(profile_path,token,proof(profile_path,token))
    settings=r('/api/hosts/'+host_id+'/monitoring')['policy']['diagnostics']
    settings.update(authentication=True,ssh=True,test_user='client-test',test_group='client-checks',ssh_source='192.168.1.90',ssh_local='127.0.0.1',ssh_port=2223)
    r('/api/users','POST',s.user('client-test'))
    r('/api/groups/client-checks','PUT',dict(name='client-checks',members=['client-test']))
    host=current_host()
    r('/api/hosts/'+host_id,'PUT',{k:host[k] for k in ['name','hostname','endpoints','revision']}|dict(allowed_groups=['client-checks']))
    edit_monitor(diagnostics=settings)
    expected=profile()
    assert 'PRIVATE KEY' not in expected['ldap_ca'] and saved['access_token'] not in json.dumps(expected)
    assert expected['settings']['authentication'] and expected['allowed_groups']==['client-checks']
    r('/api/notifications',authenticated=False,expect=401)
    sequence=0
    def check(status='failure',id='sssd.service',**changes):
        return dict(id=id,status=status,severity='info',summary='SSSD service observation',details='Structured test observation',remediation='Review the local service',at=1)|changes
    def send(checks,seq=None,expect=200,revision=None,**changes):
        nonlocal sequence
        reset_limit()
        if seq is None:sequence+=1;seq=sequence
        return machine(report_path,token,proof(report_path,token),body=dict(api_version=1,sequence=seq,profile_revision=revision or expected['revision'],interval=300,checks=checks)|changes,expected=expect)
    def active():return [i for i in r(detail_path)['issues'] if i['state']=='active' and i['check_id']=='sssd.service']
    r(detail_path,authenticated=False,expect=401)
    machine(report_path,token,body=dict(api_version=1,sequence=1,profile_revision=expected['revision'],interval=300,checks=[check()]),expected=401)
    send([check()],revision='0'*64,expect=409)
    send([check(id='shell.command')],expect=400)
    send([check(),check()],expect=400)
    send([check()],expect=422,command='forbidden')
    send([check(details='x'*513)],expect=400)
    allowed=['client.enrollment','dns.resolver','dns.forward','dns.zone','sssd.installed','sssd.service','sssd.syntax','sssd.directory','sssd.online','nss.configuration','nss.user','nss.group','pam.integration','pam.access','ssh.installed','ssh.service','ssh.syntax','ssh.authentication','ssh.listener']+[prefix+str(i) for prefix in ['dns.reverse.','dns.authority.','ldap.endpoint.'] for i in range(4)]
    large=[check('unknown',id=id,summary='s'*200,details='d'*512,remediation='r'*400) for id in allowed]
    assert len(json.dumps(large))>16384
    send(large)
    foreign='/api/client/v1/hosts/'+'f'*32+'/diagnostics'
    machine(foreign,token,proof(foreign,token),body=dict(api_version=1,sequence=1,profile_revision=expected['revision'],interval=300,checks=[check()]),expected=401)
    first=send([check()]);assert not active()
    identical=send([check()],seq=sequence);assert first==identical and not active()
    send([check()]);issue=active()[0]
    assert issue['severity']=='critical' and issue['first_detected']>1
    initial_notifications=r('/api/notifications')['notifications']
    send([check()]);assert active()[0]['id']==issue['id']
    assert len(r('/api/notifications')['notifications'])==len(initial_notifications)
    r('/api/hosts/'+host_id+'/issues/'+issue['id'],'POST',dict(action='acknowledge'),use_csrf=False,expect=403)
    r('/api/hosts/'+host_id+'/issues/'+issue['id'],'POST',dict(action='resolve'),expect=400)
    browser('issues')
    assert active()[0]['acknowledged'] and active()[0]['state']=='active'
    notice=next(n for n in r('/api/notifications')['notifications'] if n['issue_id']==issue['id'])
    r('/api/notifications/'+str(notice['id']),'POST',dict(action='dismiss'),use_csrf=False,expect=403)
    r('/api/notifications/'+str(notice['id']),'POST',dict(action='dismiss'))
    assert active()[0]['state']=='active'
    send([check('unknown')]);assert active()[0]['verification']=='unknown'
    send([check('pass',id='client.enrollment')]);assert active()[0]['verification']=='not_reported'
    send([check('pass')]);assert not active()
    assert any(n['issue_id']==issue['id'] and n['kind']=='recovered' for n in r('/api/notifications')['notifications'])
    send([check('pass')],seq=sequence-1,expect=409)
    send([check('pass',id='client.enrollment')]);assert current_host()['client']['monitoring']['diagnostics']['health']=='unknown'
    # A profile change rejects old reports and retires superseded failures without a false recovery.
    send([check()]);send([check()]);old=active()[0]['id']
    settings['failure_threshold']=3;edit_monitor(diagnostics=settings)
    send([check('pass')],expect=409)
    expected=profile();send([check('unknown')]);assert active()[0]['id']==old
    settings['authentication']=False;edit_monitor(diagnostics=settings);expected=profile();send([check('pass',id='client.enrollment')]);assert not active()
    assert next(i for i in r(detail_path)['issues'] if i['id']==old)['state']=='retired'
    print('PASS: diagnostic profile/version/size/key authorization, distinct-failure thresholds, stable issues, idempotent reports, missing/unknown observations, positive recovery, notification deduplication, WebUI acknowledgment, and retired expectations.',flush=True)

    # Native read-only diagnostics inside the existing Ubuntu integration environment.
    # This is a disposable Linux test environment, not a client deployment image.
    settings['authentication']=True;edit_monitor(diagnostics=settings)
    name=s.project+'-diagnostic-linux'
    data,_=r('/api/hosts/'+host_id+'/bundle','POST',dict(revision=current_host()['revision'],rotate=True),raw=True)
    bundle=s.root/'diagnostic-bundle';bundle.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:archive.extractall(bundle,filter='data')
    def docker(*args,data=None,check=True):return run(['docker',*args],data=data,check=check)
    def command(*args,data=None,check=True):return docker('exec','-i',name,*args,data=data,check=check)
    def install_state(p):
        snapshot=state(local_dir);snapshot['diagnostic_profile']=p
        command('python3','-c',"import json,sys,os;from pathlib import Path;p=Path('/var/lib/forklift-client');p.mkdir(mode=0o700,exist_ok=True);f=p/'state.json';f.write_text(json.dumps(json.load(sys.stdin)));os.chmod(f,0o600)",data=json.dumps(snapshot).encode())
    def checks():
        output=command('/native/forklift-client','diagnostics').stdout
        assert saved['access_token'].encode() not in output and saved['private_key'].encode() not in output
        return {c['id']:c for c in json.loads(output)['checks']}
    try:
        docker('run','-d','--name',name,'--network','host','-v',str(client_binary)+':/native/forklift-client:ro','-v',str(SOURCE/'ansible')+':/workspace/ansible:ro','forklift-ubuntu-client')
        docker('cp',str(bundle)+'/.',name+':/bundle')
        command('python3','-c',"from pathlib import Path;Path('/tmp/inventory').write_text('[forklift_clients]\\nlocalhost ansible_connection=local\\n')")
        command('ansible-playbook','-i','/tmp/inventory','/workspace/ansible/playbook.yml','-e','forklift_bundle_dir=/bundle','-e','forklift_manage_services=false')
        command('sssd','-D');command('/usr/sbin/sshd','-p','2223')
        for _ in range(30):
            if command('getent','passwd','client-test',check=False).returncode==0:break
            time.sleep(.2)
        expected=profile()
        # The published DNS fixture is loopback-only; explicitly select that real listener locally.
        expected['authorities']=[dict(address='127.0.0.1',port=int(s.env['FORKLIFT_DNS_PORT']))]
        install_state(expected)
        healthy=checks()
        for id in ['sssd.installed','sssd.syntax','sssd.directory','nss.configuration','nss.user','nss.group','pam.integration','pam.access','ssh.installed','ssh.syntax','ssh.authentication','ssh.listener','ldap.endpoint.0','dns.authority.0']:
            assert healthy[id]['status']=='pass',(id,healthy[id])
        online=command('sssctl','domain-status','forklift','--online',data=b'',check=False)
        expected_online='pass' if online.returncode==0 and b'Online status: Online' in online.stdout else ('failure' if b'Online status: Offline' in online.stdout else 'unknown')
        assert healthy['sssd.online']['status']==expected_online
        import configparser
        parsed=configparser.ConfigParser(interpolation=None);parsed.read(bundle/'sssd.conf');bind_secret=parsed['domain/forklift']['ldap_default_authtok'].encode()
        assert bind_secret not in command('/native/forklift-client','diagnostics').stdout
        assert healthy['sssd.service']['status']=='unknown','A container without systemd must not invent service health'
        # Direct authoritative answers do not make an unconfigured normal resolver pass.
        assert healthy['dns.forward']['status']!='pass'
        # Actual configuration hashes must remain unchanged by all checks.
        checksum="import hashlib,json;from pathlib import Path;paths=['/etc/sssd/sssd.conf','/etc/nsswitch.conf','/etc/pam.d/sshd','/etc/ssh/sshd_config','/etc/resolv.conf'];print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths}))"
        before=command('python3','-c',checksum).stdout;checks();assert command('python3','-c',checksum).stdout==before
        original=command('cat','/etc/sssd/sssd.conf').stdout
        command('python3','-c',"import sys;from pathlib import Path;Path('/etc/sssd/sssd.conf').write_bytes(sys.stdin.buffer.read()+b'\\n[invalid section]\\ninvalid_option = true\\n')",data=original)
        assert checks()['sssd.syntax']['status']=='failure'
        command('python3','-c',"import sys;from pathlib import Path;Path('/etc/sssd/sssd.conf').write_bytes(sys.stdin.buffer.read())",data=original)
        command('python3','-c',"from pathlib import Path;Path('/etc/ssh/sshd_config.d/99-invalid.conf').write_text('InvalidForkliftOption yes\\n')")
        assert checks()['ssh.syntax']['status']=='failure'
        command('rm','/etc/ssh/sshd_config.d/99-invalid.conf')
        # NSS failures and authenticated TLS failures are observed independently.
        missing=json.loads(json.dumps(expected));missing['settings']['test_user']='missing-'+secrets.token_hex(4);missing['settings']['test_group']='missing-'+secrets.token_hex(4)
        missing['endpoints']=['ldaps://127.0.0.1:1'];install_state(missing)
        broken=checks();assert broken['nss.user']['status']=='failure' and broken['nss.group']['status']=='failure' and broken['ldap.endpoint.0']['status']=='failure'
        wrong_ca=json.loads(json.dumps(expected));wrong_ca['ldap_ca']=(s.root/'ca.crt').read_text();install_state(wrong_ca)
        # System trust does not contain the private LDAP CA; the management CA is unrelated.
        assert checks()['ldap.endpoint.0']['status']=='failure'
        install_state(expected)
        s.compose('stop','ldap')
        try:
            cached=checks();assert cached['ldap.endpoint.0']['status']=='failure' and cached['nss.user']['status']=='pass','Cached NSS resolution was confused with live LDAP connectivity'
            send(list(cached.values()))
        finally:s.compose('start','ldap');s.wait()
        command('python3','-c',"import os,signal;from pathlib import Path;os.kill(int(Path('/run/sshd.pid').read_text()),signal.SIGTERM)")
        assert checks()['ssh.listener']['status']=='failure'
        command('python3','-c',"import os,signal;from pathlib import Path;os.kill(int(Path('/run/sssd.pid').read_text()),signal.SIGTERM)")
        stopped=checks();assert stopped['sssd.online']['status']!='pass'
        # Actual observed checks travel through the same authenticated report API.
        send(list(stopped.values()))
        assert any(c['id']=='ssh.syntax' for c in r(detail_path)['checks'])
        print('PASS: real native Ubuntu SSSD/PAM/NSS/OpenSSH inspection, syntax failures, missing NSS identities, private-CA LDAPS verification/rejection, actual authoritative DNS versus normal resolver behavior, no credential output and unchanged system configuration.',flush=True)
    finally:docker('rm','-f',name,check=False)
    # Restore default expectations for following native network/outage checks.
    settings.update(authentication=False,ssh=False,failure_threshold=2);edit_monitor(diagnostics=settings)
    code="import json,sys;from pathlib import Path;p=Path(sys.argv[1]);v=json.loads(p.read_text());v['diagnostic_sequence']=int(sys.argv[2]);p.write_text(json.dumps(v))"
    run(['sudo','-n','python3','-c',code,str(local_dir/'state.json'),str(sequence)])
