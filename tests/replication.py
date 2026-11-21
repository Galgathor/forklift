#!/usr/bin/env python3
"""Real HTTPS enrollment and WebUI-only replica lifecycle against Syncrepl."""
import io,json,os,shutil,tarfile,time
from fixture import Stack,port,run
with Stack(https=True) as s:
    s.setup();r=s.request
    primary=r('/api/overview')['hosts'][0];assert primary['directory_role']=='primary' and not primary['allowed_groups']
    r('/api/hosts/'+primary['id'],'DELETE',expect=400)
    r('/api/hosts/'+primary['id']+'/bundle','POST',dict(revision=primary['revision'],rotate=True),expect=400)
    draft=dict(name='Replica',address=s.net['address'],hostname=s.net['address'],port=port(),control_port=port())
    r('/api/directory-servers','POST',draft,authenticated=False,expect=401)
    r('/api/directory-servers','POST',draft,use_csrf=False,expect=403)
    node=r('/api/directory-servers','POST',draft);nodeid=node['id']
    assert len(r('/api/hosts'))==2
    data,_=r('/api/replicas/'+nodeid+'/bundle','POST',dict(acknowledge=True),raw=True)
    folder=s.root/'replica';folder.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as a:
        assert not any(n.endswith('.sh') or n=='.env' for n in a.getnames());a.extractall(folder,filter='data')
    enrollment=json.loads((folder/'enrollment/enrollment.json').read_text());assert enrollment['provider']=='ldaps://'+s.net['hostname']+':'+str(s.net['port'])
    shutil.copyfile(s.root/'ca.crt',folder/'enrollment/manager-ca.crt')
    project=s.project+'-replica'
    def compose(*args,check=True):return run(['docker','compose','-p',project,'-f',str(folder/'compose.yaml'),*args],cwd=folder,check=check)
    def synced():
        for _ in range(90):
            node=next(v for v in r('/api/directory-servers')['servers'] if v['id']==nodeid)
            if node['state']=='synchronized':assert node['context_csn'] and node['last_sync_at'];return node
            time.sleep(.5)
        raise AssertionError('Replica did not synchronize: '+str(node))
    try:
        compose('up','-d','--build','--wait');synced()
        r('/api/replicas/'+nodeid+'/bundle','POST',dict(acknowledge=True),expect=400)
        r('/api/users','POST',s.user('replicated'));synced()
        print('PASS: automatic inventory, scoped HTTPS enrollment, native Syncrepl and deployment without administrator scripts.',flush=True)
        path='/api/replicas/'+nodeid
        r(path+'/credential','POST',dict(acknowledge=True));assert synced()['credential_epoch']==2
        r(path+'/restart','POST',dict(acknowledge=True));synced()
        r(path+'/certificate','POST',dict(acknowledge=True));assert synced()['certificate_rotation_pending']
        for _ in range(5):
            result=r(path+'/certificate/finalize','POST',dict(acknowledge=True),expect=(200,400,503))
            if result.get('finalized'):break
            time.sleep(.5)
        else:raise AssertionError('Remote certificate activation failed')
        assert not synced()['certificate_rotation_pending']
        s.net['port']=port();s.job(dict(action='configure-primary',network=s.net,acknowledge=True))
        r(path+'/reconnect','POST',dict(acknowledge=True));assert not synced()['provider_needs_update']
        print('PASS: WebUI remote credential rotation, native restart, certificate generation/activation/retirement and primary address reconnection.',flush=True)
        # Configured replica can restart and authenticate while primary and manager are gone.
        s.compose('stop','manager','ldap');compose('restart','replica')
        for _ in range(45):
            state=compose('ps','--format','json').stdout.decode()
            if 'healthy' in state:break
            time.sleep(.5)
        code="import subprocess,sys,os; r=subprocess.run(['ldapwhoami','-x','-H',sys.argv[1],'-D','uid=replicated,ou=people,dc=integration,dc=test','-y','/dev/stdin'],input=sys.stdin.buffer.read(),capture_output=True,env={**os.environ,'LDAPTLS_CACERT':'/directory/server.crt'});sys.exit(r.returncode)"
        container=compose('ps','-q','replica').stdout.decode().strip()
        run(['docker','exec','-i',container,'python3','-c',code,'ldaps://'+draft['hostname']+':'+str(draft['port'])],data=s.password.encode())
        s.compose('start','ldap','manager');s.wait();synced()
        r(path,'DELETE');assert len(r('/api/hosts'))==1
        print('PASS: secondary restart/authentication with primary and manager unavailable; removing directory also removes its unconfigured inventory.',flush=True)
    finally:compose('down','--volumes','--remove-orphans',check=False)
