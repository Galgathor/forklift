#!/usr/bin/env python3
"""Actual native client -> fixed local Docker Compose -> verified OpenLDAP replica; isolated test volumes only."""
import json,os,re,select,signal,socket,subprocess,time,base64,hashlib,secrets,urllib.request,urllib.error
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from pathlib import Path
from fixture import Stack,SOURCE,run,port
CLIENT=SOURCE.parent/'forklift-client/target/release/forklift-client'
assert (SOURCE/'backend/assets/replica.py').read_bytes()==(SOURCE.parent/'forklift-client/assets/ldap-replica/replica.py').read_bytes()
assert (SOURCE/'backend/assets/replica.Dockerfile').read_bytes()==(SOURCE.parent/'forklift-client/assets/ldap-replica/Dockerfile').read_bytes()
with Stack(https=True) as s:
    s.setup();r=s.request;directory=Path('/var/lib')/(s.project+'-replica-client');run(['sudo','-n','mkdir','-m','700',str(directory)]);run(['sudo','-n','install','-m','0755',str(CLIENT),str(directory/'forklift-client')])
    processes=[];project=None;units=[]
    service_properties=[]
    for line in (SOURCE.parent/'forklift-client/systemd/forklift-client.service').read_text().splitlines():
        if line.startswith(('NoNewPrivileges=','Protect','Private','Restrict','LockPersonality=','MemoryDeny','CapabilityBoundingSet=','AmbientCapabilities=','SystemCallArchitectures=','MemoryMax=','LimitCORE=','UMask=')):service_properties += ['--property='+line]
    def cli(*args,check=True):return run(['sudo','-n',str(CLIENT),'--state-dir',str(directory),*args],check=check)
    def start(*args):
        unit=None
        command=['sudo','-n',str(CLIENT),'--state-dir',str(directory),*args]
        if args==('daemon',):
            unit=s.project+'-native-'+secrets.token_hex(4)+'.service';units.append(unit)
            command=['sudo','-n','systemd-run','--unit='+unit,'--collect','--wait','--pipe','--service-type=exec',*service_properties,'--property=User=root','--property=ReadWritePaths='+str(directory),str(directory/'forklift-client'),'--state-dir',str(directory),*args]
        p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);p.unit=unit;processes.append(p)
        if unit:
            for _ in range(100):
                pid=run(['sudo','-n','systemctl','show',unit,'-p','MainPID','--value'],check=False).stdout.strip()
                if pid.isdigit() and int(pid)>0:p.target_pid=int(pid);break
                if p.poll() is not None:raise AssertionError('Hardened client service could not start: '+p.stderr.read().decode()[-800:])
                time.sleep(.05)
            else:raise AssertionError('Native systemd PID missing')
        else:p.target_pid=p.pid
        return p
    def stop(p):
        if p.poll() is None:
            if p.unit:run(['sudo','-n','systemctl','stop',p.unit],check=False)
            else:run(['sudo','-n','kill','-TERM','--','-'+str(p.pid)],check=False)
            p.wait(timeout=25)
    def wait(fn,seconds=180):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            value=fn()
            if value:return value
            time.sleep(.5)
        raise AssertionError('Client replica deployment did not reach expected state')
    def browser(action,**extra):
        deps=Path(os.environ.get('FORKLIFT_TEST_BROWSER_DEPS','/tmp/forklift-m4-browser/node_modules')).resolve()
        result=run(['docker','run','--rm','-i','--network','host','--user',str(os.getuid())+':'+str(os.getgid()),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--tmpfs','/tmp:rw,nosuid,size=256m','--shm-size','256m','-e','NODE_PATH=/deps','-v',str(deps)+':/deps:ro','-v',str(SOURCE/'tests/client_replica_browser.cjs')+':/test.cjs:ro','mcr.microsoft.com/playwright:v1.65.0-noble@sha256:6e3fb709361521eb27161606e6da6d2674e5e89fa16516cb37d6fdd91372273d','node','/test.cjs'],data=json.dumps(dict(url=s.url,password=s.password,action=action,**extra)).encode());print(result.stdout.decode(),end='',flush=True)
    try:
        p=start('join','--server',s.url,'--ca-file',str(s.root/'ca.crt'),'--hostname','replica-machine.example.test','--interval','30','--include-interface','docker0')
        output='';end=time.monotonic()+30
        while time.monotonic()<end:
            if p.poll() is not None:raise AssertionError('Native enrollment failed')
            if select.select([p.stdout],[],[],.2)[0]:output+=os.read(p.stdout.fileno(),4096).decode()
            code=re.search(r'Enrollment code: ([A-Z2-9]{4}-[A-Z2-9]{4})',output)
            if code:break
        else:raise AssertionError('No pairing code')
        pending=r('/api/clients/lookup','POST',dict(code=code[1]));approved=r('/api/clients/'+pending['id']+'/approve','POST',dict(name='Replica machine',host_id=None,host_revision=None,acknowledge=True));p.communicate(timeout=30);assert p.returncode==0
        host_id=approved['host_id'];path='/api/hosts/'+host_id+'/replica-deployment'
        def host():return next(h for h in r('/api/hosts') if h['id']==host_id)
        def job():return r(path)['deployment']
        daemon=start('daemon');wait(lambda:host()['client'].get('monitoring',{}).get('inventory'));stop(daemon)
        assert 'replica-deploy-v1' in host()['client']['monitoring']['inventory']['capabilities']
        address=s.net['address'];ldap_port=port();control=port()
        request=dict(address=address,port=ldap_port,control_port=control,acknowledge=True)
        r(path,'POST',request,authenticated=False,expect=401);r(path,'POST',request,use_csrf=False,expect=403);r(path,'POST',request|dict(acknowledge=False),expect=400)
        r(path,'POST',request|dict(command='forbidden'),expect=422,raw=True)
        r(path,'POST',request|dict(address='192.168.1.254'),expect=400)
        r('/api/users','POST',s.user('replica-login'))
        before=host();browser('deploy',address=address,port=ldap_port,control=control)
        queued=job();project='forklift-replica-'+queued['id'];volume=project+'_replica_data'
        saved=json.loads(run(['sudo','-n','cat',str(directory/'state.json')]).stdout)
        def machine(action,body,expect=200,target=host_id):
            route='/api/client/v1/hosts/'+target+'/deployments/'+action
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=s.context))
            with opener.open(s.url+'/api/client/v1/info') as reply:nonce=reply.headers['DPoP-Nonce']
            key=serialization.load_pem_private_key(saved['private_key'].encode(),password=None);public=key.public_key().public_numbers()
            def enc(b):return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
            header=dict(typ='dpop+jwt',alg='ES256',jwk=dict(kty='EC',crv='P-256',x=enc(public.x.to_bytes(32,'big')),y=enc(public.y.to_bytes(32,'big'))))
            claims=dict(jti=secrets.token_hex(32),htm='POST',htu=s.url+route,iat=int(time.time()),nonce=nonce,ath=enc(hashlib.sha256(saved['access_token'].encode()).digest()))
            proof=enc(json.dumps(header,separators=(',',':')).encode())+'.'+enc(json.dumps(claims,separators=(',',':')).encode());x,y=decode_dss_signature(key.sign(proof.encode(),ec.ECDSA(hashes.SHA256())));proof+='.'+enc(x.to_bytes(32,'big')+y.to_bytes(32,'big'))
            request=urllib.request.Request(s.url+route,method='POST',data=json.dumps(body).encode(),headers={'Content-Type':'application/json','DPoP':proof,'Authorization':'DPoP '+saved['access_token']})
            try:response=opener.open(request)
            except urllib.error.HTTPError as error:response=error
            with response:
                assert response.code==expect,('Machine deployment status',response.code,expect)
                return json.loads(response.read())
        machine('poll',{},target='f'*32,expect=401)
        machine('grant',dict(job_id='f'*32,attempt=queued['attempt']),expect=409)
        machine('progress',dict(job_id=queued['id'],attempt=queued['attempt']+1,stage='awaiting_sync',error=None),expect=409)

        assert host()['directory_id']==queued['directory_id'] and host()['hostname']==before['hostname'] and host()['allowed_groups']==before['allowed_groups']
        assert len([h for h in r('/api/hosts') if h.get('directory_id')==queued['directory_id']])==1
        # Unknown persistent storage must never be silently adopted, reset or deleted.
        run(['docker','volume','create',volume]);daemon=start('daemon');wait(lambda:job()['stage']=='failed');stop(daemon)
        assert 'existing replica volume' in job()['error'].lower(),job()
        run(['docker','volume','inspect',volume]);run(['docker','volume','rm',volume])
        print('PASS: explicit machine-bound WebUI approval, retained host identity/login policy, rejected unknown volume, no destructive cleanup and actionable deployment failure.',flush=True)
        r(path+'/action','POST',dict(action='cancel',acknowledge=True));assert machine('poll',{})['deployment'] is None
        machine('grant',dict(job_id=queued['id'],attempt=queued['attempt']),expect=409)
        browser('retry')
        # Watch the atomic preparation journal before starting the process: cached builds can pass this stage too quickly for HTTP polling.
        watch_program="""import ctypes,json,os,select,signal,sys,time
from pathlib import Path
lib=ctypes.CDLL(None);fd=lib.inotify_init1(0)
assert fd>=0 and lib.inotify_add_watch(fd,os.fsencode(sys.argv[1]),128)>=0
print('READY',flush=True);pid=int(sys.stdin.readline());assert pid>1
end=time.monotonic()+60
while time.monotonic()<end:
 if not select.select([fd],[],[],2)[0]:continue
 os.read(fd,65536)
 try:v=json.loads((Path(sys.argv[1])/'replica-deployment.json').read_text())
 except FileNotFoundError:continue
 if v['stage']=='preparing':os.kill(pid,signal.SIGTERM);print('INTERRUPTED',flush=True);break
else:raise AssertionError('No durable preparing transition observed')
"""
        watcher=subprocess.Popen(['sudo','-n','python3','-u','-c',watch_program,str(directory)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        assert watcher.stdout.readline().strip()==b'READY'
        daemon=start('daemon');out,err=watcher.communicate(str(daemon.target_pid).encode()+b'\n',timeout=70);assert watcher.returncode==0,err[-500:];daemon.wait(timeout=25)

        # Resume from durable ownership/preparation after an interrupted native process.
        daemon=start('daemon');wait(lambda:job()['stage'] in ['failed','awaiting_sync'],900)
        assert job()['stage']=='awaiting_sync',job()
        synced=wait(lambda:(v if v.get('replica',{}).get('state')=='synchronized' else None) if (v:=r(path)) else None,180)
        container=project+'-replica-1';assert synced['replica']['last_sync_at']
        settings=json.loads(run(['docker','inspect','--format','{{json .HostConfig}}',container]).stdout)
        assert settings['ReadonlyRootfs'] and not settings['Privileged'] and settings['CapDrop']==['ALL'] and not settings.get('CapAdd')
        mounts=json.loads(run(['docker','inspect','--format','{{json .Mounts}}',container]).stdout)
        assert all(m['Source']=='/etc/ssl/certs/ca-certificates.crt' and m['RW'] is False for m in mounts if m['Type']=='bind')
        env=json.loads(run(['docker','inspect','--format','{{json .Config.Env}}',container]).stdout)
        assert 'FORKLIFT_REPLICA_JOIN=' in env and not any(v.startswith('FORKLIFT_REPLICA_JOIN=') and v!='FORKLIFT_REPLICA_JOIN=' for v in env)
        def bind():
            program="import subprocess,sys,os; r=subprocess.run(['ldapwhoami','-x','-H',sys.argv[1],'-D','uid=replica-login,ou=people,dc=integration,dc=test','-y','/dev/stdin'],input=sys.stdin.buffer.read(),capture_output=True,env={**os.environ,'LDAPTLS_CACERT':'/directory/server.crt'});sys.exit(r.returncode)"
            run(['docker','exec','-i',container,'python3','-c',program,'ldaps://'+address+':'+str(ldap_port)],data=s.password.encode())
        bind();stop(daemon)
        run(['docker','restart',container]);wait(lambda:run(['docker','inspect','--format','{{.State.Health.Status}}',container],check=False).stdout.strip()==b'healthy')
        s.compose('stop','manager','ldap');bind();s.compose('start','ldap','manager');s.wait()
        print('PASS: actual native Docker build/Compose deployment, interrupted-process resume, verified LDAP synchronization, consumed-secret removal, independent restart and real authentication with client/manager/primary offline.',flush=True)
    finally:
        for p in processes:stop(p)
        for unit in units:run(['sudo','-n','systemctl','stop',unit],check=False)
        if project:
            container=project+'-replica-1';run(['docker','rm','-f',container],check=False);run(['docker','volume','rm',project+'_replica_data'],check=False)
        run(['sudo','-n','rm','-rf','--',str(directory)])
