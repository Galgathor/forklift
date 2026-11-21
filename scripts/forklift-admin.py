#!/usr/bin/env python3
"""Offline local administration. Docker access is an operator privilege, never a WebUI capability."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

SOURCE=Path(__file__).resolve().parents[1]
TOOL='forklift-maintenance:latest'


def command(args, *, data=None, check=True):
    result=subprocess.run(args,input=data,capture_output=True)
    if check and result.returncode:
        # Do not print Compose environment, native-tool diagnostics, decrypted contents or secrets.
        raise RuntimeError('Operation failed ('+str(result.returncode)+'): '+args[0]+' '+(args[1] if len(args)>1 else ''))
    return result


def path(value):
    resolved=Path(value).expanduser().resolve()
    if ':' in str(resolved) or any(ord(c)<32 for c in str(resolved)):
        raise ValueError('Unsupported filesystem path')
    return resolved


def sha(file):
    with open(file,'rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def write_json(file,value):
    temporary=file.with_name(file.name+'.new')
    with open(temporary,'w') as stream:
        os.chmod(temporary,0o600);json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
    temporary.replace(file)
    descriptor=os.open(file.parent,os.O_DIRECTORY);os.fsync(descriptor);os.close(descriptor)


def toolbox(action,payload=None,mounts=None,*,raw=False):
    args=['docker','run','--rm','-i','--network','none','--read-only','--cap-drop','ALL',
          '--cap-add','DAC_OVERRIDE','--cap-add','CHOWN','--cap-add','FOWNER','--cap-add','SETUID','--cap-add','SETGID',
          '--security-opt','no-new-privileges:true','--memory','512m','--pids-limit','128','--tmpfs','/tmp:rw,noexec,nosuid,size=64m']
    for source,target,readonly in mounts or []:
        args+=['-v',str(source)+':'+target+(':ro' if readonly else '')]
    args += [TOOL,action]
    result=command(args,data=json.dumps(payload or {}).encode(),check=False)
    if result.returncode:
        try:message=json.loads(result.stderr)['error']
        except (ValueError,KeyError,TypeError):message='Maintenance helper failed; check image, permissions and resource limits'
        raise ValueError(action+': '+message)
    return result.stdout if raw else json.loads(result.stdout)


class Installation:
    def __init__(self,args):
        self.root=path(args.root)
        self.compose=['docker','compose','--project-directory',str(self.root)]
        if args.project:self.compose+=['-p',args.project]
        for name in args.file or []:self.compose+=['-f',str(path(name))]
        self.model=json.loads(command(self.compose+['config','--format','json']).stdout)
        self.project=self.model['name']
        self.actor='local-uid:'+str(os.getuid())
        self.state_file=self.root/'.forklift-maintenance.json'

    def containers(self):
        result={}
        for service in ['ldap','manager']:
            ids=command(self.compose+['ps','-a','-q',service]).stdout.decode().split()
            if len(ids)!=1:raise ValueError('Expected exactly one created '+service+' container')
            item=json.loads(command(['docker','inspect',ids[0]]).stdout)[0]
            labels=item['Config']['Labels'] or {}
            if labels.get('com.docker.compose.project')!=self.project or labels.get('com.docker.compose.service')!=service:
                raise ValueError('Container ownership mismatch')
            result[service]=item
        return result

    def volumes(self,containers=None):
        if containers:
            result={}
            for service,destination,role in [('ldap','/directory','directory'),('manager','/data','metadata')]:
                matches=[m for m in containers[service]['Mounts'] if m['Destination']==destination and m['Type']=='volume']
                if len(matches)!=1:raise ValueError('Maintenance requires named persistent volumes')
                result[role]=matches[0]['Name']
            # Never silently omit bind credentials from a customized installation.
            for service,files in [('ldap',['ca.crt','ldap.crt','ldap.key','service','provision']),('manager',['bootstrap','service','ca.crt'])]:
                actual={m['Destination']:m['Source'] for m in containers[service]['Mounts'] if m['Type']=='bind'}
                for name in files:
                    if actual.get('/run/secrets/'+name)!=str(self.root/'.secrets'/name):
                        raise ValueError('Custom secret mounts require a separately reviewed backup strategy')
            return result
        return {role:self.model['volumes'][role]['name'] for role in ['directory','metadata']}

    def source_mounts(self,volumes,readonly=True):
        return [(volumes['directory'],'/directory',readonly),(volumes['metadata'],'/metadata',readonly),(self.root/'.secrets','/secrets',readonly),(self.root/'.secrets','/run/secrets',True)]

    def ensure_current_images(self,containers=None):
        for service in ['ldap','manager']:
            image=containers[service]['Image'] if containers else self.model['services'][service].get('image',self.project+'-'+service)
            actual=json.loads(command(['docker','image','inspect',image]).stdout)[0]
            if actual['Config'].get('Labels',{}).get('io.forklift.maintenance-version')!='1':
                raise ValueError('Build/deploy Milestone 4 images before this operation')

    def stop(self,state):
        for service in ['manager','ldap']:
            info=state['containers'][service]
            if info['running']:
                command(['docker','stop','--time','30',info['id']])
                status=json.loads(command(['docker','inspect',info['id']]).stdout)[0]['State']
                if status.get('OOMKilled') or status.get('ExitCode')==137:
                    raise ValueError('Unclean forced shutdown; inspect the installation before snapshotting')

    def start(self,state):
        for service in ['ldap','manager']:
            info=state['containers'][service]
            if not info['running']:continue
            actual=json.loads(command(['docker','inspect',info['id']]).stdout)[0]
            labels=actual['Config'].get('Labels',{})
            if labels.get('com.docker.compose.project')!=self.project or labels.get('com.docker.compose.service')!=service:
                raise ValueError('Container changed during maintenance')
            command(['docker','start',info['id']])
            for _ in range(90):
                status=json.loads(command(['docker','inspect',info['id']]).stdout)[0]['State']
                if status.get('Health',{}).get('Status')=='healthy':break
                if not status['Running']:raise ValueError('A service did not restart; maintenance state retained')
                time.sleep(1)
            else:raise ValueError('A service did not become healthy; maintenance state retained')

    def save_state(self,kind,containers):
        if self.state_file.exists():raise ValueError('Pending maintenance exists; run resume first')
        state={'kind':kind,'operation_id':secrets.token_hex(16),'project':self.project,'actor':self.actor,
               'containers':{name:{'id':v['Id'],'running':v['State']['Running']} for name,v in containers.items()},
               'volumes':self.volumes(containers),'phase':'stopping'}
        write_json(self.state_file,state)
        return state


@contextmanager
def locked(installation):
    file=installation.root/'.forklift-maintenance.lock'
    with open(file,'a') as lock:
        os.chmod(file,0o600)
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Another maintenance operation is active')
        yield


def backup(installation,args):
    if not re.fullmatch(r'age1[0-9a-z]+',args.recipient):raise ValueError('Use a native age X25519 recipient')
    toolbox('recipient',{'recipient':args.recipient})
    output=path(args.output)
    if output.exists() or output.parent==installation.root/'.secrets':raise ValueError('Use a new backup filename outside installation secrets')
    output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    containers=installation.containers()
    state=installation.save_state('backup',containers)
    try:
        installation.stop(state)
        state['phase']='snapshot';write_json(installation.state_file,state)
        mounts=installation.source_mounts(state['volumes'],False)
        toolbox('event',{**state,'kind':'backup','status':'started'},mounts)
        source={'project':installation.project,'images':{k:v['Image'] for k,v in containers.items()},'checkout_revision':command(['git','-C',str(installation.root),'rev-parse','HEAD'],check=False).stdout.decode().strip()}
        packed=toolbox('pack',{**state,'source':source,'recipient':args.recipient,'filename':output.name,'owner_uid':os.getuid(),'owner_gid':os.getgid(),'max_bytes':args.max_gib*1024**3},
                       installation.source_mounts(state['volumes'])+[(installation.root/'.env','/installation/.env',True),(output.parent,'/output',False)])
        toolbox('event',{**state,'kind':'backup','status':'completed','artifact':packed['artifact'],'sha256':packed['sha256'],'detail':'Consistent offline snapshot encrypted with age'},mounts)
        print(json.dumps(packed),flush=True)
    except BaseException:
        try: toolbox('event',{**state,'kind':'backup','status':'failed','detail':'Snapshot command did not complete'},mounts)
        except Exception: pass
        raise
    finally:
        installation.start(state)
        installation.state_file.unlink()


def verified_stage(args):
    archive=path(args.archive);identity=path(args.identity)
    if not re.fullmatch('[a-f0-9]{64}',args.sha256) or sha(archive)!=args.sha256:
        raise ValueError('Archive does not match the trusted creation-time SHA-256')
    stage='forklift-restore-stage-'+secrets.token_hex(12)
    command(['docker','volume','create','--label','io.forklift.maintenance=restore-stage',stage])
    try:
        result=toolbox('unpack',{'sha256':args.sha256,'max_bytes':args.max_gib*1024**3},[(archive,'/backup.age',True),(identity,'/identity',True),(stage,'/work',False)])
        return stage,result
    except BaseException:
        command(['docker','volume','rm',stage],check=False)
        raise


def restore(installation,args):
    if not args.original_fenced:raise ValueError('Fence the original primary and replicas before restoration')
    if installation.state_file.exists():raise ValueError('Installation has pending maintenance')
    if (installation.root/'.env').exists() or (installation.root/'.secrets').exists():
        raise ValueError('Restore requires an empty installation secret/env destination')
    ids=command(installation.compose+['ps','-a','-q']).stdout.decode().split()
    if ids:raise ValueError('Restore destination must not have existing containers')
    installation.ensure_current_images()
    volumes=installation.volumes()
    # Named target volumes must be newly created, not an implicit overwrite of old data.
    for name in volumes.values():
        if command(['docker','volume','inspect',name],check=False).returncode==0:
            raise ValueError('Restore target volume already exists')
    stage,manifest=verified_stage(args)
    try:
        if not manifest['id_high_water']<args.uid_floor<=2147483647:
            raise ValueError('Choose a Unix ID floor above all IDs ever allocated, including after the backup')
        for name in volumes.values():command(['docker','volume','create',name])
        (installation.root/'.secrets').mkdir(mode=0o700)
        envdir=installation.root/'.forklift-restore-environment'
        envdir.mkdir(mode=0o700)
        state={'kind':'restore','operation_id':secrets.token_hex(16),'actor':installation.actor,'project':installation.project,'volumes':volumes,'uid_floor':args.uid_floor,'owner_uid':os.getuid(),'owner_gid':os.getgid(),'artifact':path(args.archive).name,'sha256':args.sha256,'phase':'preparing'}
        write_json(installation.state_file,state)
        toolbox('restore',state,installation.source_mounts(volumes,False)+[(stage,'/work',False),(envdir,'/installation',False)])
        state['phase']='prepared';write_json(installation.state_file,state)
        publish(installation,state)
    finally:
        command(['docker','volume','rm',stage],check=False)


def publish(installation,state):
    envdir=installation.root/'.forklift-restore-environment'
    destination=installation.root/'.env'
    if destination.exists():
        if sha(destination)!=sha(envdir/'.env'):raise ValueError('Environment changed before restore publication')
    else:
        os.link(envdir/'.env',destination)
        descriptor=os.open(installation.root,os.O_DIRECTORY);os.fsync(descriptor);os.close(descriptor)
    model=json.loads(command(installation.compose+['config','--format','json']).stdout)
    if model['name'] != state['project'] or any(model['volumes'][role]['name'] != volume for role,volume in state['volumes'].items()):
        raise ValueError('Restored environment changed project/volume names; explicitly select the original target --project and correct volume names before resume')
    result=toolbox('publish-restore',state,installation.source_mounts(state['volumes'],False)+[(destination,'/installation/.env',True)])
    installation.state_file.unlink()
    (envdir/'.env').unlink();envdir.rmdir()
    print(json.dumps(result),flush=True)


def rotate(installation,args,resume=False):
    if resume:
        state=json.loads(installation.state_file.read_text())
    else:
        containers=installation.containers();installation.ensure_current_images(containers)
        if not containers['ldap']['State']['Running']:raise ValueError('Service rotation requires a running primary, or resume an interrupted rotation')
        state=installation.save_state('rotate-service',containers)
    if state['project']!=installation.project or state['kind']!='rotate-service':raise ValueError('Wrong maintenance recovery state')
    mounts=installation.source_mounts(state['volumes'],False)
    if state['phase']!='restarted':
        # Stop by exact original IDs; no Compose dependency is implicitly started.
        installation.stop(state)
        result=toolbox('rotate-service',state,mounts)
        state['phase']='consistent';write_json(installation.state_file,state)
        installation.start(state)
        # Verify actual bind/TLS using the newly mounted secret, not just process liveness.
        script="import os,subprocess,pathlib,sys; b=pathlib.Path('/directory/complete').read_text().strip(); r=subprocess.run(['ldapwhoami','-x','-H','ldaps://ldap:636','-D','cn=manager,'+b,'-y','/dev/stdin'],input=pathlib.Path('/run/secrets/service').read_bytes().strip(),env={**os.environ,'LDAPTLS_CACERT':'/run/secrets/ca.crt'},capture_output=True);sys.exit(r.returncode)"
        command(['docker','exec',state['containers']['ldap']['id'],'python3','-c',script])
        state['phase']='restarted';write_json(installation.state_file,state)
    toolbox('ack-service',state,mounts)
    installation.state_file.unlink()
    print(json.dumps({'rotated':True,'operation_id':state['operation_id']}),flush=True)


def resume(installation,args):
    state=json.loads(installation.state_file.read_text())
    if state['project']!=installation.project:raise ValueError('Wrong maintenance project')
    if state['kind']=='restore':return publish(installation,state)
    if state['kind']=='rotate-service':return rotate(installation,args,True)
    if state['kind']!='backup':raise ValueError('Unsupported recovery state')
    markers=toolbox('markers',{},installation.source_mounts(state['volumes']))
    if markers['rotation_pending'] or markers['incomplete']:raise ValueError('Restore/credential recovery must finish before starting services')
    installation.start(state);installation.state_file.unlink()
    print(json.dumps({'resumed':True}))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',default=str(SOURCE));parser.add_argument('--project');parser.add_argument('--file',action='append')
    sub=parser.add_subparsers(dest='action',required=True)
    key=sub.add_parser('keygen');key.add_argument('--output',required=True)
    pack=sub.add_parser('backup');pack.add_argument('--recipient',required=True);pack.add_argument('--output',required=True);pack.add_argument('--max-gib',type=int,default=8)
    for name in ['verify','restore']:
        target=sub.add_parser(name);target.add_argument('--archive',required=True);target.add_argument('--identity',required=True);target.add_argument('--sha256',required=True);target.add_argument('--max-gib',type=int,default=8)
        if name=='restore':target.add_argument('--uid-floor',type=int,required=True);target.add_argument('--original-fenced',action='store_true')
    sub.add_parser('rotate-service');sub.add_parser('resume')
    args=parser.parse_args()
    if not 1<=getattr(args,'max_gib',8)<=64:raise ValueError('Use a size limit between 1 and 64 GiB')
    if command(['docker','image','inspect',TOOL],check=False).returncode:
        raise ValueError('Build the maintenance image first: docker build -t forklift-maintenance -f docker/maintenance/Dockerfile .')
    if args.action=='keygen':
        output=path(args.output)
        if path(args.root) in output.parents:raise ValueError('Keep the recovery identity outside the installation checkout')
        output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        private=toolbox('keygen',raw=True)
        fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(private);stream.flush();os.fsync(stream.fileno())
        recipient=next(line.removeprefix('# public key: ') for line in private.decode().splitlines() if line.startswith('# public key: '))
        print(json.dumps({'recipient':recipient,'identity':str(output)}));return
    if args.action=='verify':
        stage,result=verified_stage(args)
        command(['docker','volume','rm',stage]);print(json.dumps(result));return
    installation=Installation(args)
    with locked(installation):
        {'backup':backup,'restore':restore,'rotate-service':rotate,'resume':resume}[args.action](installation,args)


if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt) as exc:
        print(str(exc) if isinstance(exc,(ValueError,RuntimeError)) else type(exc).__name__,file=sys.stderr)
        sys.exit(1)
