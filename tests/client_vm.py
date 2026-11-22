#!/usr/bin/env python3
"""Optional full Ubuntu 24.04 boot/package/systemd drill. The client is installed natively in the VM."""
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import subprocess
import threading
import time
from fixture import Stack,SOURCE,run,port

IMAGE_URL='https://cloud-images.ubuntu.com/noble/20261017/noble-server-cloudimg-amd64.img'
IMAGE_SHA256='04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94'


def exercise(s):
    tools=Path(os.environ.get('FORKLIFT_TEST_VM_TOOLS','/tmp/forklift-client-vm-tools/root')).resolve()
    image=Path(os.environ.get('FORKLIFT_TEST_VM_IMAGE','/tmp/forklift-client-vm-images/noble-amd64.img')).resolve()
    assert hashlib.file_digest(image.open('rb'),'sha256').hexdigest()==IMAGE_SHA256,'Use the pinned vendor-verified Ubuntu image'
    packages=[SOURCE.parent/'forklift-client/target/packages'/f'forklift-client_0.4.0-{revision}_amd64.deb' for revision in [1,2]]
    assert all(p.is_file() for p in packages),'Build both package revisions before this fixture'
    root=s.root/'vm';root.mkdir(mode=0o700)
    env={**os.environ,'LD_LIBRARY_PATH':str(tools/'usr/lib/x86_64-linux-gnu')+':'+str(tools/'lib/x86_64-linux-gnu')}
    qemu=tools/'usr/bin/qemu-system-x86_64';qemu_img=tools/'usr/bin/qemu-img';iso=tools/'usr/bin/genisoimage'
    assert all(p.is_file() for p in [qemu,qemu_img,iso])
    ssh_port=port();file_port=port();manager_port=int(s.url.rsplit(':',1)[1])
    key=root/'ssh-key';run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)])
    allowed={'/client-1.deb':packages[0],'/client-2.deb':packages[1]}
    class Files(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            file=allowed.get(self.path)
            if file is None:self.send_error(404);return
            data=file.read_bytes();self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def log_message(self,*_):pass
    files=http.server.ThreadingHTTPServer(('127.0.0.1',file_port),Files);threading.Thread(target=files.serve_forever,daemon=True).start()
    relay="""import select,socket,socketserver
class Relay(socketserver.BaseRequestHandler):
 def handle(self):
  try:
   with socket.create_connection(('192.168.1.1',PORT),timeout=20) as remote:
    while True:
     ready,_,_=select.select([self.request,remote],[],[],30)
     for source in ready:
      data=source.recv(16384)
      if not data:return
      (remote if source is self.request else self.request).sendall(data)
  except OSError:pass
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
Server(('127.0.0.1',PORT),Relay).serve_forever()
""".replace('PORT',str(manager_port))
    install=f"""import hashlib,subprocess,urllib.request
from pathlib import Path
p=Path('/tmp/forklift-client.deb');data=urllib.request.urlopen('http://192.168.1.1:{file_port}/client-1.deb',timeout=60).read()
assert hashlib.sha256(data).hexdigest()=='{hashlib.sha256(packages[0].read_bytes()).hexdigest()}'
p.write_bytes(data)
subprocess.run(['dpkg','-i',str(p)],check=True)
Path('/var/lib/forklift-test').mkdir(exist_ok=True)
Path('/var/lib/forklift-test/ready').touch()
"""
    config=dict(hostname='forklift-vm',ssh_pwauth=False,ssh_authorized_keys=[key.with_suffix('.pub').read_text().strip()],write_files=[
        dict(path='/etc/forklift-test/manager-ca.crt',permissions='0644',content=(s.root/'ca.crt').read_text()),
        dict(path='/usr/local/libexec/forklift-test-relay.py',permissions='0755',content=relay),
        dict(path='/usr/local/libexec/forklift-test-install.py',permissions='0755',content=install),
        dict(path='/etc/systemd/system/forklift-test-relay.service',permissions='0644',content='[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nExecStart=/usr/bin/python3 /usr/local/libexec/forklift-test-relay.py\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n'),
    ],runcmd=[['systemctl','daemon-reload'],['systemctl','enable','--now','forklift-test-relay.service'],['python3','/usr/local/libexec/forklift-test-install.py']])
    (root/'user-data').write_text('#cloud-config\n'+json.dumps(config))
    (root/'meta-data').write_text(json.dumps({'instance-id':s.project,'local-hostname':'forklift-vm'}))
    run([str(iso),'-quiet','-output',str(root/'seed.iso'),'-volid','cidata','-joliet','-rock',str(root/'user-data'),str(root/'meta-data')],env=env)
    run([str(qemu_img),'create','-q','-f','qcow2','-F','qcow2','-b',str(image),str(root/'disk.qcow2'),'10G'],env=env)
    log=(root/'serial.log').open('wb')
    # Open KVM before dropping to the calling user; the VM has no host filesystem mounts or bridged NIC.
    args=['sudo','-n','env','LD_LIBRARY_PATH='+env['LD_LIBRARY_PATH'],str(qemu),'-runas',f'{os.getuid()}:{os.getgid()}','-machine','q35,accel=kvm:tcg','-cpu','max','-m','1536','-smp','2','-nodefaults','-display','none','-serial','stdio','-monitor','none','-bios',str(tools/'usr/share/seabios/bios-256k.bin'),'-L',str(tools/'usr/share/qemu'),'-drive','file='+str(root/'disk.qcow2')+',format=qcow2,if=virtio','-drive','file='+str(root/'seed.iso')+',format=raw,if=ide,media=cdrom,readonly=on','-netdev',f'user,id=net0,net=192.168.1.0/24,host=192.168.1.1,dns=192.168.1.3,dhcpstart=192.168.1.15,hostfwd=tcp:127.0.0.1:{ssh_port}-192.168.1.15:22','-device','virtio-net-pci,netdev=net0,romfile=']
    vm=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    ssh_args=['ssh','-i',str(key),'-p',str(ssh_port),'-o','BatchMode=yes','-o','ConnectTimeout=3','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(root/'known-hosts'),'ubuntu@127.0.0.1']
    def command(*args,check=True,data=None):return run(ssh_args+[shlex.join(['sudo','-n',*args])],data=data,check=check)
    def wait(fn,seconds=90):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            if vm.poll() is not None:raise AssertionError('VM stopped: '+(root/'serial.log').read_text(errors='replace')[-1500:])
            try:
                result=fn()
                if result:return result
            except (RuntimeError,ValueError,KeyError,StopIteration):pass
            time.sleep(1)
        raise AssertionError('VM check timed out; private serial log: '+str(root/'serial.log'))
    def public():return json.loads(command('forklift-client','status','--offline').stdout)
    join=None
    try:
        wait(lambda:command('test','-e','/var/lib/forklift-test/ready',check=False).returncode==0,240)
        assert command('systemctl','is-enabled','forklift-client.service').stdout.strip()==b'enabled'
        assert command('systemctl','is-active','forklift-client.service',check=False).returncode!=0
        join=subprocess.Popen(ssh_args+[shlex.join(['sudo','-n','forklift-client','join','--server',s.url,'--ca-file','/etc/forklift-test/manager-ca.crt','--hostname','vm-client.example.test','--interval','30','--diagnostic-interval','30'])],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        buffer='';deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if join.poll() is not None:raise AssertionError('VM join exited: '+join.stderr.read().decode()[-500:])
            if select.select([join.stdout],[],[],.2)[0]:buffer+=os.read(join.stdout.fileno(),4096).decode()
            match=re.search(r'Enrollment code: ([A-Z2-9]{4}-[A-Z2-9]{4})',buffer)
            if match:break
        else:raise AssertionError('VM pairing code missing')
        pending=s.request('/api/clients/lookup','POST',dict(code=match[1]));assert pending['identity']['hostname']=='vm-client.example.test'
        approved=s.request('/api/clients/'+pending['id']+'/approve','POST',dict(name='Native Ubuntu VM',host_id=None,host_revision=None,acknowledge=True));host_id=approved['host_id']
        out,err=join.communicate(timeout=30);assert join.returncode==0,err[-500:]
        wait(lambda:command('systemctl','is-active','forklift-client.service',check=False).returncode==0)
        wait(lambda:public().get('last_report') is not None)
        first=public();assert first['host_id']==host_id
        pid=int(command('systemctl','show','forklift-client.service','-p','MainPID','--value').stdout)
        properties=command('systemctl','show','forklift-client.service','-p','User','-p','NoNewPrivileges','-p','ProtectSystem','-p','MemoryMax','-p','CapabilityBoundingSet').stdout.decode()
        assert all(v in properties for v in ['User=root','NoNewPrivileges=yes','ProtectSystem=strict','MemoryMax=134217728','CapabilityBoundingSet=']),properties
        assert b'0000000000000000' in command('grep','CapEff:','/proc/'+str(pid)+'/status').stdout
        assert command('nsenter','--target',str(pid),'--mount','/usr/bin/touch','/etc/forklift-sandbox-write-test',check=False).returncode!=0
        assert command('stat','-c','%u:%a','/var/lib/forklift-client','/var/lib/forklift-client/state.json').stdout.splitlines()==[b'0:700',b'0:600']
        s.request('/api/clients/'+pending['id']+'/rotate','POST',dict(acknowledge=True))
        wait(lambda:public()['credentials']['generation']==2,75)
        # Real diagnostic commands under the installed sandbox and a fully booted service manager.
        monitoring=s.request('/api/hosts/'+host_id+'/monitoring');policy=monitoring['policy'];policy['diagnostics'].update(ssh=True,test_user='ubuntu',ssh_source='192.168.1.1',ssh_local='192.168.1.15',ssh_port=22)
        s.request('/api/hosts/'+host_id+'/monitoring','PUT',dict(revision=monitoring['revision'],policy=policy))
        checks=wait(lambda:(v if any(c['id']=='ssh.service' for c in v['checks']) else None) if (v:=s.request('/api/hosts/'+host_id+'/diagnostics')) else None,75)
        for id in ['ssh.installed','ssh.service','ssh.syntax','ssh.listener']:assert next(c for c in checks['checks'] if c['id']==id)['status']=='pass',(id,checks)
        print('PASS: full Ubuntu 24.04 boot, native package enrollment, actual hardened root service/capability/write restrictions, key rotation and OpenSSH diagnostics under systemd.',flush=True)
        rotated=public()
        # Upgrade, reboot and package lifecycle preserve the same machine identity.
        fetch="import hashlib,urllib.request;from pathlib import Path;d=urllib.request.urlopen('http://192.168.1.1:%d/client-2.deb').read();assert hashlib.sha256(d).hexdigest()=='%s';Path('/var/lib/forklift-test/client-upgrade.deb').write_bytes(d)"%(file_port,hashlib.sha256(packages[1].read_bytes()).hexdigest())
        command('python3','-c',fetch);command('dpkg','-i','/var/lib/forklift-test/client-upgrade.deb')
        wait(lambda:command('systemctl','is-active','forklift-client.service',check=False).returncode==0)
        assert public()['host_id']==host_id and public()['key_fingerprint']==rotated['key_fingerprint'] and public()['credentials']['generation']==2
        fingerprint=public()['key_fingerprint'];counter=public()['last_report']['sequence']
        command('systemctl','reboot',check=False);time.sleep(3)
        wait(lambda:command('systemctl','is-active','forklift-client.service',check=False).returncode==0,120)
        wait(lambda:public()['last_report']['sequence']>counter)
        assert public()['host_id']==host_id and public()['key_fingerprint']==fingerprint
        # A local malformed state is reported without printing its contents or deleting the identity.
        command('systemctl','stop','forklift-client.service')
        command('cp','-p','/var/lib/forklift-client/state.json','/var/lib/forklift-client/.valid-test-state')
        canary='secret-canary-'+os.urandom(12).hex()
        command('python3','-c',"import json;from pathlib import Path;p=Path('/var/lib/forklift-client/state.json');v=json.loads(p.read_text());v['access_token']={'unexpected':%r};p.write_text(json.dumps(v))"%canary)
        malformed=command('forklift-client','status','--offline',check=False);assert malformed.returncode and canary.encode() not in malformed.stderr
        command('cp','-p','/var/lib/forklift-client/.valid-test-state','/var/lib/forklift-client/state.json')
        command('chmod','0644','/var/lib/forklift-client/state.json')
        assert command('forklift-client','status','--offline',check=False).returncode
        command('chmod','0600','/var/lib/forklift-client/state.json')
        command('ln','/var/lib/forklift-client/state.json','/var/lib/forklift-client/.hardlink-test')
        assert command('forklift-client','status','--offline',check=False).returncode
        command('rm','/var/lib/forklift-client/.hardlink-test')
        command('rm','/var/lib/forklift-client/state.json')
        command('ln','-s','.valid-test-state','/var/lib/forklift-client/state.json')
        assert command('forklift-client','status','--offline',check=False).returncode
        command('rm','/var/lib/forklift-client/state.json')
        command('python3','-c',"from pathlib import Path; p=Path('/var/lib/forklift-client/state.json');p.touch(mode=0o600);p.write_bytes(b' '*262145)")
        assert command('forklift-client','status','--offline',check=False).returncode
        command('mv','/var/lib/forklift-client/.valid-test-state','/var/lib/forklift-client/state.json');command('systemctl','start','forklift-client.service')
        command('systemctl','stop','forklift-client.service')
        checksum=command('sha256sum','/var/lib/forklift-client/state.json').stdout
        command('dpkg','--remove','forklift-client');assert command('sha256sum','/var/lib/forklift-client/state.json').stdout==checksum
        command('dpkg','--purge','forklift-client');assert command('sha256sum','/var/lib/forklift-client/state.json').stdout==checksum
        assert next(h for h in s.request('/api/hosts') if h['id']==host_id)['client']['state']=='active'
        legacy=run(['git','show','94016c7:systemd/forklift-client.service'],cwd=SOURCE.parent/'forklift-client').stdout
        command('tee','/etc/systemd/system/forklift-client.service',data=legacy)
        command('dpkg','-i','/var/lib/forklift-test/client-upgrade.deb');wait(lambda:command('systemctl','is-active','forklift-client.service',check=False).returncode==0)
        assert command('cat','/etc/systemd/system/forklift-client.service.forklift-legacy').stdout==legacy
        assert command('test','-e','/etc/systemd/system/forklift-client.service',check=False).returncode
        custom=legacy+b'\n# administrator override retained\n'
        command('tee','/etc/systemd/system/forklift-client.service',data=custom)
        command('dpkg','-i','/var/lib/forklift-test/client-upgrade.deb')
        assert command('cat','/etc/systemd/system/forklift-client.service').stdout==custom
        command('rm','/etc/systemd/system/forklift-client.service');command('systemctl','daemon-reload')
        assert public()['host_id']==host_id and public()['key_fingerprint']==fingerprint
        command('systemctl','mask','--now','forklift-client.service');command('dpkg','-i','/var/lib/forklift-test/client-upgrade.deb');assert command('systemctl','is-enabled','forklift-client.service',check=False).stdout.strip()==b'masked'
        command('systemctl','unmask','forklift-client.service');command('systemctl','start','forklift-client.service')
        print('PASS: real Debian upgrade, reboot recovery, private-state validation/redaction, removal/purge without remote revocation or state loss, reinstall and preserved administrator service masks.',flush=True)
    finally:
        if join and join.poll() is None:join.terminate();join.wait(timeout=10)
        if vm.poll() is None:
            run(['sudo','-n','kill','-TERM','--','-'+str(vm.pid)],check=False)
            vm.wait(timeout=30)
        log.close();files.shutdown();files.server_close()

if __name__=='__main__':
    with Stack(https=True) as stack:stack.setup();exercise(stack)
