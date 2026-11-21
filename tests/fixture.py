"""Disposable 0.5 deployments. Secrets stay in memory/private temporary storage."""
import hashlib,http.cookiejar,io,json,os,re,secrets,socket,ssl,subprocess,tarfile,tempfile,time,urllib.request
from pathlib import Path
from urllib.error import HTTPError,URLError
SOURCE=Path(__file__).resolve().parents[1]
def port():
    with socket.socket() as s:s.bind(('0.0.0.0',0));return s.getsockname()[1]
def run(args,data=None,env=None,cwd=None,check=True):
    r=subprocess.run(args,input=data,capture_output=True,env=env,cwd=cwd)
    if check and r.returncode:raise RuntimeError('Command failed: '+args[0]+' '+args[1]+'; '+re.sub(r'[a-f0-9]{64,}','[redacted]',r.stderr.decode(errors='replace')[-1500:]))
    return r
class Stack:
    def __init__(self,https=False):
        self.project='forklift-v5-test-'+secrets.token_hex(4);self.temp=tempfile.TemporaryDirectory(prefix=self.project);self.root=Path(self.temp.name)
        self.bootstrap=secrets.token_urlsafe(40);self.password=secrets.token_urlsafe(30);self.csrf='';self.checks=0
        self.url=('https' if https else 'http')+'://localhost:'+str(port());self.https=https
        self.env={**os.environ,'FORKLIFT_PUBLIC_URL':self.url,'FORKLIFT_PORT':str(port() if https else self.url.rsplit(':',1)[1]),'FORKLIFT_BOOTSTRAP_TOKEN':self.bootstrap,'FORKLIFT_BIND':'127.0.0.1'}
        self.jar=http.cookiejar.CookieJar();self.context=None
        if https:
            def openssl(*args):return run(['openssl',*args],cwd=self.root)
            openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Forklift test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout','ca.key','-out','ca.crt')
            openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout','server.key','-out','server.csr')
            (self.root/'extensions').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
            openssl('x509','-req','-in','server.csr','-CA','ca.crt','-CAkey','ca.key','-set_serial','2','-days','2','-extfile','extensions','-out','server.crt')
            self.context=ssl.create_default_context(cafile=str(self.root/'ca.crt'))
        self.files=['-f',str(SOURCE/'compose.yaml')]
        if https:
            override=self.root/'host-test.yaml'
            override.write_text('services:\n  manager:\n    network_mode: host\n    ports: !reset []\n    environment:\n      FORKLIFT_LISTEN: 127.0.0.1:'+self.env['FORKLIFT_PORT']+'\n    healthcheck:\n      test: [CMD, /usr/bin/curl, -fsS, http://127.0.0.1:'+self.env['FORKLIFT_PORT']+'/health]\n')
            self.files+=['-f',str(override)]
        self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),urllib.request.HTTPSHandler(context=self.context))
    def compose(self,*args,input=None,check=True):return run(['docker','compose','-p',self.project,*self.files,*args],data=input,env=self.env,check=check)
    def __enter__(self):
        try:
            self.compose('up','-d','--no-build','--wait')
            if self.https:run(['docker','run','-d','--name',self.project+'-proxy','--user',str(os.getuid())+':'+str(os.getgid()),'--network','host','-e','PROXY_PORT='+self.url.rsplit(':',1)[1],'-e','MANAGER_HOST=127.0.0.1','-e','MANAGER_PORT='+self.env['FORKLIFT_PORT'],'-v',str(self.root)+':/fixture:ro','-v',str(SOURCE/'tests/tls_proxy.py')+':/proxy.py:ro','--entrypoint','python3','forklift-ldap:latest','/proxy.py'])
            self.wait('/health');return self
        except BaseException:self.__exit__(None,None,None);raise
    def __exit__(self,*args):
        if args and args[0] is not None:
            diagnostic=self.compose('logs','--no-color','--tail','15','manager','maintenance',check=False).stdout.decode(errors='replace')
            print(diagnostic.replace(self.password,'[redacted]').replace(self.bootstrap,'[redacted]'),flush=True)
        run(['docker','rm','-f',self.project+'-proxy'],check=False);self.compose('down','--volumes','--remove-orphans',check=False);self.temp.cleanup()
    def request(self,path,method='GET',body=None,expect=200,raw=False,authenticated=True,use_csrf=True,headers=None,origin=None):
        h={'Origin':origin or self.url,'Content-Type':'application/json',**({'X-CSRF-Token':self.csrf} if use_csrf else {}),**(headers or {})}
        req=urllib.request.Request(self.url+path,data=body if isinstance(body,bytes) else json.dumps(body).encode() if body is not None else None,headers=h,method=method)
        client=self.client if authenticated else urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.context))
        try:r=client.open(req,timeout=90)
        except HTTPError as e:r=e
        with r:
            data=r.read();assert r.code in (expect if isinstance(expect,tuple) else (expect,)),(path,r.code,data[:400]);self.checks+=1
            return (data,r.headers) if raw else json.loads(data)
    def wait(self,path='/ready'):
        for _ in range(90):
            try:return self.request(path)
            except (URLError,ConnectionError,AssertionError):time.sleep(.5)
        raise AssertionError('Stack did not become ready')
    def network(self):
        info=self.request('/api/setup/inspect','POST',dict(token=self.bootstrap))
        address=next((i['address'] for i in info['interfaces'] if i['name']=='docker0'),info['interfaces'][0]['address'])
        return dict(address=address,hostname=address,port=port())
    def setup(self):
        self.net=self.network();self.request('/api/setup','POST',dict(token=self.bootstrap,name='Integration',base='dc=integration,dc=test',username='admin',password=self.password,network=self.net,public_url=self.url));self.login()
    def login(self):self.csrf=self.request('/api/login','POST',dict(username='admin',password=self.password))['csrf']
    def poll(self,headers=None,success=True):
        for _ in range(450):
            state=self.request('/api/maintenance/current',headers=headers)['job']
            if state['status'] in ['completed','failed','needs_resume']:
                if success:assert state['status']=='completed',state
                return state
            time.sleep(.2)
        raise AssertionError('Maintenance job timed out')
    def job(self,body,headers=None,success=True):
        ticket=self.request('/api/maintenance/jobs','POST',body,headers=headers)
        if headers and 'X-Bootstrap-Token' in headers:headers={**headers,'X-CSRF-Token':ticket['csrf']}
        return self.poll(headers,success)
    def upload(self,data,headers=None):
        boundary='----forklift'+secrets.token_hex(12);body=('--'+boundary+'\r\nContent-Disposition: form-data; name="archive"; filename="backup.age"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+data+('\r\n--'+boundary+'--\r\n').encode()
        return self.request('/api/maintenance/uploads','POST',body,headers={**(headers or {}),'Content-Type':'multipart/form-data; boundary='+boundary})
    def user(self,name,**changes):return dict(username=name,display_name=name.title(),email='',description='',shell='/bin/bash',home='/home/'+name,gid=10000,password=self.password,disabled=False)|changes
    def bind(self,name,password=None,success=True):
        endpoint='ldaps://'+self.net['hostname']+':'+str(self.net['port'])
        code="import subprocess,sys,os; r=subprocess.run(['ldapwhoami','-x','-H',sys.argv[1],'-D',sys.argv[2],'-y','/dev/stdin'],input=sys.stdin.buffer.read(),capture_output=True,env={**os.environ,'LDAPTLS_CACERT':'/run/secrets/ca.crt'});sys.exit(r.returncode)"
        r=self.compose('exec','-T','ldap','python3','-c',code,endpoint,'uid='+name+',ou=people,dc=integration,dc=test',input=(password or self.password).encode(),check=False)
        assert (r.returncode==0)==success,'Unexpected native LDAP authentication result'
