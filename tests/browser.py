#!/usr/bin/env python3
"""Optional real Chromium flows with private ephemeral downloads."""
import json,os
from pathlib import Path
from fixture import Stack,SOURCE,port,run
with Stack(https=True,dns_bind="0.0.0.0") as s:
    output=s.root/'browser';output.mkdir(mode=0o700)
    deps=Path(os.environ.get('FORKLIFT_TEST_BROWSER_DEPS','/tmp/forklift-m4-browser/node_modules')).resolve()
    result=run(['docker','run','--rm','-i','--network','host','--user',str(os.getuid())+':'+str(os.getgid()),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--tmpfs','/tmp:rw,nosuid,size=256m','--shm-size','256m','-e','NODE_PATH=/deps','-v',str(deps)+':/deps:ro','-v',str(SOURCE/'tests/browser.cjs')+':/test.cjs:ro','-v',str(output)+':/output','mcr.microsoft.com/playwright:v1.65.0-noble@sha256:6e3fb709361521eb27161606e6da6d2674e5e89fa16516cb37d6fdd91372273d','node','/test.cjs'],data=json.dumps(dict(url=s.url,bootstrap=s.bootstrap,password=s.password,network=s.network(),replicaPort=port(),controlPort=port())).encode())
    print(result.stdout.decode(),end='')
