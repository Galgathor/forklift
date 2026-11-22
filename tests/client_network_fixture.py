#!/usr/bin/env python3
"""Native daemon fixture; mutations are restricted to an explicit private network/UTS namespace."""
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import threading
import time

assert os.geteuid()==0
for kind in ['net','uts']:
    assert os.readlink('/proc/self/ns/'+kind)!=os.readlink('/proc/1/ns/'+kind), 'Refuse host namespace mutation'
binary,state_dir,upstream,port=sys.argv[1:]
port=int(port)
assert 1024<port<65536
stop=threading.Event()
signal.signal(signal.SIGTERM,lambda *_:stop.set())
signal.signal(signal.SIGINT,lambda *_:stop.set())
for args in [['link','set','lo','up'],['link','add','fltest0','type','dummy'],['link','set','fltest0','up'],['address','add','192.168.1.60/24','dev','fltest0']]:
    subprocess.run(['/usr/sbin/ip',*args],check=True)
socket.sethostname('network-one.example.test')
listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',port));listener.listen(8);listener.settimeout(.2)
def relay(connection):
    try:
        with connection, socket.socket(socket.AF_UNIX) as remote:
            remote.connect(upstream)
            while not stop.is_set():
                ready,_,_=select.select([connection,remote],[],[],.2)
                for source in ready:
                    data=source.recv(16384)
                    if not data:return
                    (remote if source is connection else connection).sendall(data)
    except OSError:pass
def accept():
    while not stop.is_set():
        try:connection,_=listener.accept()
        except socket.timeout:continue
        except OSError:return
        threading.Thread(target=relay,args=(connection,),daemon=True).start()
threading.Thread(target=accept,daemon=True).start()
file=Path(state_dir)/'state.json'
previous=json.loads(file.read_text())['report_sequence']
daemon=subprocess.Popen([binary,'--state-dir',state_dir,'daemon'],stdin=subprocess.DEVNULL)
try:
    deadline=time.monotonic()+25
    while time.monotonic()<deadline and not stop.is_set():
        state=json.loads(file.read_text())
        if (state.get('last_report') or {}).get('sequence',0)>previous:break
        if daemon.poll() is not None:raise AssertionError('Native namespace daemon exited')
        time.sleep(.1)
    else:raise AssertionError('First namespace inventory was not acknowledged')
    print('First namespace inventory acknowledged',flush=True)
    socket.sethostname('network-two.example.test')
    for args in [['address','del','192.168.1.60/24','dev','fltest0'],['address','add','192.168.1.61/24','dev','fltest0']]:
        subprocess.run(['/usr/sbin/ip',*args],check=True)
    while not stop.wait(.2):
        if daemon.poll() is not None:raise AssertionError('Native namespace daemon exited')
finally:
    stop.set();daemon.terminate();daemon.wait(timeout=10);listener.close()
