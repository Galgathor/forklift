"""Local console-only recovery for an administrator who cannot sign in."""
import getpass
import http.client
import json
from pathlib import Path
import socket
import sqlite3
import time

class Local(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(1800);self.sock.connect('/run/maintenance-control/maintenance.sock')
def call(path,payload=None):
    connection=Local('localhost')
    try:
        headers={'Authorization':'Bearer '+Path('/secrets/maintenance').read_text().strip(),'Content-Type':'application/json'}
        connection.request('POST' if payload is not None else 'GET',path,body=None if payload is None else json.dumps(payload).encode(),headers=headers)
        result=connection.getresponse();value=json.load(result)
        if result.status!=200:raise ValueError(value.get('error','Recovery service is unavailable'))
        return value
    finally:connection.close()

if __name__=='__main__':
    state=call('/status').get('job')
    if state and state['status'] in ['running','needs_resume','awaiting_ack']:
        if state['status']=='running':raise SystemExit('A worker is still running. Wait for it to finish before recovering credentials.')
        if state['status']=='needs_resume':
            action='rollback' if state['action']=='restore' and input('Resume restore or roll back? [resume/rollback]: ').strip()=='rollback' else 'resume'
            state=call('/run',{'id':state['id'],'action':action})
        if state['status']!='awaiting_ack':raise SystemExit('Operation still needs recovery; keep its snapshots and inspect the WebUI status.')
        database=sqlite3.connect('/metadata/forklift.db')
        if database.execute('PRAGMA quick_check').fetchone()!=('ok',):raise SystemExit('Metadata is inconsistent; preserve storage before further recovery.')
        database.close()
        for _ in range(5):
            try:call('/ack',{'id':state['id']});break
            except ValueError:time.sleep(.2)
    username=input('Administrator username to recover: ').strip()
    password=getpass.getpass('New password (14+ characters): ')
    if password!=getpass.getpass('Confirm new password: '):raise SystemExit('Passwords do not match.')
    public=input('Correct WebUI origin if the configured address is wrong (blank to retain): ').strip()
    result=call('/emergency-reset',{'username':username,'password':password,'public_url':public})
    print('Administrator access recovered. Sessions were revoked. Sign in through the WebUI.')
