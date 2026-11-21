"""Fixed non-root PowerDNS lifecycle and authenticated Unix REST transport."""
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import sqlite3
import subprocess
import sys
import threading
import time

DATA = Path('/dns')
SECONDARY = os.environ.get('FORKLIFT_DNS_SECONDARY') == '1'
SECRETS = DATA / 'secrets' if SECONDARY else Path('/run/dns-secrets')
CONTROL = DATA / 'control' if SECONDARY else Path('/run/dns-control')
API_PORT = 8081
SCHEMA = Path('/usr/local/share/doc/pdns/schema.sqlite3.sql')
child = None
lock = threading.RLock()


def atomic(path, data):
    temporary = path.with_name(path.name + '.new')
    with open(temporary, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)


def secret(name):
    return (SECRETS / name).read_text().strip()


def initialize():
    for directory in [DATA, SECRETS, CONTROL]:
        directory.mkdir(exist_ok=True)
        os.chmod(directory, 0o700)
    if (DATA / 'layout.json').exists() and not (SECRETS / 'api-key').exists():
        raise ValueError('DNS credentials are missing; restore matching DNS storage instead of regenerating them')
    for name in ['api-key', 'control']:
        if not (SECRETS / name).exists():
            atomic(SECRETS / name, secrets.token_hex(48).encode())
    schema_hash = hashlib.sha256(SCHEMA.read_bytes()).hexdigest()
    marker = DATA / 'layout.json'
    database = DATA / 'pdns.sqlite3'
    journal = DATA / 'initialization.json'
    if marker.exists():
        if json.loads(marker.read_text()) != {'schema': schema_hash}:
            raise ValueError('DNS schema changed; back up and follow the reviewed upgrade procedure')
    else:
        prepared = journal.exists() and json.loads(journal.read_text()) == {'schema': schema_hash, 'prepared': True}
        if database.exists() and not prepared:
            raise ValueError('Unrecognized DNS storage; preserve it and restore a matching backup')
        pending = DATA / 'initializing.sqlite3'
        if not prepared:
            atomic(journal, json.dumps({'schema': schema_hash, 'prepared': False}).encode())
            pending.unlink(missing_ok=True)
            db = sqlite3.connect(pending)
            db.executescript(SCHEMA.read_text())
            db.commit()
            db.close()
            with open(pending, 'rb') as stream:
                os.fsync(stream.fileno())
            atomic(journal, json.dumps({'schema': schema_hash, 'prepared': True}).encode())
        if not database.exists():
            if not pending.exists():
                raise ValueError('Incomplete DNS initialization; preserve storage for recovery')
            pending.replace(database)
        db = sqlite3.connect(database)
        if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
            raise ValueError('DNS initialization integrity check failed')
        db.close()
        atomic(marker, json.dumps({'schema': schema_hash}).encode())
        journal.unlink(missing_ok=True)
    db = sqlite3.connect(database)
    if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
        raise ValueError('DNS SQLite integrity check failed')
    db.close()


def configuration():
    settings = json.loads((DATA / 'secondary.json').read_text()) if SECONDARY else None
    address = settings['address'] if settings else '0.0.0.0'
    port = settings['dns_port'] if settings else 5353
    return f'''launch=gsqlite3
gsqlite3-dnssec=yes
gsqlite3-database=/dns/pdns.sqlite3
gsqlite3-pragma-journal-mode=WAL
gsqlite3-pragma-synchronous=FULL
local-address={address}
local-port={port}
socket-dir={CONTROL}
daemon=no
guardian=no
write-pid=no
api=yes
api-key={secret('api-key')}
webserver=yes
webserver-address=127.0.0.1
webserver-port={API_PORT}
webserver-allow-from=127.0.0.1
webserver-loglevel=none
primary={"no" if SECONDARY else "yes"}
secondary={"yes" if SECONDARY else "no"}
disable-axfr={"yes" if SECONDARY else "no"}
allow-notify-from={settings["primary"]["address"] if settings else ""}
allow-axfr-ips=
send-signed-notify=no
allow-unsigned-notify={"yes" if SECONDARY else "no"}
dnsupdate=no
enable-lua-records=no
version-string=anonymous
log-dns-queries=no
log-dns-details=no
loglevel=4
'''


def native(method, path, body=None, key=None):
    connection = http.client.HTTPConnection('127.0.0.1', API_PORT, timeout=5)
    try:
        connection.request(method, path, body=body, headers={'X-API-Key': key or secret('api-key'), 'Content-Type': 'application/json'})
        response = connection.getresponse()
        content = response.read(8 * 1024 * 1024 + 1)
        if len(content) > 8 * 1024 * 1024:
            raise ValueError('DNS API response exceeds its limit')
        return response.status, content, response.getheader('Content-Type', 'application/json')
    finally:
        connection.close()


def stop():
    global child
    if child is not None:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=15)
        child = None


def start():
    global child
    atomic(DATA / 'pdns.conf', configuration().encode())
    child = subprocess.Popen(['pdns_server', '--config-dir=/dns'])
    for _ in range(80):
        if child.poll() is not None:
            raise ValueError('PowerDNS exited; inspect its startup diagnostics')
        try:
            if native('GET', '/api/v1/servers/localhost')[0] == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.1)
    raise ValueError('PowerDNS API did not become ready')


def inspect():
    code, body, _ = native('GET', '/api/v1/servers/localhost')
    if code != 200:
        raise ValueError('PowerDNS API authentication failed')
    server = json.loads(body)
    code, body, _ = native('GET', '/api/v1/servers/localhost/zones')
    if code != 200:
        raise ValueError('PowerDNS zone listing failed')
    zones = json.loads(body)
    settings = json.loads((DATA / 'secondary.json').read_text()) if SECONDARY else None
    address = settings['address'] if settings else '127.0.0.1'
    port = settings['dns_port'] if settings else 5353
    name = zones[0]['name'] if zones else '.'
    query = subprocess.run(['dig', '@'+address, '-p', str(port), name, 'SOA', '+time=1', '+tries=1'], capture_output=True, timeout=3)
    answer = query.stdout.decode(errors='replace')
    responding = query.returncode == 0 and ('status: NOERROR' in answer if zones else 'status: REFUSED' in answer)
    flags = answer.split('flags:', 1)[1].split(';', 1)[0].split() if 'flags:' in answer else []
    authoritative = responding and 'aa' in flags if zones else None
    return {'api_available': True, 'service_available': responding, 'authoritative_answer': authoritative,
            'probe_zone': name if zones else None, 'version': server.get('version'), 'checked_at': int(time.time()),
            'replication': 'configured' if SECONDARY or any(z['kind'] in ['Primary', 'Master'] for z in zones) else 'not_configured', 'role': 'secondary' if SECONDARY else 'primary' if any(z['kind'] in ['Primary', 'Master'] for z in zones) else 'standalone'}


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, body, content_type='application/json'):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def handle_request(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 <= length <= 262144:
                raise ValueError('DNS request exceeds its limit')
            body = self.rfile.read(length) if length else None
            with lock:
                if self.path.startswith('/api/v1/servers/localhost'):
                    if not hmac.compare_digest(self.headers.get('X-API-Key', ''), secret('api-key')):
                        return self.reply(401, {'error': 'DNS API authentication rejected'})
                    code, content, mime = native(self.command, self.path, body)
                    return self.reply(code, content, mime)
                if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + secret('control')):
                    return self.reply(403, {'error': 'DNS control authorization rejected'})
                if self.path == '/inspect' and self.command == 'GET':
                    return self.reply(200, inspect())
                if self.path == '/rotate' and self.command == 'POST':
                    # Publish once; an interrupted restart uses the same persistent key.
                    stop()
                    atomic(SECRETS / 'api-key', secrets.token_hex(48).encode())
                    start()
                    return self.reply(200, {'rotated': True})
                return self.reply(404, {'error': 'Unknown DNS operation'})
        except Exception:
            self.reply(503, {'error': 'PowerDNS is unavailable; inspect DNS container health and storage'})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request


def watch():
    while True:
        time.sleep(1)
        with lock:
            if child is not None and child.poll() is not None:
                print('PowerDNS exited unexpectedly; restarting through the container policy', file=sys.stderr, flush=True)
                os._exit(1)


def shutdown(*args):
    with lock:
        stop()
    raise SystemExit(0)


if __name__ == '__main__':
    os.umask(0o077)
    if sys.argv[1:] == ['health']:
        try:
            if SECONDARY:
                import secondary
                raise SystemExit(secondary.health())
            value = inspect()
            raise SystemExit(0 if value['service_available'] else 1)
        except Exception:
            raise SystemExit(1)
    if SECONDARY:
        import secondary
        secondary.run(sys.modules[__name__])
        raise SystemExit(0)
    initialize()
    start()
    signal.signal(signal.SIGTERM, shutdown)
    threading.Thread(target=watch, daemon=True).start()
    path = CONTROL / 'dns.sock'
    path.unlink(missing_ok=True)
    Server(str(path), Handler).serve_forever()
