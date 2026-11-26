"""Fixed non-root PowerDNS lifecycle and authenticated Unix REST transport."""
import hashlib
import forwarding
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
frontend = None
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


def configuration(isolated=False):
    settings = json.loads((DATA / 'secondary.json').read_text()) if SECONDARY else None
    address = settings['address'] if settings else '127.0.0.1'
    port = settings['dns_port'] if settings else 5354
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
    stop_frontend()
    if child is not None:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=15)
        child = None


def forwarding_settings():
    path = DATA / 'forwarding.json'
    return forwarding.validate(json.loads(path.read_text())) if path.exists() else dict(forwarding.DEFAULT)


def stop_frontend():
    global frontend
    if frontend is not None:
        if frontend.poll() is None:
            frontend.terminate()
            frontend.wait(timeout=10)
        frontend = None


def refresh_frontend(value=None):
    global frontend
    if SECONDARY:
        raise ValueError('Forwarding is configured on the primary DNS server')
    code, data, _ = native('GET', '/api/v1/servers/localhost/zones?rrsets=false')
    if code != 200:
        raise ValueError('Cannot read authoritative zones for forwarding')
    zones = [zone['name'] for zone in json.loads(data)]
    candidate = DATA / 'dnsdist.conf'
    atomic(candidate, forwarding.configuration(value if value is not None else forwarding_settings(), zones).encode())
    subprocess.run(['dnsdist', '--check-config', '-C', str(candidate)], check=True, timeout=10, capture_output=True)
    stop_frontend()
    frontend = subprocess.Popen(['dnsdist', '--supervised', '--disable-syslog', '-C', str(candidate)])
    for _ in range(50):
        if frontend.poll() is not None:
            raise ValueError('DNS forwarding listener could not start')
        probe = subprocess.run(['dig', '@127.0.0.1', '-p', '5353', 'version.bind', 'TXT', 'CH', '+time=1', '+tries=1'], capture_output=True, timeout=3)
        if probe.returncode == 0:
            return
        time.sleep(.1)
    raise ValueError('DNS forwarding listener did not become ready')


def save_forwarding(value):
    forwarding.validate(value)
    previous = forwarding_settings()
    try:
        refresh_frontend(value)
        atomic(DATA / 'forwarding.json', json.dumps(value).encode())
    except Exception:
        refresh_frontend(previous)
        raise
    return {'settings': value, 'listener_available': frontend is not None and frontend.poll() is None}


def start(isolated=False):
    global child
    atomic(DATA / 'pdns.conf', configuration(isolated).encode())
    child = subprocess.Popen(['pdns_server', '--config-dir=/dns'])
    for _ in range(80):
        if child.poll() is not None:
            raise ValueError('PowerDNS exited; inspect its startup diagnostics')
        try:
            if native('GET', '/api/v1/servers/localhost')[0] == 200:
                if not SECONDARY and not isolated:
                    refresh_frontend()
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
    port = settings['dns_port'] if settings else 5354
    name = zones[0]['name'] if zones else '.'
    query = subprocess.run(['dig', '@'+address, '-p', str(port), name, 'SOA', '+time=1', '+tries=1'], capture_output=True, timeout=3)
    answer = query.stdout.decode(errors='replace')
    responding = query.returncode == 0 and ('status: NOERROR' in answer if zones else 'status: REFUSED' in answer)
    flags = answer.split('flags:', 1)[1].split(';', 1)[0].split() if 'flags:' in answer else []
    authoritative = responding and 'aa' in flags if zones else None
    listener = responding if SECONDARY else subprocess.run(['dig', '@127.0.0.1', '-p', '5353', 'version.bind', 'TXT', 'CH', '+time=1', '+tries=1'], capture_output=True, timeout=3).returncode == 0
    return {'api_available': True, 'service_available': responding and listener, 'authoritative_answer': authoritative,
            'probe_zone': name if zones else None, 'version': server.get('version'), 'checked_at': int(time.time()),
            'replication': 'configured' if SECONDARY or any(z['kind'] in ['Primary', 'Master'] for z in zones) else 'not_configured', 'role': 'secondary' if SECONDARY else 'primary' if any(z['kind'] in ['Primary', 'Master'] for z in zones) else 'standalone'}


def restore_start(operation):
    marker = CONTROL/'offline.json'
    if not marker.exists() or json.loads(marker.read_text())['id'] != operation:
        raise ValueError('DNS restore fence does not match this operation')
    stop()
    initialize()
    start(isolated=True)
    def api(method, path, value=None):
        code, data, _ = native(method, '/api/v1/servers/localhost'+path, json.dumps(value).encode() if value is not None else None)
        if not 200 <= code < 300:
            raise ValueError('DNS recovery provisioning failed')
        return json.loads(data) if data else None
    # Archived peers cannot retain transfer rights or notifications after restoration.
    for zone in api('GET', '/zones?rrsets=false'):
        if zone['account'] != 'forklift':
            raise ValueError('Unmanaged DNS zones require separate recovery review')
        name = zone['name']
        api('PUT', '/zones/'+name, {'kind':'Native','master_tsig_key_ids':[]})
        for kind in ['ALSO-NOTIFY','ALLOW-AXFR-FROM']:
            api('PUT', '/zones/'+name+'/metadata/'+kind, {'kind':kind,'metadata':[]})
    for key in api('GET','/tsigkeys'):
        if key['name'].startswith('forklift-dns-'):
            api('DELETE','/tsigkeys/'+key['id'])
    stop()
    start()
    return {'restored':True}


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
                    zone_change = (self.command == 'POST' and self.path.rstrip('/') == '/api/v1/servers/localhost/zones') or (self.command == 'DELETE' and self.path.startswith('/api/v1/servers/localhost/zones/'))
                    if not SECONDARY and zone_change:
                        if 200 <= code < 300:
                            try:
                                refresh_frontend()
                            except Exception:
                                stop_frontend()
                                os._exit(1)  # Restart fail-closed with the updated zone list.
                    return self.reply(code, content, mime)
                if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + secret('control')):
                    return self.reply(403, {'error': 'DNS control authorization rejected'})
                if self.path == '/pause' and self.command == 'POST':
                    payload = json.loads(body or b'{}')
                    marker = CONTROL/'offline.json'
                    if not marker.exists() or json.loads(marker.read_text())['id'] != payload.get('operation_id'):
                        raise ValueError('DNS pause requires its durable operation fence')
                    stop()
                    return self.reply(200, {'paused':True})
                if self.path == '/restore-start' and self.command == 'POST':
                    return self.reply(200, restore_start(json.loads(body or b'{}').get('operation_id')))
                if self.path == '/start' and self.command == 'POST':
                    payload = json.loads(body or b'{}')
                    marker = CONTROL/'offline.json'
                    if marker.exists() and json.loads(marker.read_text())['id'] != payload.get('operation_id'):
                        raise ValueError('DNS start fence does not match')
                    if child is None or child.poll() is not None:
                        initialize()
                        start()
                    return self.reply(200, {'started':True})
                if self.path == '/forwarding' and not SECONDARY:
                    if self.command == 'GET':
                        return self.reply(200, {'settings': forwarding_settings(), 'listener_available': frontend is not None and frontend.poll() is None})
                    if self.command == 'PUT':
                        return self.reply(200, save_forwarding(json.loads(body or b'{}')))
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
            if (child is not None and child.poll() is not None) or (frontend is not None and frontend.poll() is not None):
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
            if (CONTROL/'offline.json').exists():
                raise SystemExit(0 if (CONTROL/'dns.sock').exists() else 1)
            value = inspect()
            raise SystemExit(0 if value['service_available'] else 1)
        except Exception:
            raise SystemExit(1)
    if SECONDARY:
        import secondary
        secondary.run(sys.modules[__name__])
        raise SystemExit(0)
    if not (CONTROL/'offline.json').exists():
        initialize()
        start()
    # Replaced storage may be incomplete. Keep recovery control reachable without
    # opening or regenerating native data/credentials while its durable fence exists.
    signal.signal(signal.SIGTERM, shutdown)
    threading.Thread(target=watch, daemon=True).start()
    path = CONTROL / 'dns.sock'
    path.unlink(missing_ok=True)
    Server(str(path), Handler).serve_forever()
