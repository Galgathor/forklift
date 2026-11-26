"""Pinned HTTPS management of native secondary zones. No public native REST proxy."""
import base64
import forwarding
from concurrent.futures import ThreadPoolExecutor
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import threading
import hashlib
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

ROOT = Path('/dns')
ZONE = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+')
supervisor = None
settings = None


def validate(config):
    if not isinstance(config, dict) or len(config.get('zones', [])) > 32:
        raise ValueError('Invalid DNS assignments')
    if not re.fullmatch('[a-f0-9]{32}', config['id']) or type(config['revision']) is not int or config['revision'] < 1:
        raise ValueError('Invalid DNS configuration identity')
    for peer in [config, config['primary']]:
        address = ipaddress.IPv4Address(peer['address'])
        if not address.is_private or address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ValueError('Use a private unicast interface address')
        if type(peer['dns_port']) is not int or not 1 <= peer['dns_port'] <= 65535:
            raise ValueError('Invalid DNS port')
    if type(config['control_port']) is not int or not 1 <= config['control_port'] <= 65535 or config['dns_port'] == config['control_port']:
        raise ValueError('DNS and management ports must differ')
    if not re.fullmatch('[a-f0-9]{64}', config['control_token']):
        raise ValueError('Invalid control credential')
    if not re.fullmatch(r'forklift-dns-[a-f0-9]{32}-[0-9]+\.', config['tsig_name']) or len(base64.b64decode(config['tsig_key'], validate=True)) != 32:
        raise ValueError('Invalid transfer credential')
    if config['tsig_name'] != 'forklift-dns-'+config['id']+'-'+str(epoch(config))+'.':
        raise ValueError('Transfer credential belongs to another enrollment')
    if len(set(config['zones'])) != len(config['zones']) or any(len(z) > 254 or not ZONE.fullmatch(z) for z in config['zones']):
        raise ValueError('Invalid zone assignment')


def epoch(config):
    value = config.get('credential_epoch', int(config['tsig_name'].rstrip('.').rsplit('-', 1)[1]))
    if type(value) is not int or value < 1:
        raise ValueError('Invalid credential epoch')
    return value


def fingerprint(path):
    der = subprocess.check_output(['openssl', 'x509', '-in', str(path), '-outform', 'DER'], stderr=subprocess.DEVNULL)
    return hashlib.sha256(der).hexdigest()


def pair(key, certificate):
    private = subprocess.check_output(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'], stderr=subprocess.DEVNULL)
    public = subprocess.check_output(['openssl', 'x509', '-in', str(certificate), '-pubkey', '-noout'], stderr=subprocess.DEVNULL)
    return private == subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public, capture_output=True, check=True).stdout


def tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(ROOT/'server.crt'), str(ROOT/'server.key'))
    return context


def stage_certificate():
    key, cert = ROOT/'server-next.key', ROOT/'server-next.crt'
    if not key.exists() or not cert.exists():
        # A complete published pair is kept stable across retries and lost responses.
        with tempfile.TemporaryDirectory(dir=ROOT, prefix='certificate-stage-') as temporary:
            temporary = Path(temporary)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '365', '-subj', '/CN='+settings['address'],
                            '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
                            '-addext', 'extendedKeyUsage=serverAuth', '-addext', 'subjectAltName=IP:'+settings['address'],
                            '-keyout', str(temporary/'key'), '-out', str(temporary/'cert')], capture_output=True, check=True)
            supervisor.atomic(key, (temporary/'key').read_bytes())
            supervisor.atomic(cert, (temporary/'cert').read_bytes())
    if not pair(key, cert):
        raise ValueError('Staged DNS certificate pair is inconsistent')
    return dict(certificate=cert.read_text())


def activate_files(expected):
    journal = ROOT/'certificate-activation.json'
    if fingerprint(ROOT/'server.crt') == expected and pair(ROOT/'server.key', ROOT/'server.crt'):
        journal.unlink(missing_ok=True)
        return
    key, cert = ROOT/'server-next.key', ROOT/'server-next.crt'
    if fingerprint(cert) != expected or not pair(key, cert):
        raise ValueError('Certificate activation does not match its staged pair')
    supervisor.atomic(journal, json.dumps(dict(fingerprint=expected)).encode())
    if not (ROOT/'server-previous.crt').exists():
        supervisor.atomic(ROOT/'server-previous.key', (ROOT/'server.key').read_bytes())
        supervisor.atomic(ROOT/'server-previous.crt', (ROOT/'server.crt').read_bytes())
    supervisor.atomic(ROOT/'server.key', key.read_bytes())
    supervisor.atomic(ROOT/'server.crt', cert.read_bytes())
    if not pair(ROOT/'server.key', ROOT/'server.crt'):
        raise ValueError('Activated TLS certificate pair is inconsistent')
    journal.unlink(missing_ok=True)


def credential_proof():
    results = []
    with tempfile.NamedTemporaryFile(mode='w', prefix='dns-transfer-', dir='/tmp') as key:
        key.write('key "'+settings['tsig_name']+'" { algorithm hmac-sha256; secret "'+settings['tsig_key']+'"; };')
        key.flush()
        def prove(name):
            native_zone = api('GET', '/zones/'+name+'?rrsets=false')
            answer = subprocess.run(['dig', '-k', key.name, '@'+settings['primary']['address'], '-p', str(settings['primary']['dns_port']), name,
                                     'AXFR', '+time=2', '+tries=1', '+nocookie'], capture_output=True, timeout=10)
            text = answer.stdout.decode(errors='replace')
            soa = [line.split()[6] for line in text.splitlines() if len(line.split()) >= 11 and line.split()[0].lower() == name and line.split()[3] == 'SOA']
            active = [v.lower().rstrip('.') for v in native_zone.get('slave_tsig_key_ids', [])] == [settings['tsig_name'].lower().rstrip('.')]
            verified = active and answer.returncode == 0 and len(soa) == 2 and soa[0] == soa[1] and b'Transfer failed' not in answer.stdout and not answer.stderr.strip()
            return dict(name=name, verified=verified, detail=None if verified else 'Native zone key does not match' if not active else 'Signed AXFR response did not validate')
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(prove, settings['zones']))
    return dict(credential_epoch=epoch(settings), transfers=results)


def api(method, path, body=None):
    status, data, _ = supervisor.native(method, '/api/v1/servers/localhost'+path,
                                      json.dumps(body).encode() if body is not None else None)
    if not 200 <= status < 300:
        raise ValueError('Native DNS provisioning failed; inspect the zone assignment and container health')
    value = json.loads(data) if data else None
    for item in value if isinstance(value, list) else [value]:
        if isinstance(item, dict) and item.get('kind') in ['Master', 'Slave']:
            item['kind'] = {'Master': 'Primary', 'Slave': 'Secondary'}[item['kind']]
    return value


def provision(config):
    validate(config)
    current = {z['name']: z for z in api('GET', '/zones?rrsets=false')}
    account = 'forklift-secondary:'+config['id']
    # Refuse adopting or deleting zones not provisioned for this enrolled node.
    for name in config['zones']:
        if name in current and (current[name]['account'] != account or current[name]['kind'] != 'Secondary'):
            raise ValueError('An assigned zone already exists outside this enrollment')
    keys = api('GET', '/tsigkeys')
    payload = dict(name=config['tsig_name'], algorithm='hmac-sha256', key=config['tsig_key'])
    if any(k['id'] == config['tsig_name'] for k in keys):
        api('PUT', '/tsigkeys/'+config['tsig_name'], payload)
    else:
        api('POST', '/tsigkeys', payload)
    primary = config['primary']
    for name in config['zones']:
        values = dict(kind='Secondary', masters=[primary['address']+':'+str(primary['dns_port'])],
                      account=account, slave_tsig_key_ids=[config['tsig_name']])
        if name not in current:
            api('POST', '/zones', dict(values, name=name, nameservers=[]))
        else:
            api('PUT', '/zones/'+name, values)
        api('PUT', '/zones/'+name+'/metadata/IXFR', dict(kind='IXFR', metadata=['1']))
        api('PUT', '/zones/'+name+'/axfr-retrieve')
    for name, zone in current.items():
        if zone['account'] == account and name not in config['zones']:
            api('DELETE', '/zones/'+name)
    for key in keys:
        if key['name'].startswith('forklift-dns-'+config['id']+'-') and key['id'] != config['tsig_name']:
            api('DELETE', '/tsigkeys/'+key['id'])
    supervisor.refresh_frontend()


def apply_forwarding(policy):
    if not isinstance(policy, dict) or set(policy) != {'settings', 'zones'}:
        raise ValueError('Invalid peer forwarding policy')
    value = forwarding.validate(policy['settings'])
    if any(peer['address'] == node['address'] and peer['port'] == node['dns_port']
           for peer in value['upstreams'] for node in (settings, settings['primary'])):
        raise ValueError('Do not forward to a controller DNS listener')
    names = policy['zones']
    if not isinstance(names, list) or len(names) > 128 or any(not isinstance(z, str) or len(z) > 254 or not ZONE.fullmatch(z) for z in names):
        raise ValueError('Invalid managed zone list')
    previous = supervisor.secondary_policy()
    if policy == previous:
        return
    try:
        supervisor.refresh_frontend(policy)
        supervisor.atomic(ROOT/'forwarding-peer.json', json.dumps(policy).encode())
    except Exception:
        supervisor.refresh_frontend(previous)
        raise



def query(address, port, name, tcp=False):
    result = subprocess.run(['dig', '@'+address, '-p', str(port), name, 'SOA', '+time=1', '+tries=1', '+nocookie'] + (['+tcp'] if tcp else []), capture_output=True, timeout=3)
    text = result.stdout.decode(errors='replace')
    flags = text.split('flags:', 1)[1].split(';', 1)[0].split() if 'flags:' in text else []
    # Parse only an authoritative SOA owned by this exact queried zone.
    serial = next((int(parts[6]) for line in text.splitlines() if len(parts := line.split()) >= 11 and parts[0].lower() == name and parts[3] == 'SOA' and parts[6].isdigit()), None)
    return dict(responding=result.returncode == 0 and 'status: NOERROR' in text,
                authoritative='aa' in flags and serial is not None, serial=serial)


def inspect():
    local = {z['name']: z for z in api('GET', '/zones?rrsets=false')}
    config = settings
    def probe(name):
        z = local.get(name, {})
        udp = query(config['address'], config['dns_port'], name)
        tcp = query(config['address'], config['dns_port'], name, True)
        primary = query(config['primary']['address'], config['primary']['dns_port'], name)
        return dict(name=name, kind=z.get('kind'), last_check=z.get('last_check'), native_serial=z.get('serial'), udp=udp, tcp=tcp, primary=primary)
    with ThreadPoolExecutor(max_workers=4) as pool:
        zones = list(pool.map(probe, config['zones']))
    return dict(id=config['id'], revision=config['revision'], credential_epoch=epoch(config), protocol=2, api_available=True,
                checked_at=int(time.time()), zones=zones, forwarding_policy=supervisor.secondary_policy())


def enroll():
    raw = os.environ.get('FORKLIFT_DNS_JOIN', '')
    try:
        if not raw or len(raw) > 131072:
            raise ValueError()
        envelope = json.loads(base64.b64decode(raw, validate=True))
        p = envelope['enrollment']
        if envelope['version'] != 1 or p['expires_at'] <= int(time.time()) or not re.fullmatch('[a-f0-9]{32}', p['id']):
            raise ValueError()
        url = urlsplit(p['manager_url'])
        if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
            raise ValueError()
        ca = envelope.get('manager_ca')
        if ca is not None and (not isinstance(ca, str) or len(ca) > 65536 or 'PRIVATE KEY' in ca):
            raise ValueError()
        # Validate local binding before consuming a one-use token.
        for port in [p['dns_port'], p['control_port']]:
            for protocol in ([socket.SOCK_STREAM, socket.SOCK_DGRAM] if port == p['dns_port'] else [socket.SOCK_STREAM]):
                with socket.socket(socket.AF_INET, protocol) as sock:
                    sock.bind((p['address'], port))
        context = ssl.create_default_context(cadata=ca) if ca else ssl.create_default_context()
        cert = ROOT/'server.crt'
        key = ROOT/'server.key'
        if key.exists() != cert.exists():
            raise ValueError()
        if not cert.exists():
            address = str(ipaddress.IPv4Address(p['address']))
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '365', '-subj', '/CN='+address,
                            '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
                            '-addext', 'extendedKeyUsage=serverAuth', '-addext', 'subjectAltName=IP:'+address,
                            '-keyout', str(key), '-out', str(cert)], capture_output=True, check=True)
        request = urllib.request.Request(p['manager_url']+'/api/dns/servers/'+p['id']+'/enroll',
                                         data=json.dumps(dict(token=p['token'], certificate=cert.read_text())).encode(),
                                         headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(request, context=context, timeout=45) as response:
            config = json.load(response)
        validate(config)
        if any(config[k] != p[k] for k in ['id', 'address', 'dns_port', 'control_port']):
            raise ValueError()
        supervisor.atomic(ROOT/'secondary.json', json.dumps(config).encode())
    except Exception:
        raise ValueError('DNS enrollment failed. Check the join expiration, private address/ports and HTTPS trust. If the token was consumed before configuration was saved, remove the pending node in Forklift and issue a new join. No credentials were logged.') from None


class Server(ThreadingHTTPServer):
    # Bound TLS handshakes and request-body reads on the private control listener.
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        try:
            return self.tls_context.wrap_socket(connection, server_side=True), address
        except Exception:
            connection.close()
            raise


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        global settings
        try:
            if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer '+settings['control_token']):
                return self.reply(401, dict(error='DNS management authorization rejected'))
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 <= length <= 65536:
                return self.reply(400, dict(error='DNS management request exceeds its limit'))
            body = json.loads(self.rfile.read(length) or b'{}')
            if body.get('id') != settings['id']:
                return self.reply(400, dict(error='DNS node identity mismatch'))
            if self.path == '/health':
                api('GET', '')
                return self.reply(200, dict(api_available=True, protocol=2))
            with supervisor.lock:
                if self.path == '/forwarding':
                    apply_forwarding(body['policy'])
                    return self.reply(200, dict(applied=True))
                if self.path == '/inspect':
                    return self.reply(200, inspect())
                if self.path == '/credentials':
                    config = body['configuration']
                    validate(config)
                    if any(config[k] != settings[k] for k in ['id','address','dns_port','control_port','primary','zones']) or config['revision'] < settings['revision']:
                        raise ValueError('Rotate credentials for the current configuration only')
                    if epoch(config) not in [epoch(settings), epoch(settings)+1]:
                        raise ValueError('Credential epoch is not consecutive')
                    if epoch(config) == epoch(settings) and any(config[k] != settings[k] for k in ['control_token','tsig_name','tsig_key']):
                        raise ValueError('Credential replay differs from the persisted transition')
                    # The desired credential set is the recovery journal; retries authenticate with the new token.
                    supervisor.atomic(ROOT/'secondary.json', json.dumps(config).encode())
                    settings = config
                    provision(settings)
                    return self.reply(200, dict(applied=True, credential_epoch=epoch(settings)))
                if self.path == '/credentials/verify':
                    if body.get('credential_epoch') != epoch(settings):
                        raise ValueError('Credential epoch mismatch')
                    return self.reply(200, credential_proof())
                if self.path == '/certificate/stage':
                    return self.reply(200, stage_certificate())
                if self.path == '/certificate/activate':
                    activate_files(body['fingerprint'])
                    self.server.tls_context = tls_context()
                    return self.reply(200, dict(activated=True))
                if self.path == '/certificate/retire':
                    if fingerprint(ROOT/'server.crt') != body.get('fingerprint') or not pair(ROOT/'server.key', ROOT/'server.crt'):
                        raise ValueError('Verify the active TLS identity before retiring staging')
                    for name in ['server-next.key','server-next.crt','server-previous.key','server-previous.crt','certificate-activation.json']:
                        (ROOT/name).unlink(missing_ok=True)
                    return self.reply(200, dict(retired=True))
                if self.path == '/configure':
                    config = body['configuration']
                    validate(config)
                    if any(config[k] != settings[k] for k in ['id', 'address', 'dns_port', 'control_port', 'control_token', 'tsig_name', 'tsig_key']) or config['revision'] < settings['revision']:
                        raise ValueError('The enrollment identity or credentials changed')
                    # Journal desired configuration before native side effects; startup resumes it.
                    supervisor.atomic(ROOT/'secondary.json', json.dumps(config).encode())
                    changed_primary = config['primary'] != settings['primary']
                    settings = config
                    if changed_primary:
                        supervisor.stop()
                        supervisor.start()
                    provision(config)
                    if body.get('clear_forwarding') is True:
                        apply_forwarding({'settings': forwarding.DEFAULT, 'zones': []})
                    return self.reply(200, dict(applied=True, revision=config['revision']))
                if self.path == '/resync':
                    provision(settings)
                    return self.reply(200, dict(requested=True))
                return self.reply(404, dict(error='Unknown DNS management operation'))
        except Exception:
            self.reply(503, dict(error='DNS provisioning needs retry; inspect service health and zone assignments'))

    def reply(self, code, value):
        content = json.dumps(value).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        try:
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            pass


def health():
    try:
        config = json.loads((ROOT/'secondary.json').read_text())
        context = ssl.create_default_context(cafile=str(ROOT/'server.crt'))
        request = urllib.request.Request('https://'+config['address']+':'+str(config['control_port'])+'/health',
                                         data=json.dumps(dict(id=config['id'])).encode(), headers={'Authorization':'Bearer '+config['control_token']})
        # Explicitly bypass environment HTTP proxies for a pinned private control listener.
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        with client.open(request, timeout=30) as response:
            return 0 if json.load(response)['api_available'] else 1
    except Exception:
        return 1


def run(runtime):
    global supervisor, settings
    supervisor = runtime
    supervisor.initialize()
    if not (ROOT/'secondary.json').exists():
        enroll()
    settings = json.loads((ROOT/'secondary.json').read_text())
    validate(settings)
    # Each isolated host-network node gets a distinct loopback-only API listener.
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        supervisor.API_PORT = sock.getsockname()[1]
    with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind(('127.0.0.1', 0))
        supervisor.AUTH_PORT = tcp.getsockname()[1]
        udp.bind(('127.0.0.1', supervisor.AUTH_PORT))
    supervisor.start()
    provision(settings)
    if (ROOT/'certificate-activation.json').exists():
        activate_files(json.loads((ROOT/'certificate-activation.json').read_text())['fingerprint'])
    server = Server((settings['address'], settings['control_port']), Handler)
    server.tls_context = tls_context()
    signal.signal(signal.SIGTERM, supervisor.shutdown)
    threading.Thread(target=supervisor.watch, daemon=True).start()
    server.serve_forever()
