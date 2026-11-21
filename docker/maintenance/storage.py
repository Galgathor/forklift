"""Internal offline storage primitives. Invoked only by the constrained custodian."""
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time
from argon2 import PasswordHasher
from primary import configuration, valid_base

MAX_MANIFEST = 16 * 1024 * 1024
ROOTS = {name: Path('/'+name) for name in ['directory','metadata','secrets','directory-secrets','authority']}
EVENT_SCHEMA = '''CREATE TABLE IF NOT EXISTS maintenance_events(operation_id TEXT PRIMARY KEY,at INTEGER NOT NULL,kind TEXT NOT NULL,status TEXT NOT NULL,artifact TEXT NOT NULL DEFAULT '',sha256 TEXT NOT NULL DEFAULT '',detail TEXT NOT NULL DEFAULT '');'''


def atomic(path, data, mode=0o600):
    path = Path(path)
    temporary = path.with_name(path.name + '.new')
    with open(temporary, 'wb') as stream:
        os.chmod(temporary, mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)


def sha(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def event(p, kind, status, artifact='', checksum='', detail=''):
    db = sqlite3.connect('/metadata/forklift.db', timeout=10)
    db.executescript(EVENT_SCHEMA)
    db.execute('INSERT INTO maintenance_events VALUES(?,?,?,?,?,?,?) ON CONFLICT(operation_id) DO UPDATE SET at=excluded.at,status=excluded.status,artifact=excluded.artifact,sha256=excluded.sha256,detail=excluded.detail',
               (p['operation_id'], int(time.time()), kind, status, artifact, checksum, detail))
    if db.execute("SELECT count(*) FROM sqlite_master WHERE name='audit'").fetchone()[0]:
        db.execute('INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)', (int(time.time()), p.get('actor', 'local-operator'), kind+' '+status, p['operation_id']))
    db.commit()
    # The stopped manager uses WAL. Finish its journal before a read-only snapshot;
    # SQLite may otherwise need to create SHM even for a read-only connection.
    db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    db.execute('PRAGMA journal_mode=DELETE')
    db.close()


def safe_name(name):
    if not isinstance(name, str) or len(name) > 512 or any(ord(c) < 32 for c in name) or '\\' in name:
        raise ValueError('Unsafe archive path')
    path = PurePosixPath(name)
    if str(path) != name or path.is_absolute() or any(part in ['', '.', '..'] for part in path.parts):
        raise ValueError('Unsafe archive path')
    if len(path.parts) < 2 or path.parts[0] not in ROOTS:
        raise ValueError('Unknown archive scope')
    return path


def files():
    result = []
    for prefix, root in ROOTS.items():
        if not root.is_dir():
            raise ValueError('Missing snapshot scope: '+prefix)
        for path in sorted(root.rglob('*')):
            relative = path.relative_to(root).as_posix()
            if prefix == 'secrets' and relative == '.maintenance.lock':
                continue
            mode = path.lstat().st_mode
            if prefix == 'directory' and path.name in ['slapd.pid','slapd.args']:
                continue
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                raise ValueError('Only regular files can be backed up')
            name = prefix+'/'+relative
            safe_name(name)
            result.append((name, path))
    return result


def add(tar, name, data, size, mode=0o600):
    header = tarfile.TarInfo(name)
    header.size = size
    header.mode = mode
    header.mtime = int(time.time())
    tar.addfile(header, data)


def pack(p):
    if any((ROOTS[scope]/marker).exists() for scope in ['directory','metadata'] for marker in ['restore-incomplete','service-rotation-incomplete']):
        raise ValueError('Cannot back up incomplete maintenance')
    if not (Path('/directory')/'complete').is_file():
        raise ValueError('Complete initial directory setup before backup')
    if any((Path('/secrets')/name).exists() for name in ['service-rotation.json','certificate-renewal.json']):
        raise ValueError('Resume pending credential/certificate maintenance before backup')
    listing = files()
    entries = [{'path': name, 'size': path.stat().st_size, 'sha256': sha(path)} for name, path in listing]
    if len(entries) > 50000 or sum(e['size'] for e in entries) > p['max_bytes']:
        raise ValueError('Snapshot exceeds the configured limit')
    db = sqlite3.connect('file:/metadata/forklift.db?mode=ro', uri=True)
    version = db.execute('PRAGMA user_version').fetchone()[0]
    if not version == 5 or db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
        raise ValueError('Unsupported or inconsistent metadata')
    db.close()
    manifest = {'format': 2, 'created_at': int(time.time()), 'architecture': platform.machine(), 'metadata_schema': version,
                'operation_id': p['operation_id'], 'source': p['source'], 'files': entries}
    encoded = json.dumps(manifest, sort_keys=True).encode()
    if len(encoded) > MAX_MANIFEST:
        raise ValueError('Manifest exceeds its limit')
    destination = Path('/backups')/p['filename']
    partial = Path('/backups')/('.'+p['operation_id']+'.partial')
    if destination.exists():
        raise ValueError('Backup already exists')
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as output:
            encrypt = subprocess.Popen(['age', '-r', p['recipient']], stdin=subprocess.PIPE, stdout=output, stderr=subprocess.PIPE)
            try:
                with tarfile.open(fileobj=encrypt.stdin, mode='w|gz', format=tarfile.PAX_FORMAT) as tar:
                    add(tar, 'manifest.json', io.BytesIO(encoded), len(encoded))
                    for name, path in listing:
                        with open(path, 'rb') as data:
                            add(tar, name, data, path.stat().st_size)
                encrypt.stdin.close()
                if encrypt.wait() != 0:
                    raise ValueError('age encryption failed')
            finally:
                if encrypt.poll() is None:
                    encrypt.kill()
                    encrypt.wait()
            output.flush()
            os.fsync(output.fileno())
        os.chown(partial, p['owner_uid'], p['owner_gid'])
        # Never overwrite a backup created concurrently.
        os.link(partial, destination)
        partial.unlink()
        descriptor=os.open(destination.parent,os.O_DIRECTORY);os.fsync(descriptor);os.close(descriptor)
        return {'operation_id': p['operation_id'], 'sha256': sha(destination), 'artifact': destination.name,
                'files': len(entries), 'metadata_schema': version, 'bytes': destination.stat().st_size}
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def validate_config(directory, secrets):
    base = (directory/'complete').read_text().strip()
    if not valid_base(base):
        raise ValueError('Invalid directory suffix')
    original = (directory/'slapd.conf').read_text()
    lines = [s.strip() for s in original.splitlines() if s.strip() and not s.lstrip().startswith('#')]
    allowed = {s.strip() for s in configuration(base).splitlines() if s.strip() and not s.startswith('#')}
    legacy = f'access to attrs=userPassword by dn.exact="cn=manager,{base}" write by anonymous auth by * none'
    allowed.add(legacy)
    if len(lines) != len(set(lines)) or any(line not in allowed for line in lines):
        raise ValueError('Unsupported/custom LDAP configuration; refusing to execute it')
    required = ['database mdb', 'directory /directory/db', f'suffix "{base}"', 'moduleload back_mdb']
    if any(line not in lines for line in required):
        raise ValueError('Incomplete LDAP configuration')
    # No arbitrary modules/includes/commands from an archive reach a native configuration parser.
    transformed = original.replace('/directory/', str(directory)+'/').replace('/run/secrets/', str(secrets)+'/')
    config = Path('/tmp/validate.conf')
    config.write_text(transformed)
    result = subprocess.run(['slaptest', '-u', '-f', str(config)], capture_output=True)
    if result.returncode:
        raise ValueError('Native LDAP configuration validation failed')
    dump = subprocess.Popen(['slapcat', '-f', str(config), '-b', base], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    largest = 10000
    for line in dump.stdout:
        if re.fullmatch(rb'(?:uidNumber|gidNumber): [0-9]+\n', line):
            largest = max(largest, int(line.split(b':', 1)[1]))
    if dump.wait() != 0:
        raise ValueError('Native LDAP database validation failed')
    return base, largest


def unpack(p):
    if sha(p['archive_path']) != p['sha256']:
        raise ValueError('Ciphertext checksum differs from the trusted backup record')
    work = Path('/work/stage')
    if any(work.iterdir()):
        raise ValueError('Restore staging area is not empty')
    decrypt = subprocess.Popen(['age', '-d', '-i', p['identity_path'], p['archive_path']], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    manifest = None
    seen = set()
    try:
        with tarfile.open(fileobj=decrypt.stdout, mode='r|gz') as tar:
            first = next(iter(tar), None)
            if first is None or first.name != 'manifest.json' or not first.isfile() or first.size > MAX_MANIFEST:
                raise ValueError('Missing/invalid manifest')
            manifest = json.load(tar.extractfile(first))
            if manifest.get('format') != 2 or manifest.get('architecture') != platform.machine() or manifest.get('metadata_schema') != 5:
                raise ValueError('Unsupported snapshot format, architecture or schema')
            entries = manifest.get('files', [])
            if not entries or len(entries) > 50000 or sum(e['size'] for e in entries) > p['max_bytes']:
                raise ValueError('Invalid archive size')
            expected = {}
            for entry in entries:
                safe_name(entry['path'])
                if entry['path'] in expected or not isinstance(entry['size'], int) or entry['size'] < 0 or not re.fullmatch('[a-f0-9]{64}', entry['sha256']):
                    raise ValueError('Invalid/duplicate manifest entry')
                expected[entry['path']] = entry
            for member in tar:
                # tarfile iteration yields the cached first member a second time on some Python versions.
                if member.name == 'manifest.json' and member is first:
                    continue
                safe_name(member.name)
                if not member.isfile() or member.name in seen or member.name not in expected or member.size != expected[member.name]['size']:
                    raise ValueError('Invalid/duplicate/non-regular archive member')
                seen.add(member.name)
                target = work/member.name
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                digest = hashlib.sha256()
                with tar.extractfile(member) as source, open(target, 'xb') as output:
                    os.chmod(target, 0o600)
                    while data := source.read(1024*1024):
                        output.write(data)
                        digest.update(data)
                    output.flush()
                    os.fsync(output.fileno())
                if digest.hexdigest() != expected[member.name]['sha256']:
                    raise ValueError('Archive member checksum mismatch')
            if seen != set(expected):
                raise ValueError('Archive is incomplete')
        # Authentication of the final age chunk must complete before anything is published.
        while decrypt.stdout.read(1024*1024):
            pass
        if decrypt.wait() != 0:
            raise ValueError('Authenticated decryption failed')
    finally:
        if decrypt.poll() is None:
            decrypt.kill()
            decrypt.wait()
    for name in ['authority/ca.key', 'authority/ca.crt', 'directory-secrets/ldap.key', 'directory-secrets/ldap.crt', 'secrets/ca.crt', 'secrets/service', 'secrets/bootstrap', 'secrets/provision', 'secrets/maintenance', 'secrets/node-control-key', 'secrets/initialized-v5', 'directory-secrets/service', 'directory-secrets/provision', 'directory-secrets/ca.crt', 'secrets/ldap.crt', 'directory/layout-v5', 'metadata/forklift.db', 'directory/complete', 'directory/network.json']:
        if name not in seen:
            raise ValueError('Snapshot lacks required installation state')
    for copies in [['authority/ca.crt','secrets/ca.crt','directory-secrets/ca.crt'],['secrets/service','directory-secrets/service'],['secrets/provision','directory-secrets/provision'],['secrets/ldap.crt','directory-secrets/ldap.crt']]:
        if len({(work/name).read_bytes() for name in copies})!=1:raise ValueError('Snapshot has inconsistent credentials or trust')
    def public_key(path,certificate=False):
        if certificate:
            pem=subprocess.run(['openssl','x509','-in',str(path),'-pubkey','-noout'],capture_output=True,check=True).stdout
            return subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=pem,capture_output=True,check=True).stdout
        return subprocess.run(['openssl','pkey','-in',str(path),'-pubout','-outform','DER'],capture_output=True,check=True).stdout
    for key,cert in [('authority/ca.key','authority/ca.crt'),('directory-secrets/ldap.key','directory-secrets/ldap.crt')]:
        if public_key(work/key)!=public_key(work/cert,True):raise ValueError('Snapshot has an inconsistent certificate/private key pair')
    subprocess.run(['openssl','verify','-no_check_time','-CAfile',str(work/'authority/ca.crt'),str(work/'directory-secrets/ldap.crt')],capture_output=True,check=True)
    db = sqlite3.connect(work/'metadata/forklift.db')
    if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok' or db.execute('PRAGMA user_version').fetchone()[0] != manifest['metadata_schema']:
        raise ValueError('Metadata integrity/schema mismatch')
    db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    allocator = db.execute('SELECT value FROM allocator').fetchone()[0]
    db.close()
    base, largest = validate_config(work/'directory', work/'directory-secrets')
    manifest['base'] = base
    manifest['id_high_water'] = max(allocator, largest)
    atomic(work/'validated.json', json.dumps(manifest).encode())
    return {'operation_id': manifest['operation_id'], 'base': base, 'metadata_schema': manifest['metadata_schema'], 'id_high_water': manifest['id_high_water'], 'files': len(seen), 'validated': True}


def rotate_service(p):
    directory, secrets = Path('/directory'), Path('/secrets')
    if (secrets/'certificate-renewal.json').exists():
        raise ValueError('Finish certificate renewal before service rotation')
    base, _ = validate_config(directory, Path('/directory-secrets'))
    journal = secrets/'service-rotation.json'
    if journal.exists():
        state = json.loads(journal.read_text())
    else:
        state = {'credential': os.urandom(48).hex(), 'operation_id': p['operation_id']}
        atomic(journal, json.dumps(state).encode())
    if state['operation_id'] != p['operation_id']:
        raise ValueError('Rotation journal does not match the operator recovery state')
    if state.get('completed'):
        for scope in ['directory', 'metadata']:
            marker = ROOTS[scope]/'service-rotation-incomplete'
            if marker.exists() and marker.read_text() != state['operation_id']:
                raise ValueError('Credential barrier mismatch')
            marker.unlink(missing_ok=True)
            fd=os.open(marker.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        return {'rotated': True, 'operation_id': state['operation_id'], 'pending_ack': True}
    raw = state['credential']
    if not re.fullmatch('[a-f0-9]{96}', raw):
        raise ValueError('Invalid rotation journal')
    atomic(directory/'service-rotation-incomplete', state['operation_id'].encode())
    atomic(Path('/metadata')/'service-rotation-incomplete', state['operation_id'].encode())
    monitor = hmac.new(raw.encode(), b'forklift/directory-monitor/v1', hashlib.sha256).hexdigest()
    new_hash = '{ARGON2}'+PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1).hash(raw)
    monitor_hash = '{ARGON2}'+PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1).hash(monitor)
    # Do not create a monitor entry on installations that have never enrolled a replica.
    dump = subprocess.run(['slapcat', '-f', '/directory/slapd.conf', '-b', base, '-a', '(cn=monitor)'], capture_output=True, check=True)
    entries = [(f'cn=manager,{base}', new_hash)]
    if b'dn: cn=monitor,' in dump.stdout:
        entries.append((f'cn=monitor,{base}', monitor_hash))
    ldif = '\n\n'.join(f'dn: {dn}\nchangetype: modify\nreplace: userPassword\nuserPassword: {value}\n' for dn, value in entries).encode()
    # Run native writers as the directory UID; no root-created MDB/index files.
    result = subprocess.run(['slapmodify', '-w', '-f', '/directory/slapd.conf', '-b', base], input=ldif, capture_output=True)
    if result.returncode:
        raise ValueError('Native credential update failed; keep services stopped and resume using the journal')
    # Keep the existing bind-mounted inode, including after an interrupted previous write.
    with open(secrets/'service', 'wb') as stream:
        stream.write((raw+'\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.chown(secrets/'service', 10001, 10001)
    os.chmod(secrets/'service', 0o600)
    db = sqlite3.connect('/metadata/forklift.db')
    db.execute('DELETE FROM sessions')
    db.commit()
    db.close()
    p['operation_id'] = state['operation_id']
    event(p, 'rotate service credential', 'completed', detail='Primary service/monitor credentials updated; administrative sessions revoked')
    state['completed'] = True
    atomic(journal, json.dumps(state).encode())
    for scope in ['metadata','directory']:
        marker=ROOTS[scope]/'service-rotation-incomplete'
        marker.unlink(missing_ok=True)
        fd=os.open(marker.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    return {'rotated': True, 'operation_id': p['operation_id'], 'pending_ack': True}
