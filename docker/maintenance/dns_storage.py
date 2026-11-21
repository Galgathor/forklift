"""Consistent DNS snapshots and strict offline validation; no native configuration execution."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3

SCHEMA = Path('/dns-schema.sql')


def schema_identity(db):
    return sorted(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall())


def validate(directory, secrets):
    expected = hashlib.sha256(SCHEMA.read_bytes()).hexdigest()
    if json.loads((directory/'layout.json').read_text()) != {'schema': expected}:
        raise ValueError('DNS schema marker does not match the supported PowerDNS release')
    for key in ['api-key', 'control']:
        if not re.fullmatch('[a-f0-9]{96}', (secrets/key).read_text().strip()):
            raise ValueError('DNS backup lacks valid service credentials')
    reference = sqlite3.connect(':memory:')
    reference.executescript(SCHEMA.read_text())
    db = sqlite3.connect('file:'+str(directory/'pdns.sqlite3')+'?mode=ro', uri=True)
    try:
        db.execute('PRAGMA trusted_schema=OFF')
        if schema_identity(db) != schema_identity(reference):
            raise ValueError('DNS SQLite schema differs from the supported schema; custom triggers/views are not restored')
        if db.execute('PRAGMA quick_check').fetchone() != ('ok',) or db.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('DNS SQLite integrity check failed')
        if db.execute("SELECT 1 FROM domains WHERE account IS NOT 'forklift' OR type NOT IN ('NATIVE','MASTER') OR coalesce(master,'')!='' OR coalesce(options,'') NOT IN ('','{}') OR coalesce(catalog,'')!='' LIMIT 1").fetchone():
            raise ValueError('DNS restore supports Forklift-managed Native/Primary zones only')
        if db.execute("SELECT 1 FROM records WHERE type NOT IN ('A','AAAA','CNAME','PTR','TXT','MX','SRV','NS','SOA') LIMIT 1").fetchone():
            raise ValueError('DNS snapshot contains unsupported or executable record types')
        if db.execute('SELECT 1 FROM cryptokeys LIMIT 1').fetchone() or db.execute('SELECT 1 FROM supermasters LIMIT 1').fetchone():
            raise ValueError('Custom DNSSEC/autoprimary configuration is not supported by this restore format')
        if db.execute("SELECT 1 FROM domainmetadata WHERE upper(kind) NOT IN ('SOA-EDIT-API','SOA-EDIT','API-RECTIFY','TSIG-ALLOW-AXFR','ALSO-NOTIFY','ALLOW-AXFR-FROM') LIMIT 1").fetchone():
            raise ValueError('DNS snapshot contains unsupported native configuration metadata')
    finally:
        db.close()
        reference.close()
    return expected


def capture(destination):
    if destination.exists():
        shutil.rmtree(destination)
    (destination/'dns').mkdir(parents=True, mode=0o700)
    (destination/'dns-secrets').mkdir(mode=0o700)
    source = sqlite3.connect('file:/dns/pdns.sqlite3?mode=ro', uri=True, timeout=10)
    target = sqlite3.connect(destination/'dns/pdns.sqlite3')
    try:
        source.backup(target, pages=1024, sleep=.05)
        target.execute('PRAGMA journal_mode=DELETE')
    finally:
        target.close()
        source.close()
    for source, target in [(Path('/dns/layout.json'), destination/'dns/layout.json'),
                           *[(Path('/dns-secrets')/name, destination/'dns-secrets'/name) for name in ['api-key','control']]]:
        shutil.copyfile(source, target)
    return validate(destination/'dns', destination/'dns-secrets')
