"""Gitea package publishing helpers. No credentials in argv/files or redirect forwarding."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request


def metadata(manifest):
    section = Path(manifest).read_text().split('[package]', 1)[1].split('\n[', 1)[0]
    version = re.search(r'^version\s*=\s*"([^"]+)"', section, re.M)[1]
    sha = os.environ['CI_SHA']
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('Expected a full commit SHA')
    ref = os.environ['CI_REF']
    if ref == 'refs/heads/main':
        package_version = version + '-dev.' + sha
        tags = ['sha-' + sha]
        revision = '0.dev.' + sha
    elif ref == 'refs/tags/v' + version and re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', version):
        package_version, tags, revision = version, ['sha-' + sha, version], '1'
    else:
        raise ValueError('Only main or a v<manifest-version> tag can publish')
    server = os.environ['CI_SERVER_URL'].rstrip('/')
    url = urllib.parse.urlsplit(server)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('Gitea must use a trusted HTTPS URL')
    owner = os.environ.get('PACKAGE_OWNER') or os.environ['CI_OWNER']
    registry = os.environ.get('CONTAINER_REGISTRY') or url.netloc
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', owner) or not re.fullmatch(r'[A-Za-z0-9.-]+(?::\d+)?', registry):
        raise ValueError('Invalid package owner or registry host[:port]')
    return dict(version=package_version, tags=tags, revision=revision, sha=sha,
                server=server, owner=owner, registry=registry.lower())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def upload(meta, package, file):
    """Immutable upload; a rerun accepts only byte-identical existing content."""
    token = os.environ.get('PACKAGES_TOKEN', '')
    if not token:
        raise ValueError('Set the PACKAGES_TOKEN Actions secret (write:package)')
    username = os.environ.get('PACKAGES_USERNAME') or os.environ['CI_OWNER']
    parts = [meta['owner'], 'generic', package, meta['version'], file.name]
    url = meta['server'] + '/api/packages/' + '/'.join(urllib.parse.quote(p, safe='') for p in parts)
    authorization = 'Basic ' + base64.b64encode((username + ':' + token).encode()).decode()
    opener = urllib.request.build_opener(NoRedirect())
    data = file.read_bytes()
    request = urllib.request.Request(url, method='PUT', data=data,
                                    headers={'Authorization': authorization, 'Content-Type': 'application/octet-stream'})
    try:
        with opener.open(request, timeout=180) as reply:
            if reply.status != 201:
                raise RuntimeError('Unexpected package upload status')
    except urllib.error.HTTPError as error:
        if error.code != 409:
            raise RuntimeError('Package upload failed (HTTP %s); check token scope, owner and registry access' % error.code) from None
        request = urllib.request.Request(url, headers={'Authorization': authorization})
        with opener.open(request, timeout=180) as reply:
            digest = hashlib.sha256()
            for block in iter(lambda: reply.read(1048576), b''):
                digest.update(block)
        if digest.digest() != hashlib.sha256(data).digest():
            raise RuntimeError('Existing package differs; refusing to overwrite immutable output')
    print('Published ' + package + '/' + meta['version'] + '/' + file.name)


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
