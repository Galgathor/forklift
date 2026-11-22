#!/usr/bin/env python3
"""Publish checked revision images, then advance latest after the full main build succeeds."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from ci_common import metadata, run, upload, write_json

IMAGES = {'manager': 'docker/manager/Dockerfile', 'ldap': 'docker/openldap/Dockerfile',
          'replica': 'docker/replica/Dockerfile', 'dns': 'docker/powerdns/Dockerfile',
          'maintenance': 'docker/maintenance/Dockerfile'}
meta = metadata('backend/Cargo.toml')
out = Path('dist/images');out.mkdir(parents=True, exist_ok=True)
if sys.argv[1:] == ['build']:
    for name, dockerfile in IMAGES.items():
        image = meta['registry'] + '/' + meta['owner'].lower() + '/forklift-' + name
        run('docker', 'buildx', 'build', '--load', '--platform', 'linux/amd64',
            '--label', 'org.opencontainers.image.revision=' + meta['sha'],
            '--label', 'org.opencontainers.image.source=' + os.environ['CI_SERVER_URL'] + '/' + os.environ['CI_REPOSITORY'],
            '--tag', image + ':' + meta['tags'][0], '--file', dockerfile, '.')
elif sys.argv[1:] == ['publish']:
    token = os.environ.get('PACKAGES_TOKEN', '')
    if not token:raise ValueError('Set the PACKAGES_TOKEN Actions secret (write:package)')
    # A private Docker config prevents leaving credentials on a reusable runner.
    with tempfile.TemporaryDirectory(prefix='forklift-registry-') as directory:
        env = dict(os.environ, DOCKER_CONFIG=directory)
        run('docker', 'login', meta['registry'], '--username', os.environ.get('PACKAGES_USERNAME') or os.environ['CI_OWNER'],
            '--password-stdin', input=token.encode(), env=env)
        for name in IMAGES:
            image = meta['registry'] + '/' + meta['owner'].lower() + '/forklift-' + name
            pins = []
            local_id = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', image + ':' + meta['tags'][0]], env=env, text=True).strip()
            for tag in meta['tags']:
                target = image + ':' + tag
                existing = subprocess.run(['docker', 'buildx', 'imagetools', 'inspect', '--raw', target], env=env, capture_output=True, text=True)
                if existing.returncode == 0:
                    manifest = json.loads(existing.stdout)
                    if manifest.get('config', {}).get('digest') != local_id:
                        raise RuntimeError('Existing image tag differs; refusing to overwrite ' + target)
                    digest = subprocess.check_output(['docker', 'buildx', 'imagetools', 'inspect', '--format', '{{.Manifest.Digest}}', target], env=env, text=True).strip()
                    pins.append(image + '@' + digest)
                    continue
                if not any(s in existing.stderr.lower() for s in ['not found', 'manifest unknown', '404']):
                    raise RuntimeError('Registry lookup failed; refusing an unchecked push for ' + target)
                run('docker', 'tag', image + ':' + meta['tags'][0], target, env=env)
                run('docker', 'push', target, env=env)
                digests = json.loads(subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{json .RepoDigests}}', target], env=env))
                pins.append(next(value for value in digests if value.startswith(image + '@sha256:')))
            pin = pins[0]
            file = out / ('forklift-' + name + '.json')
            write_json(file, dict(image=pin, tags=meta['tags'], platform='linux/amd64', revision=meta['sha']))
            upload(meta, 'forklift-images', file)
        # Keep immutable build tags/manifests separate from the convenience alias.
        # Only advance latest after every image and digest manifest was published.
        if os.environ['CI_REF'] == 'refs/heads/main':
            for name in IMAGES:
                image = meta['registry'] + '/' + meta['owner'].lower() + '/forklift-' + name
                run('docker', 'tag', image + ':' + meta['tags'][0], image + ':latest', env=env)
                run('docker', 'push', image + ':latest', env=env)
else:
    raise SystemExit('Usage: python3 scripts/ci_images.py build|publish')
