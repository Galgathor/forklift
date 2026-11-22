#!/usr/bin/env python3
"""Run isolated compiler checks with Docker API copies, including Docker-hosted Actions runners."""
import shutil
import subprocess
import tempfile
from pathlib import Path

checks = [
    ('backend', '/src', 'rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33',
     'rustup component add rustfmt clippy; cargo fmt --check; cargo test --locked; cargo clippy --locked -- -D warnings'),
    ('frontend', '/web', 'node:24.11.1-bookworm-slim@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57',
     'npm ci; npm run build'),
]
for source, destination, image, command in checks:
    with tempfile.TemporaryDirectory(prefix='forklift-check-') as directory:
        path = Path(directory)/source
        shutil.copytree(source, path, ignore=shutil.ignore_patterns('target', 'node_modules', 'dist'))
        container = subprocess.check_output(['docker', 'create', '-w', destination, image, 'sh', '-ec', command], text=True).strip()
        try:
            subprocess.run(['docker', 'cp', str(path)+'/.', container+':'+destination], check=True)
            subprocess.run(['docker', 'start', '--attach', container], check=True)
            code = subprocess.check_output(['docker', 'inspect', '--format', '{{.State.ExitCode}}', container], text=True).strip()
            if code != '0':raise RuntimeError(source+' checks failed')
        finally:
            subprocess.run(['docker', 'rm', '-f', '-v', container], check=False, stdout=subprocess.DEVNULL)
