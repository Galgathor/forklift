#!/usr/bin/env python3
"""Exercise the actual Milestone 2 -> 3 upgrade using committed source fixtures."""
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

os.chdir(Path(__file__).resolve().parents[1])
# Last tested Milestone 2 revision, including its v2 SQLite schema and pre-syncprov helper.
REVISION='264ea25'
with tempfile.TemporaryDirectory(prefix='forklift-m2-source-') as directory:
    data=subprocess.check_output(['git','archive',REVISION])
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
        archive.extractall(directory,filter='data')
    for component in ['ldap','manager']:
        filename='openldap' if component=='ldap' else 'manager'
        subprocess.run(['docker','build','-t','forklift-fixture-m2-'+component,'-f',str(Path(directory)/'docker'/filename/'Dockerfile'),directory],check=True,stdout=subprocess.DEVNULL)
    try:
        subprocess.run(['python3','tests/integration.py'],env={**os.environ,'FORKLIFT_TEST_UPGRADE':'1'},check=True)
    finally:
        subprocess.run(['docker','image','rm','forklift-fixture-m2-ldap','forklift-fixture-m2-manager'],check=False,stdout=subprocess.DEVNULL)
