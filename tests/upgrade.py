#!/usr/bin/env python3
"""Exercise the actual Milestone 2/3 -> 4 upgrade using committed source fixtures."""
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

os.chdir(Path(__file__).resolve().parents[1])
# Committed Milestone 2/3 revisions, including their actual SQLite/native LDAP profiles.
for schema,revision in [(2,'264ea25'),(3,'7b762cb')]:
    with tempfile.TemporaryDirectory(prefix='forklift-upgrade-source-') as directory:
        data=subprocess.check_output(['git','archive',revision])
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
            archive.extractall(directory,filter='data')
        for component in ['ldap','manager']:
            filename='openldap' if component=='ldap' else 'manager'
            subprocess.run(['docker','build','-t','forklift-fixture-m'+str(schema)+'-'+component,'-f',str(Path(directory)/'docker'/filename/'Dockerfile'),directory],check=True,stdout=subprocess.DEVNULL)
        try:
            subprocess.run(['python3','tests/integration.py'],env={**os.environ,'FORKLIFT_TEST_UPGRADE':'1','FORKLIFT_UPGRADE_SCHEMA':str(schema)},check=True)
        finally:
            subprocess.run(['docker','image','rm','forklift-fixture-m'+str(schema)+'-ldap','forklift-fixture-m'+str(schema)+'-manager'],check=False,stdout=subprocess.DEVNULL)
