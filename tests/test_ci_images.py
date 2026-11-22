"""Publishing order checks; no registry access or real credentials."""
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE / 'scripts'))
import ci_common


class ImagePublishingTests(unittest.TestCase):
    def publish(self, ref='refs/heads/main', fail_upload=False):
        events = []
        meta = dict(registry='registry.example.test', owner='account',
                    tags=['sha-' + 'a' * 40], sha='a' * 40, version='test')

        def run(*args, **kwargs):
            events.append(args)

        def upload(*args):
            events.append(('upload', args[-1].name))
            if fail_upload:
                raise RuntimeError('upload failed')

        def output(args, **kwargs):
            return 'sha256:test\n'

        def existing(*args, **kwargs):
            return subprocess.CompletedProcess(args, 0, '{"config":{"digest":"sha256:test"}}', '')

        previous = Path.cwd()
        try:
            with tempfile.TemporaryDirectory() as directory:
                os.chdir(directory)
                with patch.dict(os.environ, CI_REF=ref, CI_OWNER='account', PACKAGES_TOKEN='test-only'), \
                     patch.object(sys, 'argv', ['ci_images.py', 'publish']), \
                     patch.object(ci_common, 'metadata', return_value=meta), \
                     patch.object(ci_common, 'run', side_effect=run), \
                     patch.object(ci_common, 'upload', side_effect=upload), \
                     patch.object(subprocess, 'check_output', side_effect=output), \
                     patch.object(subprocess, 'run', side_effect=existing):
                    if fail_upload:
                        with self.assertRaisesRegex(RuntimeError, 'upload failed'):
                            runpy.run_path(str(SOURCE / 'scripts/ci_images.py'))
                    else:
                        runpy.run_path(str(SOURCE / 'scripts/ci_images.py'))
        finally:
            os.chdir(previous)
        return events

    def test_latest_advances_only_after_all_immutable_outputs(self):
        events = self.publish()
        uploads = [i for i, e in enumerate(events) if e[0] == 'upload']
        pushes = [i for i, e in enumerate(events) if e[:2] == ('docker', 'push')]
        self.assertEqual(len(uploads), 5)
        self.assertEqual(len(pushes), 5)
        self.assertLess(max(uploads), min(pushes))
        self.assertTrue(all(events[i][2].endswith(':latest') for i in pushes))

    def test_failed_immutable_publication_does_not_advance_latest(self):
        self.assertFalse(any(e[:2] == ('docker', 'push') for e in self.publish(fail_upload=True)))

    def test_release_build_does_not_change_latest(self):
        self.assertFalse(any(e[:2] == ('docker', 'push') for e in self.publish(ref='refs/tags/v0.5.0')))


if __name__ == '__main__':
    unittest.main()
