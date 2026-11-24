"""Publishing order checks; no registry access or real credentials."""
import os
import json
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
    def publish(self, ref='refs/heads/main', fail_upload=False, ghcr=False, missing=False):
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
            if 'RepoDigests' in args[-2]:
                return json.dumps([args[-1].rsplit(':', 1)[0] + '@sha256:test'])
            return 'sha256:test\n'

        def existing(*args, **kwargs):
            if missing:
                return subprocess.CompletedProcess(args, 1, '', 'manifest unknown')
            return subprocess.CompletedProcess(args, 0, '{"config":{"digest":"sha256:test"}}', '')

        previous = Path.cwd()
        try:
            with tempfile.TemporaryDirectory() as directory:
                os.chdir(directory)
                with patch.dict(os.environ, CI_REF=ref, CI_OWNER='account', PACKAGES_TOKEN='test-only', GHCR_TOKEN='test-only', GHCR_USERNAME='Github-User'), \
                     patch.object(sys, 'argv', ['ci_images.py', 'publish-ghcr' if ghcr else 'publish']), \
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

    def test_ghcr_uses_existing_images_and_separate_login(self):
        events = self.publish(ghcr=True)
        login = next(e for e in events if e[:2] == ('docker', 'login'))
        self.assertEqual(login[2], 'ghcr.io')
        tags = [e for e in events if e[:2] == ('docker', 'tag')]
        self.assertEqual(len(tags), 5)
        self.assertTrue(all(e[2].startswith('registry.example.test/account/') for e in tags))
        self.assertTrue(all(e[3].startswith('ghcr.io/github-user/') for e in tags))
        self.assertFalse(any(e[0] == 'upload' for e in events))

    def test_ghcr_release_does_not_change_latest(self):
        events = self.publish(ref='refs/tags/v0.5.0', ghcr=True)
        self.assertFalse(any(e[:2] == ('docker', 'push') for e in events))

    def test_first_ghcr_publish_pushes_all_revisions_before_latest(self):
        events = self.publish(ghcr=True, missing=True)
        pushes = [e[2] for e in events if e[:2] == ('docker', 'push')]
        self.assertEqual(len(pushes), 10)
        self.assertTrue(all(':sha-' in target for target in pushes[:5]))
        self.assertTrue(all(target.endswith(':latest') for target in pushes[5:]))
        self.assertTrue(all(target.startswith('ghcr.io/github-user/') for target in pushes))


if __name__ == '__main__':
    unittest.main()
