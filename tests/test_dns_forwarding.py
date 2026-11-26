"""Reject executable or public forwarding configuration, including restored data."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('dns_forwarding_settings', Path(__file__).resolve().parents[1] / 'docker/powerdns/forwarding.py')
forwarding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forwarding)


class ForwardingValidationTests(unittest.TestCase):
    def setUp(self):
        self.settings = dict(enabled=True, upstreams=[dict(address='192.168.1.1', port=53)], allowed_clients=['192.168.1.0/24'])

    def test_accepts_private_clients_and_external_upstreams(self):
        self.assertEqual(forwarding.validate(self.settings), self.settings)

    def test_cannot_become_a_public_resolver(self):
        for network in ['0.0.0.0/0', '::/0', '8.8.8.0/24', '192.168.1.1/24']:
            with self.subTest(network=network), self.assertRaises(ValueError):
                forwarding.validate(dict(self.settings, allowed_clients=[network]))

    def test_no_arbitrary_configuration_or_code(self):
        value = copy.deepcopy(self.settings)
        value['upstreams'][0]['address'] = '192.168.1.1"; os.execute("command")'
        with self.assertRaises(ValueError):
            forwarding.validate(value)
        with self.assertRaises(ValueError):
            forwarding.validate(dict(self.settings, command='anything'))
        with self.assertRaises(ValueError):
            forwarding.configuration(self.settings, ['example.test.";command'])

    def test_rejects_loopback_upstreams_duplicates_and_missing_servers(self):
        for servers in [[], [dict(address='127.0.0.1',port=53)], [dict(address='::ffff:127.0.0.1',port=5353)], self.settings['upstreams'] * 2]:
            with self.subTest(servers=servers), self.assertRaises(ValueError):
                forwarding.validate(dict(self.settings, upstreams=servers))


if __name__ == '__main__':
    unittest.main()
