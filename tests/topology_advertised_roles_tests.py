"""Role changes must not invent peers, alter links, or expose addresses."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

path = Path(__file__).resolve().parents[1] / 'scripts/veld-topology-rpc-collector.py'
spec = importlib.util.spec_from_file_location('collector', path)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class AdvertisedRolesTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        salt = Path(self.directory.name) / 'salt'
        salt.write_bytes(b'topology-role-unit-test-only-salt')
        self.fleets = ['192.0.2.1', '192.0.2.2', '192.0.2.3']
        self.peers = ['198.51.100.' + str(i) for i in range(1, 7)]
        known = {ip: {'id': i, 'role': 'fleet', 'role_index': i}
                 for i, ip in enumerate(self.fleets, 1)}
        known.update({ip: {'id': 100 + i, 'role': 'miner', 'role_index': i}
                      for i, ip in enumerate(self.peers[:4], 1)})
        self.config = {'salt_file': str(salt), 'known': known,
                       'sources': [{'name': 'fleet-' + str(i), 'address': ip}
                                   for i, ip in enumerate(self.fleets, 1)],
                       'key_file': 'unused', 'known_hosts': 'unused'}

    def collect(self, metadata=None, extra=None, reverse=False):
        def source(source, *_):
            rows = [{'ip': ip, 'peer_tip_hash': 'a' * 64, 'peer_tip_age_s': 0,
                     **(metadata or {}).get(ip, {})}
                    for ip in self.fleets + self.peers if ip != source['address']]
            rows.extend(copy.deepcopy(extra or []))
            return list(reversed(rows)) if reverse else rows
        with patch.object(collector, 'run_source', source), patch.object(collector.time, 'time', return_value=1000):
            view, failures = collector.collect(self.config)
        self.assertEqual(failures, [])
        return view

    def test_new_miners_are_classified_without_registry_entries(self):
        before = self.collect()
        config_before = copy.deepcopy(self.config)
        after = self.collect({ip: {'role': 'miner', 'services': 9} for ip in self.peers})
        self.assertEqual(len(after['nodes']), 9)
        self.assertEqual(sum(n['role'] == 'miner' for n in before['nodes']), 4)
        self.assertEqual(sum(n['role'] == 'miner' for n in after['nodes']), 6)
        self.assertEqual(sum(n['role'] == 'fleet' for n in after['nodes']), 3)
        self.assertEqual(before['edges'], after['edges'])
        self.assertEqual({n['id'] for n in before['nodes']}, {n['id'] for n in after['nodes']})
        self.assertEqual(self.config, config_before)
        for ip in self.fleets + self.peers:
            self.assertNotIn(ip, json.dumps(after))

    def test_unknown_node_stays_node(self):
        after = self.collect({self.peers[4]: {'role': 'node', 'services': 1},
                              self.peers[5]: {'role': 'miner', 'services': 9}})
        self.assertEqual(sum(n['role'] == 'node' for n in after['nodes']), 1)
        self.assertEqual(sum(n['role'] == 'miner' for n in after['nodes']), 5)

    def test_missing_metadata_keeps_valid_legacy_roles(self):
        after = self.collect()
        self.assertEqual(sum(n['role'] == 'node' for n in after['nodes']), 2)
        self.assertTrue(all(n['role'] in collector.VALID_ROLES for n in after['nodes']))
        self.assertIsNone(collector.reported_role({'role': 'node', 'services': 0}))

    def test_one_current_exporter_overrides_older_missing_reports(self):
        def source(source, *_):
            return [{'ip': ip, **({'role': 'miner', 'services': 9}
                                if source['name'] == 'fleet-3' else {})}
                    for ip in self.peers]
        with patch.object(collector, 'run_source', source):
            after, failures = collector.collect(self.config)
        self.assertEqual(failures, [])
        self.assertEqual(sum(n['role'] == 'miner' for n in after['nodes']), 6)
        self.assertEqual(sum(n['role'] == 'fleet' for n in after['nodes']), 3)

    def test_live_role_overrides_stale_configured_miner(self):
        after = self.collect({self.peers[0]: {'role': 'node', 'services': 1}})
        node = next(n for n in after['nodes'] if n['id'] == 101)
        self.assertEqual((node['role'], node['role_index']), ('node', 0))

    def test_mixed_sessions_merge_independently_of_report_order(self):
        metadata = {self.peers[4]: {'role': 'node', 'services': 1}}
        extra = [{'ip': self.peers[4], 'role': 'miner', 'services': 9}]
        after = self.collect(metadata, extra)
        self.assertEqual(after, self.collect(metadata, extra, reverse=True))
        self.assertEqual(len(after['nodes']), 9)
        self.assertEqual(len(after['edges']), 21)
        self.assertEqual(sum(n['role'] == 'miner' for n in after['nodes']), 5)

    def test_fleet_membership_is_only_configured(self):
        after = self.collect({self.peers[4]: {'role': 'fleet', 'services': 32},
                              self.fleets[0]: {'role': 'miner', 'services': 9}})
        self.assertEqual(sum(n['role'] == 'fleet' for n in after['nodes']), 3)
        self.assertEqual(sum(n['role'] == 'miner' for n in after['nodes']), 4)

    def test_metadata_and_service_validation(self):
        for peer, expected in [({}, None), ({'services': True}, None),
                               ({'services': -1}, None), ({'services': 2**64}, None),
                               ({'services': '8'}, None), ({'role': []}, None),
                               ({'services': 1}, 'node'), ({'services': 9}, 'miner'),
                               ({'services': 25}, 'validator'), ({'role': 'miner'}, 'miner')]:
            with self.subTest(peer=peer):
                self.assertEqual(collector.reported_role(peer), expected)

    def test_missing_fleet_report_does_not_invent_connections(self):
        def source(source, *_):
            if source['name'] != 'fleet-1':
                raise RuntimeError('unavailable')
            return [{'ip': self.peers[4], 'services': 9}]
        with patch.object(collector, 'run_source', source):
            result, failures = collector.collect(self.config)
        self.assertEqual(len(failures), 2)
        self.assertEqual(result['reporting_nodes'], 1)
        self.assertEqual(len(result['nodes']), 2)
        self.assertEqual(len(result['edges']), 1)
        self.assertFalse(result['edges'][0]['confirmed'])
        self.assertEqual(sum(n['role'] == 'miner' for n in result['nodes']), 1)


if __name__ == '__main__':
    unittest.main()
