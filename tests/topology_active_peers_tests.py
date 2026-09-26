"""Only fresh canonical tip reports enter the public active-node graph.

These are isolated fixtures, not P2P validation or consensus qualification.
"""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/veld-topology-rpc-collector.py'
SPEC = importlib.util.spec_from_file_location('active_collector', SOURCE)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)
TIPS = {9250: 'a' * 64, 9249: 'b' * 64, 9248: 'c' * 64}


class MembershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        salt = Path(self.temp.name) / 'salt'
        salt.write_bytes(b'isolated-fixture-only-salt' * 2)
        self.config = {
            'salt_file': str(salt),
            'key_file': 'unused',
            'known_hosts': 'unused',
            'sources': [{'name': 'local', 'address': '192.0.2.1', 'local': True}],
            'known': {'192.0.2.1': {'id': 1, 'role': 'fleet'}},
        }

    def view(self, rows):
        with (
            patch.object(collector, 'run_source', return_value=rows),
            patch.object(collector, 'reference_tips', return_value=TIPS),
            patch.object(collector.time, 'time', return_value=1000),
        ):
            view, errors = collector.collect(self.config)
        self.assertFalse(errors)
        ids = {n['id'] for n in view['nodes']}
        self.assertEqual(view['eligible_nodes'], len(ids))
        self.assertTrue(all(e['a'] in ids and e['b'] in ids for e in view['edges']))
        self.assertNotIn('198.51.100.', json.dumps(view))
        return view

    def peer(self, **changes):
        return {
            'ip': '198.51.100.1',
            'peer_height': 9250,
            'peer_tip_hash': TIPS[9250],
            'peer_tip_age_s': 1,
            'services': 9,
            **changes,
        }

    def test_stuck_peer_excluded_then_automatically_rejoins_after_catchup(self):
        old = self.peer(peer_height=3840, peer_tip_hash='d' * 64)
        self.assertEqual(self.view([old])['eligible_nodes'], 1)
        self.assertEqual(self.view([old])['not_current_nodes'], 1)
        caught_up = self.view([self.peer()])
        self.assertEqual(caught_up['eligible_nodes'], 2)
        self.assertEqual(caught_up['not_current_nodes'], 0)
        self.assertTrue(all(n['tip_state'] == 'exact' for n in caught_up['nodes']))
        self.assertEqual(self.view([old])['eligible_nodes'], 1)

    def test_two_block_canonical_grace_and_no_arbitrary_same_height_fork(self):
        for height, block_hash in TIPS.items():
            with self.subTest(height=height):
                view = self.view([self.peer(peer_height=height, peer_tip_hash=block_hash)])
                self.assertEqual(view['eligible_nodes'], 2)
                if height < 9250:
                    self.assertEqual(sum(n['tip_state'] == 'differs' for n in view['nodes']), 1)
                self.assertEqual(
                    self.view([self.peer(peer_height=height, peer_tip_hash='d' * 64)])[
                        'eligible_nodes'
                    ],
                    1,
                )
        self.assertEqual(self.view([self.peer(peer_height=9247)])['eligible_nodes'], 1)
        self.assertEqual(self.view([self.peer(peer_height=9251)])['eligible_nodes'], 1)

    def test_external_majority_cannot_change_reference(self):
        rows = [
            self.peer(ip=f'198.51.100.{i}', peer_height=3840, peer_tip_hash='d' * 64)
            for i in range(1, 100)
        ] + [self.peer(ip='198.51.100.100')]
        view = self.view(rows)
        self.assertEqual(view['eligible_nodes'], 2)
        self.assertEqual(view['not_current_nodes'], 99)
        self.assertEqual(view['reference_height'], 9250)

    def test_ages_types_and_missing_metadata(self):
        for changes in (
            {'peer_tip_age_s': 181},
            {'peer_tip_age_s': -1},
            {'peer_tip_age_s': True},
            {'peer_tip_age_s': '1'},
            {'peer_height': None},
            {'peer_height': True},
            {'peer_height': '9250'},
            {'peer_height': 2**32},
            {'peer_tip_hash': '0' * 64},
            {'peer_tip_hash': 'z' * 64},
        ):
            with self.subTest(changes=changes):
                self.assertEqual(self.view([self.peer(**changes)])['eligible_nodes'], 1)
        self.assertEqual(self.view([self.peer(peer_tip_age_s=180)])['eligible_nodes'], 2)
        self.assertEqual(self.view([{'ip': '198.51.100.1'}])['eligible_nodes'], 1)

    def test_address_group_with_old_and_updated_sessions_counts_once(self):
        rows = [self.peer(), self.peer(peer_height=3840, peer_tip_hash='d' * 64), self.peer()]
        first = self.view(rows)
        self.assertEqual(first['eligible_nodes'], 2)
        self.assertEqual(first, self.view(list(reversed(rows))))
        self.assertEqual(len(first['edges']), 1)

    def test_reference_failure_preserves_previous_output_and_fails_refresh(self):
        output = Path(self.temp.name) / 'topology.json'
        output.write_text('{"generated_at":900}')
        config = Path(self.temp.name) / 'config.json'
        config.write_text(json.dumps({**self.config, 'output': str(output)}))
        with (
            patch.object(collector, 'run_source', return_value=[self.peer()]),
            patch.object(collector, 'reference_tips', side_effect=ValueError('unavailable')),
            patch('sys.argv', ['collector', '--config', str(config)]),
            patch('sys.stderr'),
        ):
            self.assertEqual(collector.main(), 1)
        self.assertEqual(output.read_text(), '{"generated_at":900}')

    def test_reorg_invalidates_prior_membership_without_permanent_exclusions(self):
        self.assertEqual(self.view([self.peer()])['eligible_nodes'], 2)
        changed = {9250: 'e' * 64, 9249: 'f' * 64, 9248: 'c' * 64}
        with (
            patch.object(collector, 'run_source', return_value=[self.peer()]),
            patch.object(collector, 'reference_tips', return_value=changed),
        ):
            view, _ = collector.collect(self.config)
        self.assertEqual(view['eligible_nodes'], 1)
        self.assertNotIn('excluded', self.config)


class ReferenceTests(unittest.TestCase):
    def page(self):
        return {
            'tip_height': 9250,
            'tip_hash': 'a' * 64,
            'blocks': [
                {'height': 9250, 'hash': 'a' * 64, 'prev_hash': 'b' * 64},
                {'height': 9249, 'hash': 'b' * 64, 'prev_hash': 'c' * 64},
                {'height': 9248, 'hash': 'c' * 64, 'prev_hash': 'd' * 64},
            ],
        }

    def test_canonical_linked_history(self):
        with patch.object(collector, 'local_public_json', return_value=self.page()) as read:
            self.assertEqual(collector.reference_tips(), TIPS)
        read.assert_called_once_with('/api/v1/blocks/latest/3')

    def test_summary_budget_failure_falls_back_to_exact_tip_only(self):
        with patch.object(
            collector,
            'local_public_json',
            side_effect=[ValueError('budget'), {'height': 9250, 'best_block_hash': 'a' * 64}],
        ):
            self.assertEqual(collector.reference_tips(), {9250: 'a' * 64})

    def test_malformed_or_unlinked_summary_is_not_used(self):
        variants = []
        for mutate in (
            lambda p: p.update(tip_height=True),
            lambda p: p.update(tip_hash='e' * 64),
            lambda p: p['blocks'][1].update(height=9247),
            lambda p: p['blocks'][0].update(prev_hash='f' * 64),
            lambda p: p.update(blocks=[False]),
            lambda p: p.update(blocks=p['blocks'][:2]),
        ):
            page = self.page()
            mutate(page)
            variants.append(page)
        for page in variants:
            with (
                self.subTest(page=page),
                patch.object(
                    collector,
                    'local_public_json',
                    side_effect=[page, {'height': 9250, 'best_block_hash': 'a' * 64}],
                ),
            ):
                self.assertEqual(collector.reference_tips(), {9250: 'a' * 64})

    def test_invalid_fallback_is_not_a_reference(self):
        for stats in (
            {},
            {'height': True, 'best_block_hash': 'a' * 64},
            {'height': -1, 'best_block_hash': 'a' * 64},
            {'height': 9250, 'best_block_hash': '0' * 64},
        ):
            with (
                self.subTest(stats=stats),
                patch.object(collector, 'local_public_json', side_effect=[{}, stats]),
            ):
                with self.assertRaises(ValueError):
                    collector.reference_tips()

    def test_local_http_is_bounded_and_closed_even_on_error(self):
        for status, body in (
            (200, b'{}'),
            (503, b'{}'),
            (200, b'[]'),
            (200, b'x' * (collector.MAX_RPC_BYTES + 1)),
        ):
            connection = MagicMock()
            response = connection.getresponse.return_value
            response.status = status
            response.read.return_value = body
            with patch.object(
                collector.http.client, 'HTTPConnection', return_value=connection
            ) as factory:
                if status == 200 and body == b'{}':
                    self.assertEqual(collector.local_public_json('/api/stats'), {})
                else:
                    with self.assertRaises(ValueError):
                        collector.local_public_json('/api/stats')
            factory.assert_called_once_with('127.0.0.1', 8080, timeout=3)
            response.read.assert_called_once_with(collector.MAX_RPC_BYTES + 1)
            connection.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
