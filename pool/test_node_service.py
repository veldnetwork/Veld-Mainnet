import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from .node_service import configuration, command, deployment, export_token, validate_deployment
from .protocol import Refused


class BackendServiceTests(unittest.TestCase):
    def config(self, root):
        return dict(
            enabled=True,
            binary='/explicit/veld-node',
            datadir=str(root / 'node'),
            passphrase_file=str(root / 'password'),
            rpc_token_file=str(root / 'rpc-capability'),
            genesis='a' * 64,
            profile='private-fixture',
            p2p_port=23001,
            rpc_port=23002,
            peers=['127.0.0.1:23011'],
        )

    @unittest.skipUnless(os.name == 'posix', 'Linux backend supervisor configuration')
    def test_disabled_and_implicit_network_configuration_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            configuration(config)
            for change in (
                {'enabled': False},
                {'peers': []},
                {'peers': ['public.example:8333']},
                {'rpc_port': 23001},
                {'binary': 'relative'},
                {'extra_option': '--mine'},
            ):
                with self.assertRaises((Refused, ValueError)):
                    configuration(dict(config, **change))
            args = command(config)
            self.assertIn('--full-ibd', args)
            self.assertIn('--txindex', args)
            self.assertIn('--nomine', args)
            self.assertNotIn('--mine', args)
            self.assertNotIn('--regtest', args)

    def test_metadata_does_not_read_secrets(self):
        record = {'binary_role': 'node', 'genesis_fingerprint': 'a' * 64}
        with patch(
            'pool.node_service.subprocess.run',
            return_value=SimpleNamespace(
                stdout=('VELD_DEPLOYMENT_INFO_V1_JSON ' + json.dumps(record) + '\n').encode()
            ),
        ) as run:
            self.assertEqual(deployment('/node'), record)
            self.assertEqual(run.call_args.args[0], ['/node', '--deployment-info'])

    @unittest.skipUnless(os.name == 'posix', 'Linux backend supervisor configuration')
    def test_alternate_transport_needs_disposable_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            config = configuration(dict(self.config(Path(directory)), runtime_network='regtest'))
            self.assertIn('--regtest', command(config))
            identity = dict(
                binary_role='node',
                fleet_no_mine=False,
                mining_rpc_methods_compiled=True,
                profile_id=config['profile'],
                genesis_fingerprint='a' * 64,
            )
            with self.assertRaises(Refused):
                validate_deployment(identity, config)
            validate_deployment(dict(identity, disposable=True, external_value=False), config)
            with self.assertRaises(Refused):
                configuration(dict(config, runtime_network='--mine'))

    def test_compiled_fingerprint_is_converted_to_rpc_hash_order(self):
        compiled = 'ee875e86d25aabad2442451b82f6550b732a1387cbc172c2a3fc02eb216af3d5'
        config = {'profile': 'isolated-test', 'genesis': bytes.fromhex(compiled)[::-1].hex()}
        identity = {
            'binary_role': 'node',
            'fleet_no_mine': False,
            'mining_rpc_methods_compiled': True,
            'profile_id': 'isolated-test',
            'genesis_fingerprint': compiled,
        }
        validate_deployment(identity, config)
        for change in (
            {'genesis_fingerprint': config['genesis']},
            {'profile_id': 'another-chain'},
            {'fleet_no_mine': True},
            {'genesis_fingerprint': None},
        ):
            with self.assertRaises(Refused):
                validate_deployment(dict(identity, **change), config)

    def test_protected_token_export_and_invalid_response_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.config(root)
            (root / 'password').write_text('disposable password only\n')
            (root / 'password').chmod(0o600)
            with patch(
                'pool.node_service.subprocess.run',
                return_value=SimpleNamespace(stdout=b'b' * 64 + b'\n'),
            ) as run:
                export_token(config)
                self.assertNotIn('disposable password', str(run.call_args.args))
            self.assertEqual((root / 'rpc-capability').read_bytes(), b'b' * 64 + b'\n')
            config['runtime_network'] = 'regtest'
            with patch(
                'pool.node_service.subprocess.run',
                return_value=SimpleNamespace(stdout=b'b' * 64 + b'\n'),
            ) as run:
                export_token(config)
                self.assertIn('--regtest', run.call_args.args[0])
            if os.name == 'posix':
                self.assertEqual((root / 'rpc-capability').stat().st_mode & 0o777, 0o600)
            for value in (b'', b'garbage', b'b' * 65, b'B' * 64, b'b' * 64 + b'\nextra'):
                with patch(
                    'pool.node_service.subprocess.run', return_value=SimpleNamespace(stdout=value)
                ):
                    with self.assertRaises(Refused):
                        export_token(config)


if __name__ == '__main__':
    unittest.main()
