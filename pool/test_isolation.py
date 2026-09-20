"""Focused guards for the disposable qualification launcher."""
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch,mock_open
from pool.qualification.isolation import MARKER,require_isolated_network,service_identities_available

class IsolationTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','Linux qualification identity mapping')
    def test_single_uid_namespace_cannot_claim_service_separation(self):
        with patch('os.geteuid',return_value=0):
            for mapping in ('0 1000 1\n','0 0 10000\n','malformed\n'):
                with patch('builtins.open',mock_open(read_data=mapping)):
                    self.assertFalse(service_identities_available())
            with patch('builtins.open',mock_open(read_data='0 0 4294967295\n')):
                self.assertTrue(service_identities_available())
        with patch('os.geteuid',return_value=1000):self.assertFalse(service_identities_available())

    def check(self,parent,current,links,routes=''):
        responses=[SimpleNamespace(stdout=links),SimpleNamespace(stdout=routes)]
        with patch.dict(os.environ,{MARKER:parent}),patch('os.readlink',return_value=current),\
             patch('pool.qualification.isolation.subprocess.run',side_effect=responses):
            require_isolated_network()
    def test_private_loopback_namespace_is_accepted(self):
        self.check('net:[1]','net:[2]','[{"ifname":"lo"}]','local 127.0.0.1 dev lo table local scope host\n')
    def test_same_or_missing_namespace_is_refused(self):
        for parent in ('','net:[2]'):
            with self.assertRaises(RuntimeError):self.check(parent,'net:[2]','[]')
    def test_external_interface_is_refused(self):
        with self.assertRaises(RuntimeError):self.check('net:[1]','net:[2]','[{"ifname":"lo"},{"ifname":"eth0"}]')
    def test_non_loopback_route_is_refused(self):
        with self.assertRaises(RuntimeError):self.check('net:[1]','net:[2]','[{"ifname":"lo"}]','default via 10.0.0.1 dev eth0\n')

if __name__=='__main__':unittest.main()
