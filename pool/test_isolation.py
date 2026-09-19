"""Focused guards for the disposable qualification launcher."""
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pool.qualification.isolation import MARKER,require_isolated_network

class IsolationTests(unittest.TestCase):
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
