"""Offline installation checks. Synthetic files do not qualify native artifacts."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SETUP=Path(__file__).resolve().parents[1]/'pkg/pool'
def module(name):
    spec=importlib.util.spec_from_file_location('pool_setup_'+name,SETUP/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
install=module('install');configure=module('configure')

class InstallTests(unittest.TestCase):
    def package(self,root):
        package=root/'package';package.mkdir()
        for name in ('bin/veld-node','lib/pool/__init__.py','setup/README.md','third-party/LICENSE'):
            path=package/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('synthetic installer fixture\n')
        self.manifest(package);return package

    def manifest(self,package):
        (package/'pool-sha256.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(package).as_posix()+'\n'
            for p in sorted(package.rglob('*')) if p.is_file() and p.name!='pool-sha256.txt'))

    @unittest.skipUnless(os.name=='posix','Linux service installer; executed by the Linux qualification gate')
    def test_complete_staging_and_role_separation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);package=self.package(root);prefix=root/'version1'
            install.stage(package,prefix,root/'config',root/'state','pool-core','pool-gateway')
            self.assertEqual((prefix/'bin/veld-node').read_bytes(),(package/'bin/veld-node').read_bytes())
            gateway=(prefix/'systemd/veld-pool-gateway.service').read_text()
            self.assertIn('User=pool-gateway',gateway);self.assertIn('IPAddressDeny=any',gateway)
            self.assertIn('InaccessiblePaths=',gateway)
            with self.assertRaises(ValueError):install.stage(package,prefix,root/'config',root/'state','pool-core','pool-gateway')
            with self.assertRaises(ValueError):install.stage(package,root/'next',root/'config',root/'state','same','same')

    def test_tampered_missing_unlisted_and_linked_artifacts_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);package=self.package(root);install.verify(package)
            target=package/'third-party/LICENSE';original=target.read_bytes();target.write_bytes(b'changed')
            with self.assertRaises(ValueError):install.verify(package)
            target.write_bytes(original);extra=package/'lib/unlisted.py';extra.write_text('extra')
            with self.assertRaises(ValueError):install.verify(package)
            extra.unlink();target.unlink()
            with self.assertRaises(ValueError):install.verify(package)
            try:target.symlink_to(root/'outside')
            except OSError:self.skipTest('symlink creation unavailable')
            with self.assertRaises(ValueError):install.verify(package)

    def values(self):
        return dict(prefix='/opt/veld-pool/candidate',state='/var/lib/veld-pool',config='/etc/veld-pool',
            genesis='ab'*32,profile='isolated-test',peer='127.0.0.1:23331',listen='127.0.0.1',
            p2p_port=23321,rpc_port=23322,tls_port=24443,pool_address='V'+'A'*33,
            fee_address='V'+'B'*33,pool_script='76a914'+'11'*20+'88ac',fee_script='76a914'+'22'*20+'88ac')

    @unittest.skipUnless(os.name=='posix','Linux service paths; executed by the Linux qualification gate')
    def test_explicit_offline_config_and_optional_comining_are_complete(self):
        values=self.values();configs=configure.render(values)
        self.assertIs(configs['backend']['enabled'],False)
        self.assertNotIn('identity',configs['coordinator'])
        self.assertEqual(configs['gateway']['coordinator_socket'],configs['coordinator']['socket'])
        self.assertEqual(configs['backend']['rpc_token_file'],configs['coordinator']['rpc_token_file'])
        values['comining']=True;configs=configure.render(values)
        self.assertEqual(configs['coordinator']['identity']['seed'],configs['coordinator']['payments']['pool_seed'])
        for change in ({'listen':'0.0.0.0'},{'peer':'8.8.8.8:23331'},{'tls_port':23322},
                       {'genesis':'AB'*32},{'prefix':'/opt/%n'},{'fee_script':values['pool_script']}):
            with self.assertRaises(ValueError):configure.render(dict(values,**change))

    @unittest.skipUnless(os.name=='posix','Linux service installation')
    def test_admin_staging_has_separate_identity_fixed_local_listener_and_no_keys(self):
        values=dict(self.values(),admin_uid=61004,admin_port=24444)
        configs=configure.render(values)
        self.assertEqual(configs['admin']['host'],'127.0.0.1')
        self.assertEqual(configs['coordinator']['operator']['max_fee_ppm'],'0')
        self.assertEqual(configs['admin']['operator_socket'],configs['coordinator']['operator']['socket'])
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);package=self.package(root);prefix=root/'version1'
            install.stage(package,prefix,root/'config',root/'state','pool-core','pool-gateway','pool-admin')
            admin=(prefix/'systemd/veld-pool-admin.service').read_text()
            self.assertIn('User=pool-admin',admin);self.assertIn('IPAddressAllow=localhost',admin)
            self.assertIn(str(root/'config/private'),admin)
            self.assertIn('ReadWritePaths=\n',admin)
            gateway=(prefix/'systemd/veld-pool-gateway.service').read_text()
            self.assertIn(str(root/'state/operator-ipc'),gateway)
            with self.assertRaises(ValueError):install.stage(package,root/'bad',root/'config',root/'state','pool-core','pool-gateway','pool-core')
        for changes in ({'admin_uid':0},{'admin_port':values['tls_port']},{'approved_max_fee_ppm':100001}):
            with self.assertRaises(ValueError):configure.render(dict(values,**changes))

if __name__=='__main__':unittest.main()
