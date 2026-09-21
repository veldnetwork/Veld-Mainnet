"""Build-controller version drift must not accept mismatched artifacts."""
from pathlib import Path
import shutil
import tempfile
import unittest
from .qualification.production import SOURCE,verify_deployment_version

class ProductionIdentityTests(unittest.TestCase):
    def test_new_source_version_is_supported_and_mismatched_binary_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)
            (source/'scripts').mkdir();(source/'include/core').mkdir(parents=True)
            shutil.copy2(SOURCE/'scripts/verify-release-version.py',source/'scripts/verify-release-version.py')
            header=source/'include/core/version.h'
            header.write_text('inline constexpr const char* CLIENT_VERSION = "9.8.7";\n'
                              'inline constexpr const char* CLIENT_USER_AGENT = "/Veld:9.8.7/";\n')
            self.assertEqual(verify_deployment_version(source,dict(client_version='9.8.7')),'9.8.7')
            for value in ({},{'client_version':'3.2.1'},{'client_version':'9.8.6'}):
                with self.subTest(value=value),self.assertRaises(ValueError):verify_deployment_version(source,value)
            header.write_text(header.read_text().replace('/Veld:9.8.7/','/Veld:9.8.6/'))
            with self.assertRaises(ValueError):verify_deployment_version(source,dict(client_version='9.8.7'))

if __name__=='__main__':unittest.main()
