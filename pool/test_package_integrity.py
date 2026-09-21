"""A manifest of sources must not leave an executable bytecode alternative."""
from pathlib import Path
import runpy
import tempfile
import unittest

verify = runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/verify-python-package.py'))['verify']


class PackageIntegrityTests(unittest.TestCase):
    def test_verification_does_not_execute_code_or_create_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'module.py').write_text('raise RuntimeError("must never execute during validation")\n')
            self.assertEqual(verify(root), 1)
            self.assertEqual([p.name for p in root.iterdir()], ['module.py'])

    def test_cached_and_sourceless_bytecode_are_refused(self):
        for relative in ('module.pyc', '__pycache__/module.cpython-314.pyc'):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/'module.py').write_text('VALUE = 1\n')
                alternate = root/relative
                alternate.parent.mkdir(exist_ok=True)
                alternate.write_bytes(b'executable content outside source manifest')
                with self.assertRaises(ValueError): verify(root)

    def test_invalid_source_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'module.py').write_text('def broken(:\n')
            with self.assertRaises(SyntaxError): verify(root)


if __name__ == '__main__': unittest.main()
