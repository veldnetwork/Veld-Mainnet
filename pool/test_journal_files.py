import os
from pathlib import Path
import tempfile
import unittest
from .journal import Journal, atomic
from .protocol import Refused


class JournalFiles(unittest.TestCase):
    def test_atomic_does_not_follow_predictable_temporary_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            target.write_text('unchanged')
            old = root / 'anchor.new'
            try:
                old.symlink_to(target)
            except OSError:
                self.skipTest('symlink privilege unavailable')
            atomic(root / 'anchor', b'new record')
            self.assertEqual(target.read_text(), 'unchanged')
            self.assertEqual((root / 'anchor').read_bytes(), b'new record')

    @unittest.skipUnless(os.name == 'posix', 'Linux service permissions')
    def test_public_or_symlinked_journal_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsafe = root / 'unsafe'
            unsafe.mkdir(mode=0o755)
            with self.assertRaises(Refused):
                Journal(unsafe, root / 'anchors/current')
            safe = root / 'safe'
            safe.mkdir(mode=0o700)
            (root / 'link').symlink_to(safe)
            with self.assertRaises(Refused):
                Journal(root / 'link', root / 'anchors/current')


if __name__ == '__main__':
    unittest.main()
