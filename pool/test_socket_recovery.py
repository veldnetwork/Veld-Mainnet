import os
from pathlib import Path
import socket
import tempfile
import unittest
from .protocol import Refused

if os.name != 'posix':
    raise unittest.SkipTest(
        'Linux Unix-domain service socket; required and executed in Linux qualification'
    )
from .service import prepare_socket


@unittest.skipUnless(os.name == 'posix', 'Linux coordinator IPC')
class SocketRecovery(unittest.TestCase):
    def test_dead_socket_recovers_without_operator_unlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'pool.sock'
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen()
                with self.assertRaises(Refused):
                    prepare_socket(path)
                self.assertTrue(path.exists())
            prepare_socket(path)
            self.assertFalse(path.exists())

    def test_file_symlink_and_writable_parent_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'pool.sock'
            path.write_text('keep')
            with self.assertRaises(Refused):
                prepare_socket(path)
            self.assertEqual(path.read_text(), 'keep')
            path.unlink()
            path.symlink_to('missing')
            with self.assertRaises(Refused):
                prepare_socket(path)
            path.unlink()
            os.chmod(directory, 0o770)
            with self.assertRaises(Refused):
                prepare_socket(path)
            os.chmod(directory, 0o700)


if __name__ == '__main__':
    unittest.main()
