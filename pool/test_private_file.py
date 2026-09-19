"""Credential boundary tests, not native mining qualification."""
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from pool.backend import Node
from pool.private_file import read_private
from pool.protocol import Refused


class PrivateFileTests(unittest.TestCase):
    def test_rotation_is_read_before_each_request_and_invalid_replacement_sends_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'token'
            node=Node('http://127.0.0.1:32462',path,'a'*64)
            with patch('pool.backend.http.client.HTTPConnection') as transport:
                response=transport.return_value.getresponse.return_value
                response.status=200
                response.read.side_effect=[b'{"id":1,"result":0}',b'{"id":2,"result":0}']
                for token in ('b'*64,'c'*64):
                    temporary=path.with_suffix('.new');temporary.write_text(token);temporary.chmod(0o600)
                    os.replace(temporary,path)
                    self.assertEqual(node.call('getblockcount'),0)
                    self.assertEqual(transport.return_value.request.call_args.args[3]['Authorization'],'Bearer '+token)
                request_count=transport.call_count
                for bad in (b'',b'bad',b'd'*129,b'\xff'*64):
                    path.write_bytes(bad)
                    with self.assertRaises((Refused,UnicodeError)):node.call('getblockcount')
                    self.assertEqual(transport.call_count,request_count)
                path.unlink()
                with self.assertRaises(OSError):node.call('getblockcount')
                self.assertEqual(transport.call_count,request_count)

    @unittest.skipIf(os.name=='nt','Linux service ownership and symlink boundary')
    def test_symlink_fifo_and_unsafe_permissions_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);path=root/'token';link=root/'link';fifo=root/'fifo'
            path.write_bytes(b'x');path.chmod(0o600);link.symlink_to(path)
            with self.assertRaises(OSError):read_private(link,128)
            os.mkfifo(fifo,0o600)
            with self.assertRaises(Refused):read_private(fifo,128)
            for mode in (0o644,0o620,0o602,0o601):
                path.chmod(mode)
                with self.assertRaises(Refused):read_private(path,128)
            path.chmod(0o640)
            self.assertEqual(read_private(path,128),b'x')

if __name__=='__main__':unittest.main()
