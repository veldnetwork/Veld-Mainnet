import http.client
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from .backend import Node
from .protocol import Busy

class BackendHttpTests(unittest.TestCase):
    def test_invalid_http_never_becomes_a_result_or_an_automatic_write_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            token=Path(directory)/'token';token.write_text('a'*64);token.chmod(0o600)
            node=Node('http://127.0.0.1:32772',token,'b'*64)
            for error in (http.client.BadStatusLine('POST / HTTP/1.1\r\n'),
                          http.client.IncompleteRead(b'partial'),http.client.RemoteDisconnected()):
                with patch('pool.backend.http.client.HTTPConnection') as connection:
                    connection.return_value.getresponse.side_effect=error
                    with self.assertRaises(Busy):node.call('sendrawtransaction','exact-disposable-test-bytes')
                    self.assertEqual(connection.return_value.request.call_count,1)
                    connection.return_value.close.assert_called_once()

if __name__=='__main__':unittest.main()
