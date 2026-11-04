"""Recovery buffering regression using real disposable journals and files."""

import builtins
from contextlib import closing
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from .journal import Journal


class CountingWriter(io.RawIOBase):
    def __init__(self, file):
        self.file = file
        self.read_calls = 0

    def readable(self):
        return True

    def writable(self):
        return True

    def seekable(self):
        return True

    def fileno(self):
        return self.file.fileno()

    def seek(self, *args):
        return self.file.seek(*args)

    def tell(self):
        return self.file.tell()

    def write(self, data):
        return self.file.write(data)

    def read(self, size=-1):
        self.read_calls += 1
        return self.file.read(size)

    def close(self):
        self.file.close()
        super().close()


class JournalBuffering(unittest.TestCase):
    def test_recovery_does_not_read_durable_writer_byte_by_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data, anchor = root / 'data', root / 'anchor/current'
            with closing(Journal(data, anchor)) as journal:
                for i in range(8):
                    journal.append('fixture', {'i': i, 'body': 'x' * 131072})
                expected = list(journal.events())
            original_log = (data / 'events.jsonl').read_bytes()
            original_anchor = anchor.read_bytes()
            writers = []

            def tracked_open(path, *args, **kwargs):
                file = builtins.open(path, *args, **kwargs)
                if Path(path).name == 'events.jsonl' and args == ('a+b',):
                    file = CountingWriter(file)
                    writers.append(file)
                return file

            with patch('pool.journal.open', tracked_open, create=True):
                with closing(Journal(data, anchor)) as recovered:
                    self.assertEqual(list(recovered.events()), expected)
                    self.assertEqual(recovered.index_repairs, 0)
                    self.assertEqual((data / 'events.jsonl').read_bytes(), original_log)
                    self.assertEqual(anchor.read_bytes(), original_anchor)
                    self.assertEqual(len(writers), 1)
                    self.assertEqual(writers[0].read_calls, 0)
                    recovered.append('fixture', {'i': 8})
            with closing(Journal(data, anchor)) as reopened:
                self.assertEqual(list(reopened.events())[:8], expected)
                self.assertEqual(reopened.sequence, 9)


if __name__ == '__main__':
    unittest.main()
