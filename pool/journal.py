"""Append-first event journal with an independently retained rollback anchor.

SQLite is a rebuildable index. Restore must keep the current journal AND anchor;
a backup which predates either is refused. Losing/rewinding both is not claimed
to be recoverable: payments and work must remain stopped in that incident.
"""
import hashlib
import os
from pathlib import Path
import sqlite3
import threading
import secrets
import stat

from .protocol import decode, encode, require, Refused, schema, hex64, MAX_JOURNAL_BYTES

ZERO = '0' * 64
# Exact issued candidates must survive restart, including maximum-size blocks.
# Leave bounded room for RPC metadata and the journal's integrity envelope.
MAX_EVENT = MAX_JOURNAL_BYTES

def directory_sync(path):
    if os.name != 'nt':
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

def atomic(path, data):
    path=Path(path)
    temporary = path.with_name(path.name + '.' + secrets.token_hex(16) + '.new')
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         getattr(os,'O_NOFOLLOW',0), 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        directory_sync(str(path.parent))
    finally:
        temporary.unlink(missing_ok=True)

def private_directory(path):
    path=Path(path)
    path.mkdir(parents=True,exist_ok=True,mode=0o700)
    metadata=path.lstat()
    require(stat.S_ISDIR(metadata.st_mode),'journal directory must not be a symlink')
    if os.name!='nt':
        require(metadata.st_uid==os.geteuid() and metadata.st_mode & 0o077==0,
                'journal directory must be owner-only')

class Journal:
    def __init__(self, directory, anchor):
        self.db = self.log = self.guard = None
        try:
            self._open(directory, anchor)
        except BaseException:
            self.close()
            raise

    def _open(self, directory, anchor):
        self.directory, self.anchor = Path(directory), Path(anchor)
        private_directory(self.directory)
        private_directory(self.anchor.parent)
        require(not self.anchor.resolve().is_relative_to(self.directory.resolve()),
                'anchor must be outside service backup directory')
        self.lock = threading.RLock()
        self.guard = open(self.directory/'coordinator.lock', 'a+b')
        if os.name == 'nt':
            import msvcrt
            if os.fstat(self.guard.fileno()).st_size == 0:
                self.guard.write(b'0'); self.guard.flush()
            self.guard.seek(0)
            msvcrt.locking(self.guard.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(self.guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = self.directory/'events.jsonl'
        was_present = path.exists()
        if was_present:
            require(self.anchor.exists(), 'surviving rollback anchor required')
        self.log = open(path, 'a+b', buffering=0)
        if not was_present:
            os.chmod(path, 0o600)
            directory_sync(str(self.directory))
        self.db = sqlite3.connect(self.directory/'index.sqlite', check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, digest TEXT NOT NULL UNIQUE, body BLOB NOT NULL)')
        self.db.commit()
        self.sequence, self.digest = 0, ZERO
        self.index_repairs = 0
        if self.anchor.exists():
            with self.anchor.open('rb') as file:
                marker = decode(file.read(257), 256)
            schema(marker, ('seq', 'digest'))
            require(type(marker['seq']) is int and 0 <= marker['seq'] < (1 << 63), 'anchor sequence')
            hex64(marker['digest'])
        else:
            marker = {'seq': 0, 'digest': ZERO}
        seen_anchor = marker == {'seq': 0, 'digest': ZERO}
        # Recovery uses a bounded buffered reader on the same inode. Calling
        # readline on the unbuffered durable writer incurs one syscall per byte.
        # Keep the append handle unbuffered so write/fsync ordering is unchanged.
        with self._reader() as stream:
            for line in iter(lambda: stream.readline(MAX_EVENT + 1), b''):
                require(len(line) <= MAX_EVENT and line.endswith(b'\n'), 'damaged journal: stop and reconcile')
                event = decode(line, MAX_EVENT)
                require(set(event) == {'seq','previous','kind','payload','digest'}, 'journal schema')
                digest = event.pop('digest')
                require(type(event['seq']) is int and event['seq'] == self.sequence + 1 and
                        event['previous'] == self.digest, 'journal ordering')
                require(hashlib.sha256(encode(event)).hexdigest() == digest, 'journal integrity')
                self.sequence, self.digest = event['seq'], digest
                if self.sequence == marker['seq']:
                    require(digest == marker['digest'], 'rollback anchor mismatch')
                    seen_anchor = True
                self._index(event, digest)
        require(seen_anchor, 'journal rollback: current signing/work history required')
        indexed = self.db.execute('SELECT COUNT(*),COALESCE(MAX(seq),0) FROM events').fetchone()
        require(indexed == (self.sequence, self.sequence), 'index ahead of journal')
        self.db.commit()
        atomic(self.anchor, encode({'seq': self.sequence, 'digest': self.digest}))
        self.log.seek(0, os.SEEK_END)

    def _reader(self):
        original = os.fstat(self.log.fileno())
        descriptor = os.open(self.directory/'events.jsonl', os.O_RDONLY |
                             getattr(os, 'O_NOFOLLOW', 0))
        try:
            current = os.fstat(descriptor)
            require((current.st_dev, current.st_ino) == (original.st_dev, original.st_ino),
                    'journal identity changed during replay')
            return os.fdopen(descriptor, 'rb', buffering=65536)
        except BaseException:
            os.close(descriptor)
            raise

    def _index(self, event, digest):
        body = encode(event)
        # A digest column does not authenticate its neighboring cached body.
        # Bound any cached BLOB read and reconstruct it only from the verified
        # journal event. SQLite never supplies recovery authority.
        prior = self.db.execute("SELECT digest, CASE WHEN typeof(body)='blob' AND length(body)<=? THEN body ELSE NULL END "
                                'FROM events WHERE seq=?', (MAX_EVENT, event['seq'])).fetchone()
        if prior:
            require(prior[0] == digest, 'index identity mismatch')
            if prior[1] != body:
                self.db.execute('UPDATE events SET body=? WHERE seq=?', (body, event['seq']))
                self.index_repairs += 1
        else:
            self.db.execute('INSERT INTO events VALUES(?,?,?)', (event['seq'], digest, body))

    def append(self, kind, payload):
        with self.lock:
            event = {'seq': self.sequence + 1, 'previous': self.digest, 'kind': kind, 'payload': payload}
            digest = hashlib.sha256(encode(event)).hexdigest()
            line = encode(dict(event, digest=digest)) + b'\n'
            require(len(line) <= MAX_EVENT, 'event limit')
            # Persistence failure poisons this process: callers must shut down,
            # never continue with a potentially uncertain journal position.
            try:
                require(self.log.write(line) == len(line), 'partial journal write')
                os.fsync(self.log.fileno())
                atomic(self.anchor, encode({'seq': event['seq'], 'digest': digest}))
                self._index(event, digest); self.db.commit()
            except BaseException:
                self.close()
                raise
            self.sequence, self.digest = event['seq'], digest
            return self.sequence

    def events(self):
        with self.lock:
            # Consumers reconstruct nonce reservations, signing commitments and
            # balances from the authoritative log, never a mutable SQLite copy.
            # Use an independent cursor: nested reads or appends made by a caller
            # must not rewind the durable writer or extend this replay snapshot.
            count, expected_digest = self.sequence, self.digest
            original = os.fstat(self.log.fileno())
            with self._reader() as stream:
                previous = ZERO
                for sequence in range(1, count + 1):
                    line = stream.readline(MAX_EVENT + 1)
                    require(len(line) <= MAX_EVENT and line.endswith(b'\n'), 'damaged journal: stop and reconcile')
                    event = decode(line, MAX_EVENT)
                    schema(event, ('seq','previous','kind','payload','digest'))
                    digest = event.pop('digest')
                    require(type(event['seq']) is int and event['seq'] == sequence and
                            event['previous'] == previous, 'journal ordering')
                    require(hashlib.sha256(encode(event)).hexdigest() == digest, 'journal integrity')
                    previous = digest
                    yield event
                require(previous == expected_digest and stream.tell() == original.st_size,
                        'journal changed during replay')

    def close(self):
        for name in ('db', 'log', 'guard'):
            resource = getattr(self, name, None)
            if resource is not None:
                resource.close()
                setattr(self, name, None)
