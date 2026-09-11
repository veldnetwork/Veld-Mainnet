"""Atomic, journaled installation of already signed checkpoint documents."""
from pathlib import Path
import base64
import contextlib
import json
import os
import re
import stat
import subprocess
import sys
import time

from policy import MAX_BYTES, append_only, parse, require, sha


def read_regular(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= MAX_BYTES, 'Unsafe checkpoint file')
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, 'Checkpoint file exceeded limit')
    return raw


def atomic_write(path, raw, mode=0o600):
    path = Path(path)
    temporary = path.parent / ('.'+path.name+'.'+os.urandom(12).hex())
    try:
        with temporary.open('xb') as stream:
            os.chmod(temporary, mode)
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != 'nt':
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_json(path, value):
    atomic_write(path, (json.dumps(value, sort_keys=True, indent=2)+'\n').encode())


class Store:
    def __init__(self, config, verifier=None):
        self.feed = Path(config['feed'])
        self.state = Path(config['state'])
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not self.state.is_symlink() and not self.feed.parent.is_symlink(), 'Unsafe publication path')
        self.tool = config.get('verifier')
        self.tool_sha = config.get('verifier_sha256')
        self.verifier = verifier or self.verify

    def verify(self, raw):
        records = parse(raw)
        require(sha(Path(self.tool).read_bytes()) == self.tool_sha, 'Verifier identity changed')
        target = self.state/('verify-'+os.urandom(12).hex()+'.json')
        try:
            atomic_write(target, raw)
            result = subprocess.run([self.tool,'verify',str(target),str(len(records))],capture_output=True,timeout=20)
            require(result.returncode == 0, 'Checkpoint signature verification failed')
            require(json.loads(result.stdout)['verified'] == len(records), 'Checkpoint verification count mismatch')
        finally:
            target.unlink(missing_ok=True)

    def transaction_path(self, transaction):
        require(isinstance(transaction, str) and re.fullmatch('[0-9a-f]{32}', transaction), 'Invalid transaction identity')
        return self.state/('transaction-'+transaction+'.json')

    def read(self):
        raw = read_regular(self.feed)
        parse(raw)
        pending = []
        for path in self.state.glob('transaction-*.json'):
            record = json.loads(read_regular(path))
            if record['phase'] in ('prepared','installed'):
                pending.append(record)
        require(len(pending) <= 1, 'Multiple unresolved publication transactions')
        return dict(sha256=sha(raw), document_b64=base64.b64encode(raw).decode(), pending=pending)

    def install(self, request):
        transaction = request['transaction']
        journal = self.transaction_path(transaction)
        require(not journal.exists(), 'Publication transaction already exists')
        require(not self.read()['pending'], 'Previous publication requires recovery')
        old = read_regular(self.feed)
        new = base64.b64decode(request['document_b64'], validate=True)
        require(sha(old) == request['base_sha256'], 'Checkpoint feed changed before publication')
        before, after = parse(old), parse(new)
        append_only(before, after)
        require(after[-1]['height'] % 100 == 0, 'Checkpoint interval rejected')
        self.verifier(old); self.verifier(new)
        backup = self.state/('feed-'+sha(old)+'.json')
        if backup.exists(): require(read_regular(backup) == old, 'Backup identity mismatch')
        else: atomic_write(backup, old)
        record = dict(transaction=transaction, phase='prepared', before_sha256=sha(old), after_sha256=sha(new),
                      checkpoint_height=after[-1]['height'], prepared_at=int(time.time()))
        atomic_json(journal, record)
        atomic_write(self.feed, new, 0o644)
        record['phase'] = 'installed'
        atomic_json(journal, record)
        return record

    def finish(self, transaction, commit):
        journal = self.transaction_path(transaction)
        record = json.loads(read_regular(journal))
        raw = read_regular(self.feed)
        if commit:
            require(record['phase'] in ('prepared','installed','committed'), 'Transaction cannot be committed')
            require(sha(raw) == record['after_sha256'], 'Published feed changed before commit')
            self.verifier(raw)
            record['phase'] = 'committed'
            record['committed_at'] = int(time.time())
        else:
            require(record['phase'] in ('prepared','installed','rolled_back'), 'Transaction cannot be rolled back')
            require(sha(raw) in (record['before_sha256'], record['after_sha256']), 'Rollback refuses unrelated feed change')
            old = read_regular(self.state/('feed-'+record['before_sha256']+'.json'))
            require(sha(old) == record['before_sha256'], 'Rollback backup mismatch')
            self.verifier(old)
            if sha(raw) != record['before_sha256']: atomic_write(self.feed, old, 0o644)
            record['phase'] = 'rolled_back'
            record['rolled_back_at'] = int(time.time())
        atomic_json(journal, record)
        return record

    def checked(self, tip):
        raw = read_regular(self.feed)
        records = parse(raw)
        require(type(tip) is int and tip >= records[-1]['height'], 'Invalid observed tip')
        self.verifier(raw)
        require(not self.read()['pending'], 'Uncommitted publication remains')
        result = dict(last_checked_at=int(time.time()), feed_sha256=sha(raw), checkpoint_height=records[-1]['height'],
                      signed_at=records[-1]['signed_at'], observed_tip=tip)
        atomic_json(self.state/'publisher-status.json', result)
        return result

    def health(self):
        status = json.loads(read_regular(self.state/'publisher-status.json'))
        raw = read_regular(self.feed)
        self.verifier(raw)
        require(status['feed_sha256'] == sha(raw), 'Checkpoint feed and publisher status disagree')
        require(0 <= time.time()-status['last_checked_at'] <= 3*3600, 'Protected checkpoint publisher has not checked in for three hours')
        require(not self.read()['pending'], 'Checkpoint publication is awaiting commit')
        return dict(healthy=True, **status)


def main():
    import fcntl
    config = json.loads(Path('/etc/veld/checkpoint-publisher.json').read_bytes())
    store = Store(config)
    with (store.state/'publisher.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        command = sys.argv[1]
        request = {} if command in ('read','health') else json.loads(sys.stdin.buffer.read(2*MAX_BYTES+1))
        if command == 'read': result = store.read()
        elif command == 'install': result = store.install(request)
        elif command in ('commit','rollback'): result = store.finish(request['transaction'], command=='commit')
        elif command == 'checked': result = store.checked(request['tip'])
        elif command == 'health': result = store.health()
        else: raise ValueError('Unknown checkpoint publication operation')
        print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Checkpoint publication failed: '+str(error), file=sys.stderr)
        raise SystemExit(1)
