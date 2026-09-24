"""Rebuildable disk projections of the append-first journal.

The journal and independently retained anchor remain authoritative. These tables
do not own nonce leases, money, signatures, or recovery decisions. Rebuilding a
projection from an older database must replay the current complete journal.
"""
from collections.abc import MutableMapping
from .protocol import encode, decode, require
from .journal import MAX_EVENT


class Records(MutableMapping):
    def __init__(self,journal,bucket):
        self.journal,self.bucket=journal,bucket
        with journal.lock:
            journal.db.execute('CREATE TABLE IF NOT EXISTS pool_records('
                'bucket TEXT NOT NULL, key TEXT NOT NULL, seq INTEGER NOT NULL, '
                'height INTEGER NOT NULL, status TEXT NOT NULL, body BLOB NOT NULL, '
                'PRIMARY KEY(bucket,key)) WITHOUT ROWID')
            journal.db.execute('CREATE INDEX IF NOT EXISTS pool_records_sequence ON pool_records(bucket,status,seq)')
            journal.db.execute('CREATE INDEX IF NOT EXISTS pool_records_height ON pool_records(bucket,height,seq)')
            journal.db.execute('DELETE FROM pool_records WHERE bucket=?',(bucket,))

    def __getitem__(self,key):
        with self.journal.lock:
            self.journal.ensure_open()
            row=self.journal.db.execute('SELECT body FROM pool_records WHERE bucket=? AND key=?',(self.bucket,key)).fetchone()
        if row is None:raise KeyError(key)
        return decode(row[0],MAX_EVENT)

    def __setitem__(self,key,value):
        require(isinstance(key,str) and isinstance(value,dict),'record encoding')
        seq=value.get('seq',0);height=value.get('height',0);status=value.get('status',value.get('state',''))
        require(type(seq) is int and type(height) is int and isinstance(status,str),'record index fields')
        body=encode(value);require(len(body)<=MAX_EVENT,'record limit')
        with self.journal.lock:
            self.journal.ensure_open()
            self.journal.db.execute('INSERT INTO pool_records VALUES(?,?,?,?,?,?) '
                'ON CONFLICT(bucket,key) DO UPDATE SET seq=excluded.seq,height=excluded.height,status=excluded.status,body=excluded.body',
                (self.bucket,key,seq,height,status,body))

    def __delitem__(self,key):
        with self.journal.lock:
            self.journal.ensure_open()
            row=self.journal.db.execute('DELETE FROM pool_records WHERE bucket=? AND key=?',(self.bucket,key))
            if not row.rowcount:raise KeyError(key)

    def __len__(self):
        with self.journal.lock:
            self.journal.ensure_open()
            return self.journal.db.execute('SELECT COUNT(*) FROM pool_records WHERE bucket=?',(self.bucket,)).fetchone()[0]

    def __iter__(self):
        with self.journal.lock:
            self.journal.ensure_open()
            cursor=self.journal.db.execute('SELECT key FROM pool_records WHERE bucket=? ORDER BY key',(self.bucket,))
            try:
                for row in cursor:yield row[0]
            finally:cursor.close()

    def values(self):return self.select()

    def select(self,*,status=None,cutoff=None,first=None,last=None,reverse=False,sequence=False):
        sql='SELECT body FROM pool_records WHERE bucket=?';args=[self.bucket]
        for column,operator,value in [('status','=',status),('seq','<=',cutoff),('height','>=',first),('height','<=',last)]:
            if value is not None:sql+=' AND '+column+operator+'?';args.append(value)
        sql+=' ORDER BY '+('seq' if sequence else 'key')+(' DESC' if reverse else ' ASC')
        with self.journal.lock:
            self.journal.ensure_open()
            cursor=self.journal.db.execute(sql,args)
            try:
                for row in cursor:yield decode(row[0],MAX_EVENT)
            finally:cursor.close()
