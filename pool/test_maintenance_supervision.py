"""Disposable projection recovery and complete service-entry failure lifecycle."""
import hashlib,json,os,signal,sqlite3,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from pool.journal import Journal
from pool.records import Records

@unittest.skipUnless(os.name=='posix','Unix IPC service lifecycle')
class MaintenanceSupervision(unittest.TestCase):
    def test_complete_entry_stops_serving_and_closes_resources_on_unexpected_failure(self):
        from pool import service
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'ipc').mkdir(mode=0o700)
            cfg={'rpc_url':'unused','rpc_token_file':'unused','genesis':'a'*64,'state_directory':str(p/'data'),
                 'rollback_anchor':str(p/'anchor/current'),'native_binary':'NO_PROCESS_ALLOWED','pool_address':'pool',
                 'accounting_target':'f'*64,'socket':str(p/'ipc/coordinator.sock')}
            native=SimpleNamespace(close=lambda:None);closed=[];journals=[];original=service.Journal
            def journal(*a):
                j=original(*a);journals.append(j);return j
            native.close=lambda:closed.append('native')
            node=SimpleNamespace(genesis='a'*64,check_chain=lambda:None,call=lambda *a:{'window_blocks':3,'yield_blocks':3})
            handlers={s:signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT)};started=time.monotonic()
            try:
                with patch('sys.argv',['service','--config','unused']),patch.object(service,'read_private',return_value=json.dumps(cfg).encode()),\
                     patch.object(service,'Node',return_value=node),patch.object(service,'Native',return_value=native),\
                     patch.object(service,'Journal',side_effect=journal),\
                     patch.object(service,'maintain_once',side_effect=sqlite3.OperationalError('injected SQLite fault')):
                    with self.assertRaisesRegex(RuntimeError,'maintenance failed'):service.main()
            finally:
                for s,h in handlers.items():signal.signal(s,h)
            self.assertLess(time.monotonic()-started,5);self.assertEqual(closed,['native'])
            self.assertTrue(journals);self.assertTrue(all(j.db is None and j.log is None for j in journals))
            self.assertFalse(Path(cfg['socket']).exists())
            j=original(p/'data',p/'anchor/current');self.assertEqual(j.sequence,0);j.close()

if __name__=='__main__':unittest.main()
