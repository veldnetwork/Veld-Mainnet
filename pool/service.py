"""Private coordinator IPC. Only the fixed worker API is exposed to gateway UID."""
import argparse
from pathlib import Path
import os
import socketserver
import threading
import signal
import sys
import subprocess
import time
import socket
import stat
import errno
import struct

from .backend import Node, NodeRefused
from .coordinator import Coordinator
from .journal import Journal
from .native import Native
from .payments import Payments
from .rewards import Rewards
from .identity import Identity
from .protocol import decode, encode, schema, require, units, Busy, Refused
from .private_file import read_private
from .operator import Operator

def prepare_socket(path):
    """Recover a dead socket only while holding the exclusive journal lock."""
    path=Path(path)
    parent=path.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.geteuid() and
            parent.st_mode & 0o022==0, 'unsafe IPC parent directory')
    try:metadata=path.lstat()
    except FileNotFoundError:return
    require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid==os.geteuid(),
            'IPC path is not an owned socket')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        try:probe.connect(str(path))
        except OSError as error:
            require(error.errno==errno.ECONNREFUSED,'cannot establish stale IPC state')
        else:raise Refused('IPC listener is still active')
    current=path.lstat()
    require((current.st_dev,current.st_ino)==(metadata.st_dev,metadata.st_ino),
            'IPC path changed during recovery')
    path.unlink()

def dispatch(pool, request):
    schema(request, ('action','payload'))
    value=request['payload']; action=request['action']
    if action=='health':
        schema(value,());return pool.health()
    if action=='register':
        schema(value,('address',));return pool.register(value['address'])
    if action=='work':
        schema(value,('account','token','count'))
        return pool.work(value['account'],value['token'],units(value['count'],4096))
    if action=='submit':
        schema(value,('account','token','lease','nonce'))
        return pool.submit(value['account'],value['token'],value['lease'],value['nonce'])
    if action=='account':
        schema(value,('account','token'))
        return pool.account(value['account'],value['token'])
    if action=='history':
        schema(value,('account','token','before'))
        return pool.history(value['account'],value['token'],units(value['before'],(1<<63)-1))
    raise Refused('unsupported action')

class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads=False
    def __init__(self,path,pool,operator_uid=None):
        self.pool=pool;self.operator_uid=operator_uid;self.slots=threading.BoundedSemaphore(16 if operator_uid is None else 4)
        self.notice_lock=threading.Lock();self.last_refusal_notice=None
        super().__init__(path,Handler)
        os.chmod(path,0o660)
    def refusal_notice(self,action,error):
        # One global budget prevents anonymous requests or varying refusal
        # reasons from growing memory or flooding operator logs. The public
        # response remains generic and carries no backend authority details.
        action=action if action in ('health','register','work','submit','account','history') else 'other'
        reason=error.diagnostic if isinstance(error,NodeRefused) else 'request_validation_failed'
        with self.notice_lock:
            now=time.monotonic()
            if self.last_refusal_notice is not None and now-self.last_refusal_notice<30:return
            self.last_refusal_notice=now
        print('pool request refused action='+action+' reason='+reason,file=sys.stderr,flush=True)
    def process_request(self,request,address):
        if not self.slots.acquire(False):request.close();return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(15)
        action=None
        try:
            if self.server.operator_uid is not None:
                _,uid,_=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                require(uid==self.server.operator_uid,'operator process identity')
            raw=self.rfile.readline(16385)
            require(raw.endswith(b'\n'),'IPC framing')
            request=decode(raw)
            action=request.get('action')
            if self.server.operator_uid is None:result=dispatch(self.server.pool,request)
            else:
                schema(request,('action','payload','actor'))
                operator=self.server.pool.operator;require(operator is not None,'operator controls unavailable')
                if request['action']=='snapshot':
                    schema(request['payload'],('before',))
                    result=operator.snapshot(units(request['payload']['before'],(1<<63)-1))
                else:result=operator.execute(request['action'],request['payload'],request['actor'])
            response={'ok':True,'result':result}
        except Busy:
            response={'ok':False,'error':'busy','retryable':True}
        except (Refused,ValueError) as error:
            self.server.refusal_notice(action,error)
            response={'ok':False,'error':str(error)[:180] if self.server.operator_uid is not None else 'request refused','retryable':False}
        except (OSError,RuntimeError):
            response={'ok':False,'error':'service temporarily unavailable','retryable':True}
        try:self.wfile.write(encode(response)+b'\n')
        except (BrokenPipeError,ConnectionResetError,TimeoutError):pass

def maintain_once(pool,node,stop):
    deferred=[]
    def step(stage,action):
        try:action();return True
        except (OSError,RuntimeError,ValueError) as error:
            deferred.append(stage)
            detail=str(error)[:200] if isinstance(error,(Refused,Busy)) else type(error).__name__
            notices=getattr(pool,'maintenance_notices',{});prior=notices.get(stage)
            if prior is None or prior[0]!=detail or time.monotonic()-prior[1]>=30:
                print(stage+' deferred: '+detail+'; existing reservations retained',file=sys.stderr,flush=True)
                notices[stage]=(detail,time.monotonic());pool.maintenance_notices=notices
            return False
    if not step('chain identity',node.check_chain):
        pool.deferred_phases=deferred;return
    step('deferred work',pool.retry_deferred)
    step('block reconciliation',pool.reconcile_solutions)
    def rewards():
        with pool.lock:pool.rewards.reconcile()
    step('reward reconciliation',rewards)
    # A rebuilding secondary reward index cannot block already validated miner
    # receipts. Canonical income reconciliation IS a prerequisite for signing.
    safe=step('income reconciliation',pool.reconcile_income)
    if pool.identity or pool.payments:
        # Loss of the index after startup must pause all funds-bearing work,
        # while shares and independently checked income still reconcile.
        safe=step('transaction index readiness',node.require_transaction_index) and safe
    operator=getattr(pool,'operator',None)
    if safe and pool.identity:step('pool identity',lambda:operator.run('comining',pool.identity.maintain) if operator else pool.identity.maintain())
    def payments():
        for identity in list(pool.payments.intents):
            if stop.is_set():return
            pool.payments.sign(identity);pool.payments.reconcile(identity)
        if not stop.is_set():
            identity=pool.payments.plan()
            if identity:pool.payments.sign(identity);pool.payments.reconcile(identity)
    if safe and pool.payments:
        if operator and operator.settings['payments_paused']:
            def observe_payments():
                for identity in list(pool.payments.intents):pool.payments.reconcile(identity,broadcast=False)
            step('payment observations',observe_payments)
        else:step('payment reconciliation',lambda:operator.run('payments',payments) if operator else payments())
    if operator:step('operator reconciliation',operator.reconcile)
    if safe:pool.last_healthy=time.monotonic()
    pool.deferred_phases=deferred

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);args=parser.parse_args()
    config=decode(read_private(args.config, 16384))
    fields={'rpc_url','rpc_token_file','genesis','state_directory','rollback_anchor','native_binary','pool_address','accounting_target','socket'}
    require(fields<=set(config) and set(config)<=fields|{'payments','identity','operator'},'coordinator configuration')
    node=Node(config['rpc_url'],config['rpc_token_file'],config['genesis'])
    if 'identity' in config or 'payments' in config:
        node.check_chain()
        node.require_transaction_index()
    journal=Journal(config['state_directory'],config['rollback_anchor'])
    prepare_socket(config['socket'])
    with (Path(config['state_directory'])/'verifier.log').open('a') as log:
        native=Native(config['native_binary'],log)
        pool=Coordinator(node,journal,native,config['pool_address'],config['accounting_target'])
        canonical_policy=node.call('getpoolidentitystate',config['pool_address'])
        pool.rewards=Rewards(pool,canonical_policy['window_blocks'],canonical_policy['yield_blocks'])
        payment_journal=None
        identity_journal=None
        if 'identity' in config:
            settings=config['identity']
            schema(settings,('state_directory','rollback_anchor','native_binary','seed','script','operator_funding_file','tier'))
            funding=decode(read_private(settings['operator_funding_file'],2*1024*1024),2*1024*1024)
            schema(funding,('chain','script','funding'))
            require(funding['chain']==node.genesis and funding['script']==settings['script'],'operator funding chain/identity')
            identity_journal=Journal(settings['state_directory'],settings['rollback_anchor'])
            pool.identity=Identity(pool,identity_journal,settings['native_binary'],settings['seed'],settings['script'],
                                   funding['funding'],settings['tier'])
        if 'payments' in config:
            settings=config['payments']
            schema(settings,('state_directory','rollback_anchor','native_binary','pool_seed','fee_seed','pool_script','fee_script','fee_address','fee_units'))
            payment_journal=Journal(settings['state_directory'],settings['rollback_anchor'])
            policy_run=subprocess.run([settings['native_binary'],'--policy'],capture_output=True,check=True,timeout=10)
            policy=decode(policy_run.stdout)
            schema(policy,('chain','minimum_fee_units','dust_threshold_units'))
            require(policy['chain']==node.genesis and units(settings['fee_units'])==units(policy['minimum_fee_units']),'payout native chain/fee policy')
            pool.payments=Payments(pool,payment_journal,settings['native_binary'],settings['pool_seed'],settings['fee_seed'],
                                   settings['pool_script'],settings['fee_script'],settings['fee_address'],units(settings['fee_units']),units(policy['dust_threshold_units']))
        operator_server=operator_thread=None
        if 'operator' in config:
            settings=config['operator'];schema(settings,('socket','uid','max_fee_ppm'))
            require(type(settings['uid']) is int and settings['uid']>0 and settings['uid']!=os.geteuid(),'separate non-root operator UID required')
            Operator(pool,units(settings['max_fee_ppm'],100000));prepare_socket(settings['socket'])
            operator_server=Server(settings['socket'],pool,settings['uid'])
            operator_thread=threading.Thread(target=operator_server.serve_forever,kwargs={'poll_interval':.25},daemon=True)
            operator_thread.start()
        else:
            require(not any(e['kind'].startswith('operator_') for e in journal.events()),
                    'recorded operator policy requires the operator service configuration')
        stop=threading.Event()
        def maintain():
            while not stop.wait(1):
                maintain_once(pool,node,stop)
        maintenance=threading.Thread(target=maintain,daemon=True);maintenance.start()
        try:
            with Server(config['socket'],pool) as server:
                def shutdown(*_):
                    threading.Thread(target=server.shutdown,daemon=True).start()
                signal.signal(signal.SIGTERM,shutdown)
                signal.signal(signal.SIGINT,shutdown)
                server.serve_forever(poll_interval=.25)
        finally:
            stop.set();maintenance.join()
            if operator_server:
                operator_server.shutdown();operator_thread.join();operator_server.server_close()
                Path(config['operator']['socket']).unlink(missing_ok=True)
            native.close();journal.close()
            if payment_journal:payment_journal.close()
            if identity_journal:identity_journal.close()
            Path(config['socket']).unlink(missing_ok=True)

if __name__=='__main__':main()
