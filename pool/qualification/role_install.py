"""Clean Linux installation with real, separate process credentials.

Run as root in the disposable Linux environment. The optional systemd exercise
uses temporary DynamicUser identities and transient units; no persistent users
or enabled services are created. All nodes use a loopback-only network namespace.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from ..backend import Node
from ..node_service import deployment
from ..native import Native
from ..protocol import encode,Busy
from .isolation import MARKER,require_isolated_network

def identity_lease_seconds(maturity_timeout):
    if type(maturity_timeout) is not int or not 3600 <= maturity_timeout <= 43200:
        raise ValueError('maturity deadline must be between one and twelve hours')
    # Cover the full bounded maturity exercise, both short upgrade phases,
    # startup and teardown. A fixed four-hour NSS lease expired mid-exercise.
    return maturity_timeout + 2 * 900 + 7200

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--build-directory',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--systemd',action='store_true',help='execute packaged sandbox settings in uniquely named transient test units')
    parser.add_argument('--maturity-timeout',type=int,default=21600,
                        help='bounded real-clock mining and payout deadline, 3600..43200 seconds')
    args=parser.parse_args()
    if not 3600<=args.maturity_timeout<=43200:raise ValueError('maturity deadline must be between one and twelve hours')
    if os.geteuid()!=0:raise PermissionError('root is required to exercise distinct service UIDs')
    if not os.environ.get(MARKER):
        env=dict(os.environ);env[MARKER]=os.readlink('/proc/self/ns/net')
        raise SystemExit(subprocess.call(['unshare','-n',sys.executable,'-m','pool.qualification.role_install',*sys.argv[1:]],env=env))
    require_isolated_network();subprocess.run(['ip','link','set','lo','up'],check=True)
    source=Path(__file__).resolve().parents[2];build=args.build_directory.resolve();out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    core,gateway,worker_uid=61001,61002,61003
    for uid in (core,gateway,worker_uid):
        try:pwd.getpwuid(uid)
        except KeyError:pass
        else:raise RuntimeError('test UID already belongs to a system user')
    # PrivateTmp intentionally hides /var/tmp from each service. The actual
    # sandbox exercise therefore stages beneath a new /var/lib test root.
    # No existing service, account, datadir or configuration is changed.
    root=Path(tempfile.mkdtemp(prefix='veld-pool-install-',dir='/var/lib' if args.systemd else '/var/tmp'));root.chmod(0o755)
    (out/'state-directory.txt').write_text(str(root)+'\n')
    def module(name):
        spec=importlib.util.spec_from_file_location('pool_setup_'+name,source/'pkg/pool'/(name+'.py'))
        value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
    installer,configure,provision=(module(n) for n in ('install','configure','provision'))
    package=root/'package';package.mkdir()
    for name in ('bin','lib/pool','setup','third-party'):(package/name).mkdir(parents=True,exist_ok=True)
    for name in ('work','client','identity','payout'):
        shutil.copy2(build/('pool-'+name),package/'bin'/('veld-pool-'+name))
    shutil.copy2(build/'veld-node',package/'bin/veld-node')
    for file in (source/'pool').glob('*.py'):
        if not file.name.startswith('test_'):shutil.copy2(file,package/'lib/pool'/file.name)
    shutil.copytree(source/'pool/web',package/'lib/pool/web')
    shutil.copytree(source/'pool/admin_web',package/'lib/pool/admin_web')
    shutil.copytree(source/'pkg/pool',package/'setup',dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__'))
    # Preserve actual attribution in this test staging artifact. This is not
    # the final distribution dependency/license inventory.
    licenses=[p for p in (source/'vendor/pqc').rglob('*') if p.is_file() and p.name in ('LICENSE','LICENSE.txt','COPYING')]
    for index,file in enumerate(licenses):shutil.copy2(file,package/'third-party'/f'{index}-{file.name}')
    (package/'third-party/QUALIFICATION.txt').write_text('Isolated native installation exercise; not a release artifact.\n')
    (package/'pool-sha256.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(package).as_posix()+'\n'
        for p in sorted(package.rglob('*')) if p.is_file()))
    identity=deployment(str(build/'veld-node'));assert identity['disposable'] and not identity['external_value']
    genesis=bytes.fromhex(identity['genesis_fingerprint'])[::-1].hex()
    keys=subprocess.run([str(build/'pool-lab-keys'),str(root/'keys')],capture_output=True,text=True,check=True)
    addresses={line.split()[0]:line.split()[1] for line in keys.stdout.splitlines()}
    scripts={line.split()[0]:line.split()[2] for line in keys.stdout.splitlines()}
    config_root,state=root/'config',root/'state';config_root.mkdir(mode=0o700)
    private=config_root/'private';private.mkdir(mode=0o700)
    for name in ('pool','fees'):shutil.copy2(root/'keys'/(name+'.seed'),private/(name+'.seed'))
    (private/'backend.passphrase').write_text(secrets.token_hex(32)+'\n');(private/'backend.passphrase').chmod(0o600)
    tls=config_root/'tls';tls.mkdir(mode=0o700)
    with (out/'certificate.log').open('w') as log:
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(tls/'private-key.pem'),
            '-out',str(tls/'certificate.pem'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],
            stdout=log,stderr=subprocess.STDOUT,check=True)
    report=dict(status='RUNNING',scope='native Linux role separation, clean staging and side-by-side restart',
                complete_pool_gate=False,real_system_users_created=False,systemd_units_activated=args.systemd,
                persistent_services_installed=False,checks=[])
    processes=[];logs=[]
    unit_prefix='veld-pool-lab-'+secrets.token_hex(6)
    report['transient_unit_prefix']=unit_prefix if args.systemd else None
    units=[]
    def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    def check(name,value):
        assert value,name
        report['checks'].append(name);save();print(name,flush=True)
    def start(name,command,uid=0,cwd=source,stdin=False):
        role=name.split('-v',1)[0]
        if args.systemd and role in ('backend','coordinator','gateway'):
            # Use the installer-produced service restrictions unchanged. Only
            # the test UID names, unique dependency names and private namespace
            # are substituted; the ExecStart comes from this installed version.
            unit=unit_prefix+'-'+name+'.service';text=installer.unit(role,cwd.parent,config_root,state,str(core),str(gateway))
            for other in ('backend','coordinator','gateway'):
                text=text.replace('veld-pool-'+other+'.service',unit_prefix+'-'+other+'-v'+name.rsplit('v',1)[1]+'.service')
            properties=[];section=''
            for line in text.splitlines():
                if line.startswith('['):section=line
                elif line and not line.startswith('#') and '=' in line:
                    key=line.split('=',1)[0]
                    if section=='[Service]' and key not in ('Type','ExecStart'):
                        properties.append('--property='+line)
                    elif section=='[Unit]' and key in ('After','Requires','StartLimitIntervalSec','StartLimitBurst'):
                        properties.append('--property='+line)
            properties.append('--property=NetworkNamespacePath=/proc/'+str(os.getpid())+'/ns/net')
            log=(out/(name+'.log')).open('w');logs.append(log)
            units.append(unit)
            subprocess.run(['systemd-run','--quiet','--collect','--service-type=exec','--unit='+unit,*properties,
                '/usr/bin/python3','-m','pool.'+{'backend':'node_service','coordinator':'service','gateway':'gateway'}[role],
                '--config',str(config_root/(role+'.json'))],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=180)
            p=UnitProcess(unit,log);processes.append(p);return p
        log=(out/(name+'.log')).open('w');logs.append(log)
        env=dict(os.environ);env.update(PYTHONPATH=str(cwd),PYTHONDONTWRITEBYTECODE='1')
        p=subprocess.Popen(command,cwd=cwd,env=env,user=uid,group=uid,
            extra_groups=[gateway] if uid==core else [],umask=0o077,
            stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,text=True)
        processes.append(p);return p
    class UnitProcess:
        stdin=None
        def __init__(self,unit,log):self.unit,self.log,self.returncode=unit,log,None
        def poll(self):
            result=subprocess.run(['systemctl','show',self.unit,'--property=ActiveState','--property=ExecMainStatus'],
                                  capture_output=True,text=True,timeout=20)
            values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
            if values.get('ActiveState') in ('active','activating','reloading','deactivating'):return None
            self.returncode=int(values.get('ExecMainStatus','1' if result.returncode else '0'));return self.returncode
        def terminate(self):
            subprocess.run(['systemctl','stop',self.unit],capture_output=True,check=True,timeout=180)
        def kill(self):
            subprocess.run(['systemctl','kill','--kill-whom=all',self.unit],capture_output=True,timeout=30)
        def wait(self,timeout):
            until=time.monotonic()+timeout
            while self.poll() is None:
                if time.monotonic()>until:raise subprocess.TimeoutExpired(self.unit,timeout)
                time.sleep(.2)
            return self.returncode
    def stop(p):
        if p.poll() is not None:return
        if p.stdin:p.stdin.write('stop\n');p.stdin.flush()
        else:p.terminate()
        try:p.wait(timeout=150)
        except subprocess.TimeoutExpired:p.kill();p.wait()
    def ready(rpc,p):
        until=time.monotonic()+300
        while time.monotonic()<until:
            assert p.poll() is None,'service exited before readiness'
            try:rpc.check_chain();return
            except (OSError,ValueError,Busy):time.sleep(.2)
        raise RuntimeError('native service startup deadline')
    try:
        if args.systemd:
            # systemd requires NSS-resolvable credentials, even for numeric
            # User= values. Short-lived DynamicUser leases provide them without
            # adding host passwd/group entries or reusing a real user's UID.
            allocated=[]
            for role in ('core','gateway'):
                name='vpl-'+unit_prefix.rsplit('-',1)[1]+'-'+role
                unit=unit_prefix+'-'+role+'-identity.service';units.append(unit)
                assert len(name)<=31,'bounded Linux service account name'
                subprocess.run(['systemd-run','--quiet','--collect','--service-type=exec','--unit='+unit,
                    '--property=DynamicUser=yes','--property=User='+name,
                    '--property=NetworkNamespacePath=/proc/'+str(os.getpid())+'/ns/net',
                    '--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=',
                    '/usr/bin/sleep',str(identity_lease_seconds(args.maturity_timeout))],capture_output=True,check=True,timeout=30)
                account=pwd.getpwnam(name);allocated.append(account.pw_uid)
            core,gateway=allocated
            check('temporary systemd identities are distinct and non-root',0 not in allocated and len(set(allocated))==2)
            report['temporary_systemd_uids']=allocated
        observer=start('observer',[str(build/'pool-backend'),str(root/'observer'),'32111','32112'],stdin=True)
        independent=Node('http://127.0.0.1:32112',root/'observer/lab-rpc-token',genesis);ready(independent,observer)
        prior_account=None;prior_paid=0
        for version in (1,2,3):
            prefix=root/('installed-v'+str(version));installer.stage(package,prefix,config_root,state,'veld-test-core','veld-test-gateway')
            values=dict(prefix=str(prefix),state=str(state),config=str(config_root),genesis=genesis,
                profile=identity['profile_id'],runtime_network='regtest',peer='127.0.0.1:32111',listen='127.0.0.1',
                p2p_port=32101,rpc_port=32102,tls_port=32143,pool_address=addresses['pool'],pool_script=scripts['pool'],
                fee_address=addresses['fees'],fee_script=scripts['fees'])
            configs=configure.render(values);configs['backend']['enabled']=True
            for name,value in configs.items():
                path=config_root/(name+'.json');path.write_bytes(encode(value));path.chmod(0o600)
            provision.layout(config_root,state,core,core,gateway,gateway)
            backend=start('backend-v'+str(version),[sys.executable,'-m','pool.node_service','--config',str(config_root/'backend.json')],core,prefix/'lib')
            rpc=Node('http://127.0.0.1:32102',state/'rpc/token',genesis);ready(rpc,backend)
            if version==1:
                # A separately mined operator coin supplies fees; no worker
                # liability or pool receipt is diverted to operating costs.
                with (out/'operator-fee-work.log').open('w') as log:
                    verifier=Native(prefix/'bin/veld-pool-work',log)
                    try:
                        candidate=rpc.template(addresses['fees']);header=bytearray.fromhex(candidate['block_hex'])[:88]
                        for nonce in range(4096):
                            header[80:88]=nonce.to_bytes(8,'little');proof,_=verifier.hash(bytes(header),candidate['height'])
                            if int(proof,16)<int(candidate['target'],16):
                                check('operator fee float uses a separately earned canonical output',rpc.submit(candidate,nonce)['accepted']);break
                        else:raise RuntimeError('native operator fee funding deadline')
                    finally:verifier.close()
            coordinator=start('coordinator-v'+str(version),[sys.executable,'-m','pool.service','--config',str(config_root/'coordinator.json')],core,prefix/'lib')
            until=time.monotonic()+120
            while not (state/'ipc/coordinator.sock').exists():
                assert coordinator.poll() is None,'coordinator exited'
                if time.monotonic()>until:raise RuntimeError('owned IPC startup deadline')
                time.sleep(.1)
            info=(state/'ipc/coordinator.sock').stat()
            check('v'+str(version)+' IPC owner/group/mode enforce role access',info.st_uid==core and info.st_gid==gateway and info.st_mode&0o777==0o660)
            public=start('gateway-v'+str(version),[sys.executable,'-m','pool.gateway','--config',str(config_root/'gateway.json')],gateway,prefix/'lib')
            # Ask the OS, not a mocked permission predicate, whether the gateway
            # can open private core files. Never print any credential contents.
            denied=[state/'rpc/token',private/'pool.seed',private/'fees.seed',config_root/'coordinator.json']
            check_program='import sys\nfor p in sys.argv[1:]:\n try:\n  f=open(p,"rb");f.close();raise SystemExit(2)\n except PermissionError:pass\n'
            check('v'+str(version)+' gateway cannot read RPC or signing authority',subprocess.run(
                [sys.executable,'-c',check_program,*map(str,denied)],user=gateway,group=gateway,extra_groups=[],capture_output=True).returncode==0)
            worker_root=root/'worker';worker_root.mkdir(exist_ok=True,mode=0o700);os.chown(worker_root,worker_uid,worker_uid)
            shutil.copy2(tls/'certificate.pem',worker_root/'ca.pem');os.chown(worker_root/'ca.pem',worker_uid,worker_uid)
            worker_config=worker_root/'config.json';worker_config.write_bytes(encode(dict(endpoint='https://localhost:32143',
                ca_file=str(worker_root/'ca.pem'),genesis=genesis,payout_address=addresses['worker-a'],
                state_directory=str(worker_root/'account'),threads='1',nonce_count='8',pause_ms='0')))
            os.chown(worker_config,worker_uid,worker_uid);worker_config.chmod(0o600)
            # This is an explicit new Start, matching PoolPanel::Start. A Stop
            # request deliberately survives process exit and must not turn
            # into an unsolicited auto-resume. No account or ledger is reset.
            (worker_root/'account/stop.request').unlink(missing_ok=True)
            first=rpc.call('getblockcount');worker=start('worker-v'+str(version),[str(prefix/'bin/veld-pool-client'),'--config',str(worker_config)],worker_uid,prefix/'lib')
            # The canonical CLI follows its real clock and unchanged ASERT
            # difficulty. A one-hour cap is shorter than even 120 target
            # intervals. Never lower difficulty or maturity to fit that cap.
            until=time.monotonic()+(args.maturity_timeout if version==2 else 900)
            next_progress=time.monotonic()
            while True:
                assert all(p.poll() is None for p in (backend,coordinator,public,worker)),'installed service exited'
                height=rpc.call('getblockcount');status_path=worker_root/'account/pool-status.json'
                try:current=json.loads(status_path.read_text())
                except (OSError,json.JSONDecodeError):current={}
                if height>=first+(124 if version==2 else 2) and (version!=2 or int(current.get('paid_units','0'))>0):break
                if time.monotonic()>until:raise RuntimeError('installed native worker deadline')
                if time.monotonic()>=next_progress:
                    print('installed worker v'+str(version)+' height',height,flush=True);next_progress=time.monotonic()+30
                time.sleep(.2)
            (worker_root/'account/stop.request').write_text('stop\n');worker.wait(timeout=60)
            status=json.loads((worker_root/'account/pool-status.json').read_text())
            check('v'+str(version)+' installed worker mined accepted native blocks',int(status['accepted'])>0)
            if prior_account:check('upgrade preserved worker account and earned balances',status['account']==prior_account)
            prior_account=status['account'];tip=rpc.call('getbestblockhash');until=time.monotonic()+180
            while independent.call('getbestblockhash')!=tip:
                if time.monotonic()>until:raise RuntimeError('independent installed-block validation deadline')
                time.sleep(.2)
            check('v'+str(version)+' independently validated installed service state',independent.call('getstatedigest')==rpc.call('getstatedigest'))
            if version>=2:
                amount=int(status['paid_units'])
                actual=sum(c['value_units'] for c in rpc.call('listunspent',addresses['worker-a']))
                external=sum(c['value_units'] for c in independent.call('listunspent',addresses['worker-a']))
                check('v'+str(version)+' installed signer paid exactly the recorded mature liability',amount>0 and actual==external==amount)
                if version==3:check('post-payment upgrade did not repeat the economic payment',amount==prior_paid)
                prior_paid=amount;report['recipient_wallet_units']=actual;report['independent_wallet_units']=external
            stop(public);stop(coordinator);stop(backend)
            check('v'+str(version)+' ordered shutdown removed API capabilities',not (state/'rpc/token').exists() and not (state/'ipc/coordinator.sock').exists())
        report.update(status='PASS',height=independent.call('getblockcount'),account_preserved=True,
            limitations=([] if args.systemd else ['systemd sandbox directives are staged but not activated in this namespace'])+
                         ['final release provenance and packaging remain separate'])
    except BaseException as error:
        report.update(status='FAILED',error=repr(error));(out/'failure.txt').write_text(traceback.format_exc());raise
    finally:
        for p in reversed(processes):stop(p)
        for unit in reversed(units):
            # Retrieve only this run's units, including startup failures. No
            # unrelated host logs or service state are inspected or altered.
            with (out/(unit+'.journal.log')).open('w') as log:
                subprocess.run(['journalctl','--unit='+unit,'--no-pager','--output=cat'],stdout=log,stderr=subprocess.STDOUT,timeout=30)
            subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=180)
        report['transient_units']=units
        for log in logs:log.close()
        report['processes_stopped']=all(p.poll() is not None for p in processes)
        report['package_manifest_sha256']=hashlib.sha256((package/'pool-sha256.txt').read_bytes()).hexdigest();save()

if __name__=='__main__':main()
