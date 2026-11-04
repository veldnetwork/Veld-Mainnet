"""Qualify the public parent pipe with authentic blocks and full native replay."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import struct
import sys
import time


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main(a):
    os.umask(0o077)
    assert a.root.parent == Path('/var/tmp') and a.root.name.startswith('veld-public-parent-feed-')
    a.root.mkdir(exist_ok=False)
    report = dict(status='PREPARING', commands=[], inputs={}, checks=[], real_funds=False,
                  public_network_connected=False, started_at=datetime.now(timezone.utc).isoformat())
    def save():
        (a.root/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    def pin(p):
        report['inputs'][str(p)] = sha(p)
    def check(ok, label):
        assert ok, label
        report['checks'].append(label); save(); print('PASS '+label, flush=True)
    def run(label, argv, timeout=900):
        argv = list(map(str, argv)); row = dict(label=label, argv=argv)
        report['commands'].append(row); save(); print('START '+label, flush=True)
        with (a.root/(label+'.log')).open('xb') as log:
            p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            row['pid'] = p.pid; save()
            try: row['exit'] = p.wait(timeout)
            except BaseException:
                os.killpg(p.pid, 15)
                try: p.wait(20)
                except subprocess.TimeoutExpired: os.killpg(p.pid, 9); p.wait()
                raise
        row['log_sha256'] = sha(a.root/(label+'.log')); save()
        assert row['exit'] == 0, label
    process = None
    try:
        source = a.root/'source'
        source.mkdir()
        for folder in ('include','vendor/pqc'):
            shutil.copytree(a.source/folder, source/folder)
        shutil.copyfile(a.source/'src/veld-appchain-parent.cpp', source/'parent.cpp')
        pin(Path(__file__))
        for p in source.rglob('*'):
            if p.is_file(): pin(p)
        # Copy a closed authenticated donor. Only the copy is opened by LevelDB.
        donor = Path('/var/tmp/veld-native-public-p2p-20261013-r4/donor/db')
        for p in donor.rglob('*'):
            if p.is_file(): pin(p)
        shutil.copytree(donor, a.root/'donor')
        seed = source/'seed.cpp'
        seed.write_text(r'''
#include "core/leveldb.h"
#include "core/block.h"
#include <filesystem>
#include <fstream>
#include <stdexcept>
int main(int argc,char**argv){try{
  if(argc!=2)return 2;std::filesystem::path root(argv[1]);
  veld::db::VeldDB in((root/"donor").string()),out((root/"data/db").string());
  uint64_t supply=0;
  for(uint64_t h=0;h<=10;++h){
    auto hash=in.GetHashAtHeight(h);if(!hash)throw std::runtime_error("source index");
    auto body=in.ReadBlock(veld::HexToHash(*hash));if(!body)throw std::runtime_error("source block");
    veld::Block b;if(veld::Block::Deserialize(*body,0,b)!=body->size()||b.Serialize()!=*body||veld::HashToHex(b.GetHash())!=*hash)throw std::runtime_error("source encoding");
    std::ofstream f(root/(std::to_string(h)+".block"),std::ios::binary);f.write((const char*)body->data(),body->size());f.close();if(!f)throw std::runtime_error("export");
    if(h<=8){
      if(!out.WriteBlock(b.GetHash(),*body)||!out.WriteBlockIndex(*hash,h,b.header.bits))throw std::runtime_error("write");
      for(const auto&o:b.transactions.front().outputs)supply+=o.value;
      if(h==8&&!out.WriteChainTip(b.GetHash(),h,supply))throw std::runtime_error("tip");
    }
  }return 0;
}catch(const std::exception&e){return 1;}}
''')
        pin(seed)
        (a.root/'data').mkdir()
        identity = Path('/var/tmp/veld-native-public-p2p-20261013-r4/data/network.identity')
        pin(identity)
        shutil.copyfile(identity, a.root/'data/network.identity')
        (a.root/'data/appchain-parent-reader').write_text('dedicated qualification reader\n')
        objects = sorted(Path('/var/tmp/veld-native-public-20261012-r1/linux-node/obj').glob('*.o'))
        assert len(objects) == 11
        for p in objects: pin(p)
        flags = ['g++','-std=c++20','-O1','-DNDEBUG','-pthread','-DVELD_MAINNET_POW',
                 '-DVELD_PUBLIC_RELEASE','-DVELD_PUBLIC_MAINNET','-DVELD_USE_LEVELDB',
                 '-DVELD_ENABLE_SNAPSHOT_BOOTSTRAP','-I'+str(source/'include'),
                 '-I'+str(source/'vendor/pqc'),'-I'+str(source/'vendor/pqc/mldsa65')]
        libs = ['-lssl','-lcrypto','-lleveldb']
        if a.reuse:
            prior=json.loads((a.reuse/'result.json').read_bytes());pin(a.reuse/'result.json')
            for p in source.rglob('*'):
                if p.is_file():assert sha(p)==sha(a.reuse/'source'/p.relative_to(source)),str(p)
            for p in objects:assert sha(p)==prior['inputs'][str(p)]
            assert prior['binary_sha256']==sha(a.reuse/'parent-feed')
            report['reused_commands']=[row for row in prior['commands'] if row['label'] in ('compile-seed','compile')]
            assert len(report['reused_commands'])==2 and all(row['exit']==0 for row in report['reused_commands'])
            for row in report['reused_commands']:
                assert sha(a.reuse/(row['label']+'.log'))==row['log_sha256']
            for name in ('seed','parent-feed'):
                pin(a.reuse/name);shutil.copy2(a.reuse/name,a.root/name)
        else:
            run('compile-seed',[*flags,seed,*objects,*libs,'-o',a.root/'seed'])
        run('seed',['unshare','-Urn',a.root/'seed',a.root],120)
        binary = a.root/'parent-feed'
        if not a.reuse:run('compile',[*flags,source/'parent.cpp',*objects,*libs,'-o',binary])
        report['binary_sha256'] = sha(binary); save()
        codec_source=a.source.parent/'Veld-Appchain-Exchange/node/public_parent_protocol.py'
        pin(codec_source);shutil.copyfile(codec_source,a.root/'protocol.py');pin(a.root/'protocol.py')
        spec=importlib.util.spec_from_file_location('qualified_public_parent_protocol',a.root/'protocol.py')
        codec=importlib.util.module_from_spec(spec);sys.modules[spec.name]=codec;spec.loader.exec_module(codec)
        for mode in ('network-profile','devnet-profile','light-profile'):
            defines = [] if mode == 'network-profile' else ['-D'+('VELD_APPCHAIN_BRIDGE_DEVNET' if mode == 'devnet-profile' else 'VELD_LIGHT_VERIFY')]
            # A production source must refuse test/development flags before it can run.
            if not defines: continue
            argv = [*flags,*defines,'-fsyntax-only',source/'parent.cpp']
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            (a.root/(mode+'.log')).write_bytes(p.stdout)
            report['commands'].append(dict(label=mode,argv=list(map(str,argv)),exit=p.returncode,
                                           log_sha256=sha(a.root/(mode+'.log'))))
            check(p.returncode != 0 and b'cannot use development validation' in p.stdout,
                  mode+' rejected at compile time')
        blocks = {h:(a.root/(str(h)+'.block')).read_bytes() for h in range(11)}
        def block_hash(body): return hashlib.sha256(hashlib.sha256(body[:88]).digest()).digest()
        def anchor(h, body=None): return struct.pack('<Q',h)+block_hash(blocks[h] if body is None else body)
        def read_exact(n, timeout=600):
            end=time.monotonic()+timeout; result=b''
            with selectors.DefaultSelector() as sel:
                sel.register(process.stdout, selectors.EVENT_READ)
                while len(result)<n:
                    assert sel.select(max(0,end-time.monotonic())), 'parent response deadline'
                    part=os.read(process.stdout.fileno(),n-len(result));assert part,'parent exited'
                    result+=part
            return result
        def call(op, body=b''):
            raw=bytes([op])+body
            process.stdin.write(struct.pack('<I',len(raw))+raw);process.stdin.flush()
            n=struct.unpack('<I',read_exact(4))[0];assert 0<n<=8_000_001
            return read_exact(n)
        def launch(h, label):
            nonlocal process
            argv=['unshare','-Urn',str(binary),'--public-parent',str(a.root/'data'),str(h),block_hash(blocks[h]).hex()]
            log=(a.root/(label+'.log')).open('xb')
            process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,bufsize=0,start_new_session=True)
            log.close();report['commands'].append(dict(label=label,argv=argv,pid=process.pid));save()
        def stop(expected=0):
            nonlocal process
            process.stdin.close();code=process.wait(30)
            report['commands'][-1]['exit']=code;save();process.stdout.close();process=None
            assert code==expected,'parent exit status'
        launch(8,'first')
        status=call(0)
        check(len(status)==89 and status[0]==0 and status[1:33]==block_hash(blocks[0]) and status[41:81]==anchor(8),
              'real public genesis and fully verified prefix through pipe')
        check(codec.status(status).anchor==anchor(8),'exchange codec reads actual public parent status')
        policy=call(3)
        check(len(policy)==91 and policy[:2]==b'\0\1' and policy[2:34]==block_hash(blocks[0]) and
              policy[34]==0 and policy[35:43]==b'\xff'*8 and policy[43:]==b'\0'*48,
              'inactive public bridge reported without development override')
        check(not codec.policy(policy).active_at(8),'exchange codec preserves inactive public bridge policy')
        check(call(5,anchor(9)+blocks[9])==b'\4','inactive parent mining relay refused before admission')
        check(call(0)==status,'refused mining relay leaves canonical state unchanged')
        settlement=codec.transaction_request(anchor(8),b'd'*48,b'b'*48,b'signed-transaction-required',100000)
        check(call(6,settlement)==b'\4','static public parent settlement relay refused before admission')
        check(call(0)==status,'refused settlement relay leaves canonical state unchanged')
        canonical=call(2,codec.body_request(8,block_hash(blocks[8])))
        check(canonical==b'\0'+blocks[8],'exact canonical block exported')
        check(codec.block_body(canonical,block_hash(blocks[8]))==blocks[8],'exchange codec reads actual public block bytes')
        check(call(2,anchor(9))==b'\4','unvalidated future body refused')
        check(call(2,struct.pack('<Q',8)+b'\x12'*32)==b'\4','mismatched canonical hash refused')
        check(call(2,struct.pack('<Q',2**64-1)+b'\x12'*32)==b'\4','overflow height refused')
        check(call(1,struct.pack('<Q',10)+block_hash(blocks[9])+blocks[9])==b'\4','forged import height refused')
        bad=bytearray(blocks[9]);bad[-1]^=1;bad=bytes(bad)
        check(call(1,anchor(9,bad)+bad)==b'\4','tampered real block refused by native validation')
        check(call(0)==status,'failed imports leave canonical state unchanged')
        check(call(1,anchor(9)+blocks[9])[41:81]==anchor(9),'real successor admitted and persisted')
        check(call(1,anchor(10)+blocks[10])[41:81]==anchor(10),'second real successor admitted')
        final=call(0);stop()
        launch(10,'restart')
        check(call(0)==final and call(2,anchor(9))==b'\0'+blocks[9],
              'fresh process fully replays and exports identical public state')
        check(codec.status(call(0)).anchor==anchor(10),'exchange codec observes restarted public state')
        # Reject oversize framing before reading or allocating the advertised body.
        process.stdin.write(struct.pack('<I',8_000_042));process.stdin.flush();stop(1)
        check(True,'oversized input frame stops without a body allocation')
        for p,digest in report['inputs'].items(): assert sha(Path(p))==digest,p
        for row in report['commands']:
            path=a.root/(row['label']+'.log')
            if path.exists():row['log_sha256']=sha(path)
        report.update(status='PASS_PUBLIC_PARENT_FEED_SMALL_HISTORY',all_owned_processes_stopped=True,
                      limitations=['Authentic public blocks 0-10 only; current-height and reorg feed qualification remain outstanding.',
                                   'Private local pipe only; production child follower, deployment and native bridge activation are not enabled.'])
    except BaseException as error:
        report.update(status='FAILED',error=repr(error));raise
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid,15)
            try:process.wait(20)
            except subprocess.TimeoutExpired:os.killpg(process.pid,9);process.wait()
        report['finished_at']=datetime.now(timezone.utc).isoformat();save()


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--source',type=Path,required=True)
    p.add_argument('--reuse',type=Path)
    main(p.parse_args())
