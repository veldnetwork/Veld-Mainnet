"""Exercise the real public transport against retained, authenticated forks."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile


def sha(p):
    with p.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main(a):
    os.umask(0o077)
    assert a.root.parent == Path('/var/tmp') and a.root.name.startswith('veld-native-public-p2p-')
    a.root.mkdir(exist_ok=False)
    report = dict(status='PREPARING', started_at=datetime.now(timezone.utc).isoformat(),
                  commands=[], inputs={}, real_funds=False, public_network_connected=False)
    def save():
        (a.root/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    def pin(p):
        report['inputs'][str(p)] = sha(p)
    def run(label, command, timeout=5400):
        command = list(map(str, command))
        row = dict(label=label, argv=command)
        report['commands'].append(row); save(); print('START '+label, flush=True)
        with (a.root/(label+'.log')).open('xb') as log:
            p = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                 start_new_session=True)
            row['pid'] = p.pid; save()
            try:
                row['exit'] = p.wait(timeout)
            except BaseException:
                os.killpg(p.pid, 15)
                try: p.wait(20)
                except subprocess.TimeoutExpired: os.killpg(p.pid, 9); p.wait()
                raise
        row['log_sha256'] = sha(a.root/(label+'.log')); save()
        assert row['exit'] == 0, label+' failed'
        print('PASS '+label, flush=True)
    try:
        prior = Path('/var/tmp/veld-native-snapshot-forward-20261013-r2')
        receipt = a.current/'artifacts/public-snapshot-forward-20261013-r2/completion.json'
        assert sha(receipt) == 'd65911c5eca640207b2b9d4624dea5189e5b46fdd138e6dfedd5792d43d0a498'
        pin(receipt)
        assert sha(prior/'result.json') == '87b22ea3d36ef09c84bbe41a8f42b2ba1e32e68199fe59acc52bced55bc54ce5'
        full = json.loads((prior/'result.json').read_bytes()); pin(prior/'result.json')
        assert full['status'] == 'PASS_PUBLIC_SNAPSHOT_FORWARD_RESTART_AND_FULL_VALIDATION'
        for row in full['commands']:
            assert row['exit'] == 0 and sha(prior/(row['label']+'.log')) == row['log_sha256']
            pin(prior/(row['label']+'.log'))
        # Check every previously qualified core input against the present source.
        for name, digest in full['source_inputs'].items():
            assert sha(a.current/name) == digest, 'Changed public dependency: '+name
        source=a.root/'source'; source.mkdir()
        for folder in ('include','vendor/pqc'):
            shutil.copytree(a.current/folder,source/folder)
        shutil.copyfile(a.current/'tests/appchain_public_p2p_reorg.cpp',source/'fixture.cpp')
        for p in source.rglob('*'):
            if p.is_file(): pin(p)
        pin(Path(__file__))
        # Closed, fully qualified chain copy. Snapshot replay checks its exact
        # prior tip/state digest; no PoW model or mainnet test bypass is compiled.
        base=prior/'scratch/pending'
        for p in base.rglob('*'):
            if p.is_file(): pin(p)
        shutil.copytree(base,a.root/'data')
        inventory=Path('/var/tmp/veld-native-public-fork-inventory-20261013-r2')
        inv=json.loads((inventory/'result.json').read_bytes())
        assert inv['status']=='PASS_AUTHENTICATED_BODY_INVENTORY'
        pin(inventory/'result.json')
        stage=Path('/var/tmp/veld-native-snapshot-acquire-data-20261013-r1/client/.snapshot-stage-03072d6971417bbe301eee781a4e04b6')
        archive=stage/'veld-chain-snapshot-h19612-a38c860d895fb302.tar.gz'
        assert sha(archive)=='a38c860d895fb3026ed5bf9bc35790ac461fb36c81da6586c907c088552928e7'
        pin(archive)
        native=Path('/var/tmp/veld-native-public-20261012-r1/linux-node/bin/veld-node')
        assert sha(native)=='fd29b4b40d45ea18787f0cce64fc2c4f8ff11d7f11685d38f8c75a4887f051c6'
        pin(native)
        for p in (stage/'veld-chain-snapshot.manifest',stage/'veld-chain-snapshot.manifest.sig'):
            pin(p);shutil.copyfile(p,a.root/p.name)
        run('verify-snapshot',['unshare','-Urn',native,'--verify-snapshot',a.root/'veld-chain-snapshot.manifest',a.root/'veld-chain-snapshot.manifest.sig'],120)
        assert 'RELEASE-SIGNATURE-VALID' in (a.root/'verify-snapshot.log').read_text()
        fields=dict(line.split('=',1) for line in (stage/'veld-chain-snapshot.manifest').read_text().splitlines())
        assert fields['sha256']==sha(archive) and fields['height']=='19612'
        names=set()
        with tarfile.open(archive) as tar:
            for m in tar:
                parts=Path(m.name).parts
                assert not Path(m.name).is_absolute() and '..' not in parts and m.name not in names
                names.add(m.name)
                assert parts[0]=='db' and (len(parts)==1 or parts[1] in ('blocks','index','utxo'))
                target=a.root/'donor'/m.name
                if m.isdir(): target.mkdir(parents=True,exist_ok=True)
                else:
                    assert m.isfile() and len(parts)==3
                    target.parent.mkdir(parents=True,exist_ok=True)
                    with tar.extractfile(m) as src,target.open('xb') as out: shutil.copyfileobj(src,out)
        orphan=inventory/'side-bodies/ada6eb556e12d3d569b48b03ca95acba5f679a428ac8fb56861642d65f87897c.block'
        assert sha(orphan)=='1720e061f595cb2f779a5282667dde4b6f2d9659f71ac7c6cf65acfda09b01ca'
        pin(orphan);shutil.copyfile(orphan,a.root/'orphan.block')
        (a.root/'.qualification-only').write_text('public-p2p-reorg\n')
        # Canonical block 19561 was independently validated by the retained run.
        # Obtain its hash from the closed DB inside the fixture, using the
        # already checked snapshot-forward finish log's recorded expected tip.
        # The fixture reads its current DB tip and binds height and digest; the
        # tip is extracted using the retained fork inventory's canonical index.
        export_source=source/'tip.cpp'
        export_source.write_text('#include <leveldb/db.h>\n#include <iostream>\nint main(int n,char**v){leveldb::DB*d=nullptr;leveldb::Options o;auto s=leveldb::DB::Open(o,v[1],&d);if(!s.ok())return 1;std::string h;s=d->Get({},"idx:height:19561",&h);delete d;if(!s.ok()||h.size()!=64)return 2;std::cout<<h;}\n')
        pin(export_source)
        run('compile-tip',['g++',export_source,'-lleveldb','-o',a.root/'tip'],120)
        with (a.root/'base-tip').open('xb') as out:
            subprocess.run([a.root/'tip',a.root/'donor/db/index'],stdout=out,check=True,timeout=30)
        digest=(prior/'scratch/expected-tip-digest').read_text()
        assert digest=='a6bd23cc098d7a16a1f673b825aaa2a49fbae54946efb88ab3b9390043d7e219'
        (a.root/'base-digest').write_text(digest)
        objects=sorted(Path('/var/tmp/veld-native-public-20261012-r1/linux-node/obj').glob('*.o'))
        assert len(objects)==11
        for p in objects: pin(p)
        binary=a.root/'fixture'
        run('compile',['g++','-std=c++20','-O1','-DNDEBUG','-pthread','-DVELD_MAINNET_POW',
            '-DVELD_PUBLIC_RELEASE','-DVELD_PUBLIC_MAINNET','-DVELD_USE_LEVELDB','-DVELD_ENABLE_SNAPSHOT_BOOTSTRAP',
            '-I'+str(source/'include'),'-I'+str(source/'vendor/pqc'),'-I'+str(source/'vendor/pqc/mldsa65'),
            source/'fixture.cpp',*objects,'-lssl','-lcrypto','-lleveldb','-o',binary],1800)
        report['binary_sha256']=sha(binary); save()
        for mode in ('network','restart'):
            run(mode,['unshare','-Urn','python3','-c',
                'import json,subprocess,os,sys; assert [x["ifname"] for x in json.loads(subprocess.check_output(["ip","-json","link"]))]==["lo"]; subprocess.run(["ip","link","set","lo","up"],check=True); assert json.loads(subprocess.check_output(["ip","-json","route"]))==[]; os.execv(sys.argv[1],sys.argv[1:])',binary,mode,a.root])
            assert 'PASS_PUBLIC_P2P_REORG mode='+mode in (a.root/(mode+'.log')).read_text()
        for path,digest in report['inputs'].items(): assert sha(Path(path))==digest,path
        report.update(status='PASS_PUBLIC_P2P_HISTORICAL_REORG_AND_COLD_REPLAY',
            tip=(a.root/'final-tip').read_text(),state_digest=(a.root/'final-digest').read_text(),
            prior_full_validation_reused=True,new_peer_blocks_real_pow=True,all_owned_processes_stopped=True,
            limitations=['One historical one-block fork through actual public-profile TCP on isolated loopback.',
                        'Previously qualified historical PoW prefix reused; no full daemon, client installer or public bridge activation claim.'])
    except BaseException as error:
        report.update(status='FAILED',error=repr(error)); raise
    finally:
        report['finished_at']=datetime.now(timezone.utc).isoformat(); save()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--current',type=Path,required=True)
    main(p.parse_args())
