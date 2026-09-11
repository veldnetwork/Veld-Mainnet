"""Protected fleet signer and authenticated checkpoint publication controller."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
import base64
import datetime
import fcntl
import json
import os
import subprocess
import sys
import time
import uuid

from policy import append_only, bind_candidate, bind_records, candidate_height, encode, parse, preserves, qualify, require, sha
from remote_store import atomic_json, atomic_write


class Publisher:
    def __init__(self, config):
        self.config = config
        self.state = Path(config['state'])
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])
        self.tool = Path(config['tool'])
        require(sha(self.tool.read_bytes()) == config['tool_sha256'], 'Checkpoint tool identity changed')
        self.run_dir = self.state/('run-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])
        self.run_dir.mkdir(mode=0o700)
        self.counter = 0

    def gateway(self, host, action, **values):
        address = self.config['hosts'][host]
        args = ['/usr/bin/ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','IdentitiesOnly=yes',
                '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+self.config['known_hosts'],
                '-o','ConnectTimeout=12','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3',
                '-i',str(self.credentials/'fleet-ssh-key'), 'veld-checkpoint-peer@'+address]
        response = subprocess.run(args,input=json.dumps(dict(action=action,**values)).encode(),capture_output=True,timeout=100)
        if response.returncode:
            atomic_write(self.run_dir/('gateway-'+host+'-'+action+'-'+str(time.time_ns())+'.log'),response.stderr[:16384])
        require(response.returncode == 0, host+': checkpoint gateway operation failed: '+action)
        require(len(response.stdout) <= 16*1024*1024, 'Gateway response too large')
        return json.loads(response.stdout)

    def observe(self, heights):
        for attempt in range(3):
            with ThreadPoolExecutor(max_workers=3) as pool:
                rows = list(pool.map(lambda host:self.gateway(host,'observe',heights=sorted(set(heights))),self.config['hosts']))
            self.counter += 1
            atomic_json(self.run_dir/('fleet-'+str(self.counter)+'.json'), rows)
            try:
                qualify(rows, heights)
                return rows
            except ValueError:
                if attempt == 2: raise
                time.sleep(2)

    def public_feed(self):
        response = self.gateway(self.config['public_read_host'],'public-feed')
        raw = base64.b64decode(response['document_b64'],validate=True)
        require(sha(raw) == response['sha256'], 'Public feed response hash mismatch')
        parse(raw)
        return raw

    def verify(self, raw, name):
        records = parse(raw)
        path = self.run_dir/(name+'.json')
        atomic_write(path, raw)
        result = subprocess.run([str(self.tool),'verify',str(path),str(len(records))],capture_output=True,timeout=20)
        require(result.returncode == 0 and json.loads(result.stdout)['verified'] == len(records), 'Checkpoint signature validation failed')
        return records

    def sign(self, height, block_hash):
        candidate = self.state/('signed-'+str(height)+'.json')
        if candidate.exists():
            record = self.verify(candidate.read_bytes(),'retained-candidate')[0]
            require(record['height'] == height and record['hash'] == block_hash, 'Previously signed checkpoint conflicts with candidate')
            return record
        password = bytearray((self.credentials/'checkpoint-password').read_bytes())
        require(password and b'\n' not in password and b'\r' not in password, 'Checkpoint credential format rejected')
        password.append(10)
        try:
            result = subprocess.run([str(self.tool),'sign',str(self.credentials/'checkpoint-keystore'),str(height),block_hash],
                                    input=password,capture_output=True,timeout=60)
        finally:
            for i in range(len(password)): password[i] = 0
        require(result.returncode == 0, 'Protected checkpoint signing failed')
        record = json.loads(result.stdout)
        require(record['height'] == height and record['hash'] == block_hash, 'Signer returned a different checkpoint')
        self.verify(encode([record]),'new-record')
        atomic_write(candidate, encode([record]))
        return record

    def finish(self, status, records, rows, **extra):
        tip = qualify(rows)
        self.gateway(self.config['publisher_host'],'checked',tip=tip)
        atomic_write(self.state/'history.json',encode(records))
        result = dict(status=status, checked_at=int(time.time()), checkpoint_height=records[-1]['height'],
                      checkpoint_hash=records[-1]['hash'], observed_tip=tip, checkpoint_count=len(records), **extra)
        atomic_json(self.run_dir/'result.json',result)
        atomic_json(self.state/'last-result.json',result)
        print(json.dumps(result),flush=True)
        return result

    def run(self):
        origin = self.gateway(self.config['publisher_host'],'read')
        raw = self.public_feed()
        if origin['pending'] and sha(raw) != origin['sha256']:
            pending = origin['pending'][0]
            require(sha(raw) == pending['before_sha256'] and origin['sha256'] == pending['after_sha256'], 'Unresolved publication has unexpected public contents')
            self.gateway(self.config['publisher_host'],'rollback',transaction=pending['transaction'])
            origin = self.gateway(self.config['publisher_host'],'read')
            raw = self.public_feed()
        require(sha(raw) == origin['sha256'], 'Origin and public checkpoint feed disagree')
        records = self.verify(raw,'existing-feed')
        require(base64.b64decode(origin['document_b64'],validate=True) == raw, 'Origin response differs from public feed')
        history = self.state/'history.json'
        if history.exists(): preserves(parse(history.read_bytes()), records)
        rows = self.observe([records[-1]['height']])
        bind_records(records[-1:],rows)
        if origin['pending']:
            pending = origin['pending'][0]
            if origin['sha256'] == pending['before_sha256']:
                self.gateway(self.config['publisher_host'],'rollback',transaction=pending['transaction'])
            else:
                require(origin['sha256'] == pending['after_sha256'], 'Unresolved publication does not match feed')
                bind_candidate(records[-1]['height'],records[-1]['hash'],rows)
                self.gateway(self.config['publisher_host'],'commit',transaction=pending['transaction'])
                return self.finish('recovered_publication',records,rows,transaction=pending['transaction'])
        height = candidate_height(rows[0]['height'])
        if height <= records[-1]['height']:
            return self.finish('current_no_new_eligible_height',records,rows)
        rows = self.observe([records[-1]['height'],height])
        block_hash = rows[0]['hashes'][str(height)]
        bind_records(records[-1:],rows); bind_candidate(height,block_hash,rows)
        record = self.sign(height,block_hash)
        updated = records+[record]
        append_only(records,updated)
        new = encode(updated)
        self.verify(new,'candidate-feed')
        rows = self.observe([records[-1]['height'],height])
        bind_records(records[-1:],rows); bind_candidate(height,block_hash,rows)
        transaction = uuid.uuid4().hex
        atomic_json(self.run_dir/'publication-plan.json',dict(transaction=transaction,base_sha256=sha(raw),after_sha256=sha(new)))
        try:
            installed = self.gateway(self.config['publisher_host'],'install',transaction=transaction,base_sha256=sha(raw),document_b64=base64.b64encode(new).decode())
            atomic_json(self.run_dir/'installed.json',installed)
            public = self.public_feed()
            require(public == new, 'Published checkpoint readback mismatch')
            self.verify(public,'published-feed')
            self.gateway(self.config['publisher_host'],'commit',transaction=transaction)
        except Exception:
            current = self.gateway(self.config['publisher_host'],'read')
            if any(p['transaction'] == transaction for p in current['pending']):
                rolled_back = self.gateway(self.config['publisher_host'],'rollback',transaction=transaction)
                atomic_json(self.run_dir/'rollback.json',rolled_back)
            raise
        return self.finish('published',updated,rows,transaction=transaction)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config',default='/etc/veld-checkpoints/signer.json')
    parser.add_argument('--preflight',action='store_true')
    args = parser.parse_args()
    publisher = Publisher(json.loads(Path(args.config).read_bytes()))
    with (publisher.state/'publisher.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.preflight:
            rows = publisher.observe([2800])
            origin = publisher.gateway(publisher.config['publisher_host'],'read')
            raw = publisher.public_feed()
            require(sha(raw) == origin['sha256'], 'Preflight feed mismatch')
            publisher.verify(raw,'preflight-feed')
            print(json.dumps(dict(status='preflight_pass',tip=rows[0]['height'],feed_sha256=sha(raw))))
        else:
            publisher.run()


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Checkpoint publisher failed: '+str(error),file=sys.stderr)
        raise SystemExit(1)
