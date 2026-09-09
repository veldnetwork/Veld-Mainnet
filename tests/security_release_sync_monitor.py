"""Passive resource and authenticated-RPC measurements for an owned sync run."""
from pathlib import Path
import argparse, datetime, http.client, json, os, time
import psutil

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run',type=Path,required=True)
    parser.add_argument('--attempt',type=int,required=True)
    args=parser.parse_args();run=args.run.resolve()
    result=run/f'sync-recovery-results-{args.attempt}.json'
    output=run/f'sync-resource-observations-{args.attempt}.json'
    assert result.is_file() and not output.exists()
    binary=run/'first-activation-archive-readback-node.exe'
    targets={}
    for role in ('source','fresh'):
        directory=run/f'node-sync-{role}-{args.attempt}'
        matches=[]
        for process in psutil.process_iter(['exe','cmdline']):
            try:
                cmd=process.info['cmdline'] or []
                if (process.info['exe'] and Path(process.info['exe']).resolve()==binary and
                    len(cmd)==4 and Path(cmd[1]).resolve()==directory):
                    matches.append((process,int(cmd[3]),directory))
            except (psutil.NoSuchProcess,psutil.AccessDenied):pass
        assert len(matches)==1,(role,len(matches))
        targets[role]=matches[0]
    report={'status':'observing','scope':'passive observation of two owned loopback test nodes',
            'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'psutil_version':psutil.__version__,'samples':[]}
    start=time.monotonic()
    def save():
        temp=output.with_suffix('.tmp');temp.write_text(json.dumps(report,indent=2)+'\n');os.replace(temp,output)
    while True:
        state=json.loads(result.read_text())
        if state['status']!='running':
            report['status']='observations_complete';report['integration_status']=state['status'];break
        sample={'elapsed_seconds':round(time.monotonic()-start,1),'nodes':{}}
        for role,(process,port,directory) in targets.items():
            row={};sample['nodes'][role]=row
            if not process.is_running():row['process_stopped']=True;continue
            try:
                with process.oneshot():
                    mem=process.memory_info();cpu=process.cpu_times();io=process.io_counters()
                    row.update(rss_bytes=mem.rss,private_bytes=mem.private,
                        cpu_seconds=cpu.user+cpu.system,read_bytes=io.read_bytes,write_bytes=io.write_bytes)
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
                token=(directory/'test-rpc-token').read_text()
                started=time.monotonic()
                conn.request('POST','/',json.dumps({'jsonrpc':'2.0','id':1,'method':'getblockchaininfo','params':[]}),
                    {'Content-Type':'application/json','Authorization':'Bearer '+token})
                response=conn.getresponse();body=response.read(1024*1024);status=response.status;conn.close()
                assert status==200
                value=json.loads(body);assert not value.get('error')
                row.update(rpc_seconds=round(time.monotonic()-started,6),height=value['result']['blocks'],
                    tip=value['result']['best_block_hash'],ibd_complete=value['result']['ibd_complete'])
            except Exception as error:
                # Record type only; never serialize authenticated request details.
                row['observation_error_type']=type(error).__name__
        report['samples'].append(sample);save()
        if time.monotonic()-start>32400:report['status']='observation_deadline';break
        time.sleep(60)
    report['ended_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['summary']={}
    for role in targets:
        rows=[sample['nodes'][role] for sample in report['samples']]
        report['summary'][role]={
            'successful_rpc_samples':sum('rpc_seconds' in row for row in rows),
            'observation_errors':sum('observation_error_type' in row for row in rows),
            'peak_rss_bytes':max((row.get('rss_bytes',0) for row in rows),default=0),
            'max_rpc_seconds':max((row.get('rpc_seconds',0) for row in rows),default=0)}
    save();print(json.dumps({'status':report['status'],'summary':report['summary']}),flush=True)

if __name__=='__main__':main()
