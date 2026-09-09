"""Normal governance, endorsement and populated-state reorg at a separate test height."""
from pathlib import Path
import argparse,json,struct,time
from security_state_migration_network_tests import Node,wait_equal,wait_admission,proposal

def prefix(source,destination,last_height):
    chunks=[]
    with source.open("rb") as src:
        magic=src.read(8);assert magic==b"VLDMIG01";chunks.append(magic)
        for height in range(last_height+1):
            length=src.read(4);assert len(length)==4
            n=struct.unpack("<I",length)[0];assert 0<n<=8000000
            body=src.read(n);assert len(body)==n
            chunks.extend((length,body))
    expected=b"".join(chunks)
    if destination.exists():assert destination.read_bytes()==expected
    else:
        with destination.open("xb") as out:out.write(expected)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--completed-run",type=Path,required=True)
    p.add_argument("--attempt",type=int,default=1)
    args=p.parse_args();directory=args.completed_run.resolve()
    assert 1<=args.attempt<=20
    suffix="-"+str(args.attempt)
    result_path=directory/("separate-boundary-results"+suffix+".json")
    previous=json.loads((directory/"first-activation-results.json").read_text())
    assert previous["status"]=="integration_pass" and previous["stopped"]
    assert previous["test_migration_height"]==3360 and previous["original_upgrade_height"]==2880
    binary=directory/"first-activation-node.exe"
    assert not result_path.exists()
    prefix(directory/"final-history.bin",directory/"prefix-history.bin",3357)
    report={"status":"running","original_upgrade_height":2880,"new_test_height":3360,
            "new_production_height":0,"checks":{}}
    checks=report["checks"];nodes=[]
    try:
        a=Node(binary,directory/("node-boundary-a"+suffix));nodes.append(a)
        parent=a.control("import_history",name="prefix-history.bin")
        b=Node(binary,directory/("node-boundary-b"+suffix));nodes.append(b)
        assert b.control("import_history",name="prefix-history.bin")["digest"]==parent["digest"]
        b.control("connect",port=a.p2p);wait_equal(a,b)
        wait_admission(a);wait_admission(b)
        a.control("synchronize");b.control("synchronize")
        print("PASS populated canonical prefix independently validated on two peers",flush=True)
        title="Existing community voting round"
        a.control("propose",wallet=1,title=title,description="This ordinary vote must survive the later parser and archive migration.")
        for wallet in range(1,6):a.control("endorse",wallet=wallet,sponsor=0,height=3357)
        a.generate(1);wait_equal(a,b)
        legacy=proposal(a,title)
        a.control("vote",wallet=1,proposal=legacy["id"],identity=legacy["vote_identity"])
        a.generate(1);wait_equal(a,b)
        before=proposal(a,title)
        assert before["votes_yes"]==1 and before["status"]=="open",before
        checks["legacy_round_and_five_endorsements_before_new_height"]=True
        new_title="Community caf\u00e9 | later activation"
        a.control("propose",wallet=3,title=new_title,description="UTF-8 | text: fields remain independently framed after the separate migration.")
        a.control("endorse",wallet=4,sponsor=0,height=3359)
        a.generate(1);migration=wait_equal(a,b)
        assert migration["height"]==3360
        after=proposal(a,title)
        for field in ("id","creation_identity","votes_yes","vote_round_start","expires_at"):
            assert before[field]==after[field],(field,before,after)
        checks["new_height_preserves_original_governance_round"]=True
        new=proposal(a,new_title)
        endorsements=a.rpc("getblockendorsements",["3359"])
        assert endorsements["count"]==1 and endorsements["endorsements"][0]["address"]==a.ready["addresses"][4],endorsements
        checks["new_framed_proposal_and_attributed_sponsored_endorsement"]=True
        request_id=previous["request"]["request_id"]
        expected_request={k:v for k,v in previous["request"].items() if k!="request_id"}
        assert a.control("fa_request",request_id=request_id)==expected_request
        assert a.rpc("getpeginfo")["reserve_accounting_holds"]
        assert a.rpc("getpeginfo")["supply_sats"]==2400000
        checks["populated_reserve_and_archived_fulfillment_preserved"]=True
        for wallet in range(1,6):
            a.control("vote",wallet=wallet,proposal=new["id"],identity=new["vote_identity"])
        a.generate(1);wait_equal(a,b)
        assert proposal(a,new_title)["votes_yes"]==5
        checks["five_votes_after_separate_migration"]=True
        report["legacy_before"]=before;report["legacy_after"]=after;report["migration_state"]=migration
        fork=Node(binary,directory/("node-boundary-fork"+suffix));nodes.append(fork)
        assert fork.control("import_history",name="prefix-history.bin")["digest"]==parent["digest"]
        fork.control("synchronize");wait_admission(fork,require_peer=False)
        fork.generate(5)
        assert fork.control("status")["height"]==3362
        a.control("connect",port=fork.p2p);b.control("connect",port=fork.p2p)
        selected=wait_equal(a,fork,420)
        assert wait_equal(a,b,420)["digest"]==selected["digest"]
        assert all(row["title"] not in (title,new_title) for row in a.rpc("getproposals"))
        assert a.control("fa_request",request_id=request_id)==expected_request
        assert a.rpc("getpeginfo")["supply_sats"]==2400000 and a.rpc("getpeginfo")["reserve_accounting_holds"]
        checks["p2p_reorganization_across_new_height_preserves_prior_financial_state"]=True
        report["reorganized_state"]=selected
        a.stop();b.stop();fork.stop()
        restarted=Node(binary,a.directory,"-after-reorg-restart");nodes.append(restarted)
        assert restarted.ready["digest"]==selected["digest"] and restarted.ready["height"]==3362
        assert restarted.control("fa_request",request_id=request_id)==expected_request
        checks["restart_after_populated_state_migration_reorganization"]=True
        report["status"]="integration_pass"
        print("PASS separate activation boundary checks="+str(len(checks)),flush=True)
    except BaseException as error:
        report["status"]="integration_failed";report["failure"]={"type":type(error).__name__,"message":str(error)}
        raise
    finally:
        for node in reversed(nodes):node.stop()
        report["stopped"]=all(n.process.poll() is not None for n in nodes)
        result_path.write_text(json.dumps(report,indent=2)+"\n")
if __name__=="__main__":main()
