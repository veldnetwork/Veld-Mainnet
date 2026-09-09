"""Read back terminal state from the authenticated archive after real-chain replay."""
from pathlib import Path
import argparse,hashlib,json
from security_state_migration_network_tests import Node
p=argparse.ArgumentParser()
p.add_argument("--completed-run",type=Path,required=True)
p.add_argument("--binary",type=Path,required=True)
a=p.parse_args();directory=a.completed_run.resolve()
prior=json.loads((directory/"first-activation-results.json").read_text())
assert prior["status"]=="integration_pass" and prior["stopped"]
node=None
result={"status":"running","checks":{},"binary_sha256":hashlib.sha256(a.binary.read_bytes()).hexdigest()}
try:
    node=Node(a.binary.resolve(),directory/"node-a","-archive-readback")
    assert node.ready["digest"]==prior["final_state"]["digest"]
    state=node.control("fa_archive_status")
    assert state["migration_active"] and state["hot_requests"]==0 and state["hot_payout_identities"]==0,state
    assert state["archive_count"]>=2,state
    request=node.control("fa_request",request_id=prior["request"]["request_id"])
    assert request=={k:v for k,v in prior["request"].items() if k!="request_id"},request
    result["archive"]=state;result["request"]=request
    result["checks"]={"complete_replay_digest_matches":True,"terminal_request_removed_from_hot_map":True,
                      "consumed_payout_removed_from_hot_set":True,"authenticated_archive_serves_complete_terminal_request":True}
    result["status"]="integration_pass"
    print("PASS real-chain archive readback checks=4",flush=True)
except BaseException as error:
    result["status"]="integration_failed";result["failure"]={"type":type(error).__name__,"message":str(error)}
    raise
finally:
    if node:node.stop()
    result["stopped"]=node is None or node.process.poll() is not None
    (directory/"archive-readback-results.json").write_text(json.dumps(result,indent=2)+"\n")
