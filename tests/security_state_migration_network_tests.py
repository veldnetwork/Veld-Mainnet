"""Ordinary isolated node/RPC/P2P integration. No public endpoints or real keys."""
from pathlib import Path
import argparse, datetime, http.client, json, os, queue, shutil, socket, subprocess, threading, time

ROOT = Path(__file__).resolve().parents[1]

class RpcError(RuntimeError):
    pass
def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        if port < 20000:
            return free_port()
        return port

class Node:
    def __init__(self, binary, directory, suffix=""):
        self.directory = directory
        self.p2p, self.rpc_port = free_port(), free_port()
        self.events = queue.Queue()
        self.admission_retries = 0
        env = dict(os.environ)
        env["PATH"] = r"C:\msys64\clang64\bin" + os.pathsep + env.get("PATH", "")
        env["VELD_LEVELDB_WRITE_BUFFER_MB"] = "8"
        env["VELD_LEVELDB_BLOCK_CACHE_MB"] = "16"
        self.log = open(directory.parent / (directory.name + suffix + ".log"), "w", encoding="utf-8")
        self.process = subprocess.Popen(
            [str(binary), str(directory), str(self.p2p), str(self.rpc_port)],
            cwd=directory.parent, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.reader = threading.Thread(target=self.read_output, daemon=True)
        self.reader.start()
        try:
            self.ready = self.event("TEST_READY", 240)
            self.token = (directory / "test-rpc-token").read_text()
        except BaseException:
            self.stop()
            raise
    def read_output(self):
        for line in self.process.stdout:
            self.log.write(line)
            self.log.flush()
            if line.startswith(("TEST_READY ", "TEST_RESULT ", "TEST_FATAL ", "TEST_STOPPED")):
                self.events.put(line.strip())
        self.events.put("EXIT " + str(self.process.wait()))
    def event(self, prefix, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            item = self.events.get(timeout=max(.1, deadline-time.monotonic()))
            if item.startswith(prefix+" "):
                return json.loads(item[len(prefix)+1:])
            if item.startswith(("EXIT", "TEST_FATAL")):
                raise RuntimeError(item + "; see " + self.log.name)
        raise TimeoutError(prefix)
    def control(self, command, **fields):
        self.process.stdin.write(json.dumps(dict(command=command, **fields), ensure_ascii=True)+"\n")
        self.process.stdin.flush()
        result = self.event("TEST_RESULT",600 if command=="import_history" else 120)
        if "test_error" in result:
            raise RuntimeError(result["test_error"])
        return result
    def rpc(self, method, params=(), authenticated=True, timeout=240):
        conn = http.client.HTTPConnection("127.0.0.1", self.rpc_port, timeout=timeout)
        headers = {"Content-Type": "application/json"}
        if authenticated: headers["Authorization"] = "Bearer " + self.token
        conn.request("POST", "/", json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=list(params))), headers)
        response = conn.getresponse()
        raw = response.read(4 * 1024 * 1024)
        status = response.status
        conn.close()
        if not authenticated:
            return status
        if status != 200:
            raise RuntimeError(f"RPC HTTP status {status}: {raw[:100]!r}")
        value = json.loads(raw)
        if value.get("error"):
            raise RpcError(f"{method}: {value['error']}")
        return value["result"]
    def generate(self, count):
        start=self.control("status")["height"]
        target=start+count
        for attempt in range(max(20,count*2)):
            height=self.control("status")["height"]
            assert start<=height<=target, (start,height,target)
            if height==target: return {"generated":count,"height":height}
            try:
                result=self.rpc("generate", [str(target-height)])
                assert result["generated"]==target-height, result
            except RpcError as error:
                # A changed peer view cancels an obsolete binding. Retry only
                # this explicit safe refusal, from the actual committed height.
                if not any(message in str(error) for message in (
                    "Synchronous mining cancelled: IBD/work admission closed",
                    "Synchronous mining refused: IBD/work admission is closed",
                    "Synchronous mining discarded: work admission closed before commit",
                    "Block commit deferred: local work admission unavailable")):
                    raise
                self.admission_retries+=1
                wait_admission(self,require_peer=False)
        raise TimeoutError("generation repeatedly cancelled by admission changes")
    def stop(self):
        if self.log.closed: return
        if self.process.poll() is None:
            self.process.stdin.write('{"command":"stop"}\n')
            self.process.stdin.flush()
            try: self.process.wait(timeout=40)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=20)
                raise RuntimeError("node did not shut down gracefully")
        self.reader.join(timeout=5)
        self.log.close()

def wait_equal(a, b, timeout=90):
    deadline = time.monotonic() + timeout
    maintenance_at=0
    redial_at=0
    while time.monotonic() < deadline:
        aa, bb = a.control("status"), b.control("status")
        if aa["height"] == bb["height"] and aa["tip"] == bb["tip"]:
            assert aa["digest"] == bb["digest"], (aa, bb)
            return aa
        if time.monotonic()>=maintenance_at:
            a.control("maintain"); b.control("maintain")
            maintenance_at=time.monotonic()+5
        if time.monotonic()>=redial_at:
            if aa["ready_peer_ips"]==0: a.control("connect",port=b.p2p)
            if bb["ready_peer_ips"]==0: b.control("connect",port=a.p2p)
            redial_at=time.monotonic()+30
        time.sleep(.25)
    raise TimeoutError("peers did not converge: "+str((aa,bb)))

def wait_admission(node, require_peer=True, timeout=90):
    deadline=time.monotonic()+timeout
    previous=None
    stable=0
    while time.monotonic()<deadline:
        status=node.control("status")
        generation=status["admission_generation"]
        if status["admission_allowed"] and (not require_peer or status["ready_peer_ips"]>0):
            stable=stable+1 if previous==generation else 0
            if stable>=3: return status
            previous=generation
        else:
            previous=None; stable=0
        time.sleep(.25)
    raise TimeoutError("work admission did not stabilize: "+str(status))

def advance(a,b,height):
    state=a.control("status"); previous=state["height"]
    while previous<height:
        a.generate(min(32,height-previous))
        state=wait_equal(a,b) if b is not None else a.control("status")
        previous=state["height"]
        print("CHAIN height="+str(previous)+" "+("peers_equal=true" if b is not None else "local_full_validation=true"),flush=True)
    return state

def proposal(node,title):
    found=[p for p in node.rpc("getproposals") if p["title"]==title]
    assert len(found)==1, found
    return found[0]

def full_scenario(a,b,binary,directory,nodes,report):
    height=2880
    checks=report["checks"]
    b.stop(); b=None
    wait_admission(a,require_peer=False)
    # The ordinary emission schedule activates staking early and redirects most
    # subsidy to protocol pools. Accumulate the five bonds from real mature
    # coinbase outputs; do not inject balances or lower the bonding rule.
    advance(a,b,256)
    for wallet in range(1,6):
        a.control("fund",to=wallet,amount="60")
        advance(a,b,a.control("status")["height"]+1)
        assert a.rpc("getbalance",[a.ready["addresses"][wallet]])["balance_veld"]==60
    checks["wallet_prepare_sign_mempool_mine_peer_credit"]=True
    for wallet in range(1,5):
        a.control("register",wallet=wallet)
        advance(a,b,a.control("status")["height"]+1)
        info=a.rpc("getgovernanceinfo")
        assert info["registered_validators"]==wallet and not info["governance_active"], info
    try:
        a.control("propose",wallet=1,title="Ordinary proposal while locked",description="Governance gate control.")
        raise AssertionError("four validators unexpectedly permitted governance")
    except RuntimeError as error:
        if "Governance is locked" not in str(error): raise
    a.control("register",wallet=5)
    advance(a,b,a.control("status")["height"]+1)
    info=a.rpc("getgovernanceinfo")
    assert info["registered_validators"]==5 and info["governance_active"], info
    assert info["bonded_veld"]==250, info
    checks["five_distinct_custodial_bonds_unlock_governance"]=True
    a.control("stake",amount="50")
    advance(a,b,a.control("status")["height"]+1)
    assert a.rpc("getbalance",[a.ready["addresses"][0]])["staked_veld"]==50
    checks["ordinary_stake_backing"]=True
    advance(a,b,height-3)

    # A stopped disposable peer gives the fork an exact, durable common parent.
    parent=a.control("status")
    a.control("export_history",name="prefix-history.bin")
    b=Node(binary,directory/"node-b-prefix"); nodes.append(b)
    imported=b.control("import_history",name="prefix-history.bin")
    assert imported["imported_height"]==parent["height"] and imported["digest"]==parent["digest"]
    checks["full_local_prefix_validation"]=True
    b.stop()
    shutil.copytree(b.directory,directory/"node-fork")
    b=Node(binary,b.directory,"-preactivation-restart"); nodes.append(b)
    b.control("connect",port=a.p2p)
    assert wait_equal(a,b)["digest"]==parent["digest"]
    wait_admission(a); wait_admission(b); b.control("synchronize")
    checks["preactivation_restart"]=True

    legacy_title="Legacy community proposal"
    a.control("propose",wallet=1,title=legacy_title,description="Preserve the recorded proposal across migration.")
    advance(a,b,height-2)
    legacy=proposal(a,legacy_title)
    a.control("vote",wallet=1,proposal=legacy["id"],identity="")
    # Registration opens the bond gate; recent endorsements determine the
    # GENERAL proposal quorum. Exercise five recently active validators, so
    # this one-vote legacy proposal is still OPEN when the old upgrade runs.
    for wallet in range(1,6):
        a.control("endorse",wallet=wallet,sponsor=0 if wallet==1 else wallet,height=height-3)
    advance(a,b,height-1)
    before=proposal(a,legacy_title)
    assert before["votes_yes"]==1 and before["status"]=="open", before
    assert a.rpc("getblockendorsements",[str(height-3)])["count"]==5
    assert a.rpc("getgovernanceinfo")["active_validators"]==5
    assert a.rpc("getblockchaininfo")["gov_proposal_version"]==2
    checks["legacy_proposal_vote_and_endorsement_before_height"]=True

    new_title="Community caf\u00e9 | phase:2"
    a.control("propose",wallet=3,title=new_title,description="UTF-8 and delimiter text retain their signed field boundaries.")
    # A different disposable wallet funds this explicit validator identity.
    a.control("endorse",wallet=4,sponsor=0,height=height-1)
    advance(a,b,height)
    new=proposal(a,new_title)
    after=proposal(a,legacy_title)
    assert after["id"]==before["id"] and after["creation_identity"]==before["creation_identity"]
    # The pre-existing 2880 upgrade resets OPEN voting rounds. The new framing
    # migration must preserve that established historical behavior exactly.
    assert after["vote_round_start"]==height and after["votes_yes"]==0, after
    assert after["expires_at"]==height+14*480
    endorsements=a.rpc("getblockendorsements",[str(height-1)])
    assert endorsements["count"]==1 and endorsements["endorsements"][0]["address"]==a.ready["addresses"][4], endorsements
    checks["combined_activation_at_2880"]=True
    checks["historical_governance_round_migration_preserved"]=True
    checks["attributed_sponsored_endorsement"]=True
    report["activation_state"]=wait_equal(a,b)
    report["legacy_proposal_before"]=before
    report["legacy_proposal_after"]=after
    report["new_proposal"]=new

    for wallet in range(1,6):
        a.control("vote",wallet=wallet,proposal=new["id"],identity=new["vote_identity"])
    # Quorum finalization runs once after every operation in the block.
    advance(a,b,height+1)
    voted=proposal(a,new_title)
    assert voted["votes_yes"]==5 and voted["expires_at"]==new["expires_at"], voted
    checks["five_signed_bound_votes_after_activation"]=True
    report["voted_proposal"]=voted
    stable=wait_equal(a,b)
    b.stop()
    b=Node(binary,b.directory,"-postactivation-restart"); nodes.append(b)
    assert b.ready["digest"]==stable["digest"] and b.ready["height"]==stable["height"]
    b.control("connect",port=a.p2p)
    assert wait_equal(a,b)["digest"]==stable["digest"]
    assert proposal(b,new_title)==voted
    checks["postactivation_full_disk_replay"]=True

    fork=Node(binary,directory/"node-fork"); nodes.append(fork)
    assert fork.ready["digest"]==parent["digest"] and fork.ready["height"]==height-3
    fork.control("synchronize")
    wait_admission(fork,require_peer=False)
    fork.generate(6)
    assert fork.control("status")["height"]==height+3
    a.control("connect",port=fork.p2p); b.control("connect",port=fork.p2p)
    forked=wait_equal(a,fork,420)
    assert wait_equal(a,b,420)["digest"]==forked["digest"]
    assert all(p["title"] not in (new_title,legacy_title) for p in a.rpc("getproposals"))
    checks["p2p_reorganization_across_2880"]=True
    report["reorganized_state"]=forked

    fresh=Node(binary,directory/"node-fresh-ibd"); nodes.append(fresh)
    fork.control("export_history",name="final-history.bin")
    replayed=fresh.control("import_history",name="final-history.bin")
    assert replayed["digest"]==forked["digest"] and replayed["imported_height"]==forked["height"]
    fresh.control("connect",port=fork.p2p)
    assert wait_equal(fresh,fork,300)["digest"]==forked["digest"]
    checks["fresh_node_full_local_history_replay_and_p2p_convergence"]=True
    report["genesis_to_tip_p2p_ibd"]="NOT RUN: unchanged eight-PoW-checks-per-minute source limit; local full validation plus migration P2P suffix tested"
    report["final_state"]=forked
    report["admission_cancellations_safely_retried"]=sum(n.admission_retries for n in nodes)
    report["status"]="integration_pass"
    return report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    directory = args.output_dir.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    nodes=[]
    report={"status":"starting","activation_height":2880,"checks":{}}
    try:
        a=Node(args.binary.resolve(),directory/"node-a"); nodes.append(a)
        print("READY node-a height="+str(a.ready["height"]), flush=True)
        assert a.rpc("getblockchaininfo",authenticated=False) in (401,403)
        assert a.rpc("getblockchaininfo")["gov_proposal_version"] == 1
        conn=http.client.HTTPConnection("127.0.0.1",a.ready["explorer_port"],timeout=20)
        conn.request("GET","/")
        response=conn.getresponse(); page=response.read(4*1024*1024); conn.close()
        assert response.status==200 and b"<html" in page.lower()
        print("PASS authenticated RPC and loopback Explorer", flush=True)
        b=Node(args.binary.resolve(),directory/"node-b"); nodes.append(b)
        print("READY node-b height="+str(b.ready["height"]), flush=True)
        b.control("connect",port=a.p2p)
        wait_admission(a)
        wait_admission(b)
        a.control("synchronize"); b.control("synchronize")
        wait_admission(a)
        print("GENERATE initial blocks",flush=True)
        a.generate(3)
        state=wait_equal(a,b)
        print("PASS peers converged height="+str(state["height"]),flush=True)
        report={"status":"smoke_pass","activation_height":2880,"height":state["height"],
                "digest":state["digest"],"p2p":"loopback","rpc_auth":"required",
                "mainnet_activation":0,"checks":{"authenticated_rpc":True,"explorer_http":True,"initial_p2p_convergence":True},
                "admission_cancellations_safely_retried":a.admission_retries}
        if not args.smoke:
            report=full_scenario(a,b,args.binary.resolve(),directory,nodes,report)
        (directory/"network-results.json").write_text(json.dumps(report,indent=2)+"\n")
        print("PASS security_state_migration_network_tests "+report["status"],flush=True)
        return 0
    except Exception as error:
        report["status"]="integration_failed"
        report["failure"]={"type":type(error).__name__,"message":str(error)}
        (directory/"network-results.json").write_text(json.dumps(report,indent=2)+"\n")
        raise
    finally:
        for node in reversed(nodes): node.stop()
if __name__=="__main__":
    raise SystemExit(main())
