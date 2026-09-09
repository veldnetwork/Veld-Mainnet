"""Normal-flow first activation against a private Bitcoin Core regtest wallet."""
from pathlib import Path
import argparse, base64, hashlib, http.client, json, os, subprocess, time, traceback
from security_state_migration_network_tests import Node, free_port, wait_admission, wait_equal, advance, RpcError
ROOT=Path(__file__).resolve().parents[1]
def sha(data): return hashlib.sha256(data).digest()
def sha256d(data): return sha(sha(data))
def internal(display): return bytes.fromhex(display)[::-1].hex()
def btc(sats): return round(sats/100000000,8)

class Bitcoin:
    def __init__(self,binary,directory):
        self.directory=directory
        directory.mkdir(parents=True,exist_ok=True)
        self.port=free_port()
        self.log=open(directory.parent/"bitcoin-core.log","a",encoding="utf-8")
        args=[str(binary),"-regtest",f"-datadir={directory}","-server=1","-listen=0","-connect=0",
              "-dnsseed=0","-fixedseeds=0","-discover=0","-upnp=0","-natpmp=0","-networkactive=0",
              "-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1",f"-rpcport={self.port}",
              "-txindex=1","-fallbackfee=0.00001","-persistmempool=0"]
        self.process=subprocess.Popen(args,stdout=self.log,stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        self.wallet=False
        for _ in range(100):
            if self.process.poll() is not None: raise RuntimeError("Bitcoin Core startup failed; see local log")
            try:
                self.cookie=(directory/"regtest/.cookie").read_text()
                assert self.rpc("getblockchaininfo")["chain"]=="regtest"
                assert self.rpc("getnetworkinfo")["connections"]==0
                assert not self.rpc("getnetworkinfo")["networkactive"]
                break
            except (OSError,RuntimeError): time.sleep(.2)
        else: raise TimeoutError("Bitcoin Core RPC startup")
        loaded=self.rpc("listwallets")
        if "disposable" not in loaded:
            existing=[x["name"] for x in self.rpc("listwalletdir")["wallets"]]
            self.rpc("loadwallet" if "disposable" in existing else "createwallet",["disposable"])
        self.wallet=True
    def rpc(self,method,params=(),wallet=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.port,timeout=120)
        headers={"Content-Type":"application/json","Authorization":"Basic "+base64.b64encode(self.cookie.strip().encode()).decode()}
        conn.request("POST",("/wallet/"+(wallet or "disposable")) if self.wallet else "/",json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":list(params)}),headers)
        response=conn.getresponse(); raw=response.read(16*1024*1024); conn.close()
        value=json.loads(raw)
        if value.get("error"): raise RuntimeError(f"Bitcoin RPC {method}: {value['error']}")
        return value["result"]
    def mine(self,count=3):
        return self.rpc("generatetoaddress",[count,self.rpc("getnewaddress",["mining","bech32"])])
    def fund(self,sats,legacy=False):
        address=self.rpc("getnewaddress",["external-fee-or-deposit","legacy" if legacy else "bech32"])
        txid=self.rpc("sendtoaddress",[address,btc(sats)])
        self.mine(1)
        tx=self.rpc("getrawtransaction",[txid,True])
        matches=[o["n"] for o in tx["vout"] if o["scriptPubKey"].get("address")==address]
        assert len(matches)==1
        return {"txid":txid,"vout":matches[0],"raw":tx["hex"],"value":sats}
    def send(self,inputs,outputs):
        raw=self.rpc("createrawtransaction",[[{"txid":x["txid"],"vout":x["vout"]} for x in inputs],outputs])
        signed=self.rpc("signrawtransactionwithwallet",[raw])
        assert signed["complete"],"Core wallet must sign every Bitcoin input"
        admission=self.rpc("testmempoolaccept",[[signed["hex"]]])[0]
        assert admission["allowed"],admission
        txid=self.rpc("sendrawtransaction",[signed["hex"]])
        self.mine(4)
        tx=self.rpc("getrawtransaction",[txid,True])
        return {"txid":txid,"raw":signed["hex"],"block":tx["blockhash"],"parents":[x["raw"] for x in inputs]}
    def proof(self,transaction):
        block=self.rpc("getblock",[transaction["block"],1])
        nodes=[bytes.fromhex(x)[::-1] for x in block["tx"]]
        index=block["tx"].index(transaction["txid"])
        original_index=index; branch=[]
        while len(nodes)>1:
            if len(nodes)%2: nodes.append(nodes[-1])
            branch.append(nodes[index^1].hex())
            nodes=[sha256d(nodes[i]+nodes[i+1]) for i in range(0,len(nodes),2)]
            index//=2
        header=bytes.fromhex(self.rpc("getblockheader",[transaction["block"],False]))
        assert nodes[0]==header[36:68]
        return {"txid":internal(transaction["txid"]),"rawtx":transaction["raw"],"block":internal(transaction["block"]),
                "branch":branch,"directions":original_index,"parents":transaction["parents"]}
    def stop(self):
        if self.process.poll() is None:
            try:self.rpc("stop")
            finally:self.process.wait(timeout=45)
        self.log.close()
        cookie=self.directory/"regtest/.cookie"
        if cookie.exists(): cookie.unlink()

def compile_node(directory,script,compiler,checkpoint):
    objects=sorted((ROOT.parent/"build/migration-pqc-opt").glob("pqc-*.o"))
    assert len(objects)==11
    env=dict(os.environ);env["PATH"]=str(compiler.parent)+os.pathsep+env.get("PATH","")
    public=directory/"disposable-addresses.json"
    if not public.exists():
        helper=directory/"create-disposable-identities.exe"
        command=[str(compiler),"-std=c++20","-O2","-Iinclude","tests/security_first_activation_identity.cpp",
                 *[str(x) for x in objects],"-lws2_32","-lbcrypt","-lcrypt32","-o",str(helper)]
        with open(directory/"identity-build.log","w") as log:
            subprocess.run(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        addresses=subprocess.check_output([str(helper),str(directory/"disposable-identities")],env=env,text=True).splitlines()
        assert len(addresses)==8
        public.write_text(json.dumps(addresses,indent=2))
    addresses=json.loads(public.read_text())
    header=directory/"custody-test-profile.h"
    header.write_text('#define VELD_FIRST_ACTIVATION_CUSTODY_SPK_HEX "'+script+'"\n'+
                      '#define VELD_FIRST_ACTIVATION_AUTHORITY_ADDRESS "'+addresses[0]+'"\n'+
                      '#define VELD_FIRST_ACTIVATION_BTC_CHECKPOINT_HEIGHT 2016u\n'+
                      '#define VELD_FIRST_ACTIVATION_BTC_CHECKPOINT_BITS 0x'+checkpoint["bits"]+'u\n'+
                      '#define VELD_FIRST_ACTIVATION_BTC_CHECKPOINT_TIME '+str(checkpoint["time"])+'u\n'+
                      '#define VELD_FIRST_ACTIVATION_BTC_CHECKPOINT_HASH "'+internal(checkpoint["hash"])+'"\n'+
                      '#define VELD_FIRST_ACTIVATION_BTC_CHECKPOINT_PREV10 {'+','.join(str(t)+'u' for t in checkpoint["prev10"])+'}\n')
    binary=directory/"first-activation-node.exe"
    command=[str(compiler),"-std=c++20","-O2","-pthread","-DVELD_FIRST_ACTIVATION_NETWORK=1",
             "-DVELD_FIRST_ACTIVATION_MIGRATION_HEIGHT=3360","-DVELD_LIGHT_VERIFY=1","-DVELD_USE_LEVELDB=1","-include",str(header),
             "-Iinclude","-Ivendor/pqclean/crypto_sign/ml-dsa-65/clean","-Ivendor/pqclean/common",
             "tests/security_state_migration_node.cpp",*[str(x) for x in objects],
             "-lleveldb","-lws2_32","-lbcrypt","-lcrypt32","-o",str(binary)]
    (directory/"build-command.json").write_text(json.dumps(command,indent=2))
    with open(directory/"build.log","w") as log:
        process=subprocess.run(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
    if process.returncode:raise RuntimeError("first activation build failed; see build.log")
    return binary

def relay(a,core):
    best=a.rpc("getbtcheaderinfo")["best_height"]
    tip=core.rpc("getblockcount")
    for start in range(best+1,tip+1,100):
        headers=[core.rpc("getblockheader",[core.rpc("getblockhash",[h]),False]) for h in range(start,min(start+100,tip+1))]
        a.control("fa_headers",headers=headers)
        a.generate(1)
    assert a.rpc("getbtcheaderinfo")["best_height"]==tip

def finalize(a,core,target=None):
    height=a.control("status")["height"]
    target=target if target is not None else ((height+19)//20)*20
    advance(a,None,target+1)
    # Independently verify every staged Bitcoin observation against Core's
    # active chain before authorizing these exact disposable validator votes.
    info=a.rpc("getanchorinfo")
    for observation in info.get("pending_observations",[]):
        header=core.rpc("getblockheader",[internal(observation["btc_block_hash"]),True])
        assert header["confirmations"]>=145 and observation["btc_final"],header
    target_hash=a.rpc("getblockhash",[str(target)])
    vote=a.control("fa_finality",bitcoin_checked_height=target,bitcoin_checked_hash=target_hash)
    assert vote["precommit_qc_bytes"]>0,vote
    a.generate(1)
    peg=a.rpc("getpeginfo")
    assert peg["final_height"]==target,peg
    print("PASS actual quorum certificate finalized="+str(target),flush=True)
    return peg

def observe_bitcoin(a,core):
    finalized=a.rpc("getfinalitysnapshot")["snapshot"]["finalized"]
    assert finalized and finalized["height"]>=2880
    payload=b"VELD_ANCHOR:"+finalized["height"].to_bytes(8,"little")+bytes.fromhex(finalized["hash"])
    anchor=core.send([core.fund(1000,legacy=True)],[{"data":payload.hex()}])
    assert sha256d(bytes.fromhex(anchor["raw"])).hex()==internal(anchor["txid"])
    core.mine(144)  # Preserve the full public Bitcoin anchor burial requirement.
    relay(a,core)
    proof=core.proof(anchor)
    wire=(b"ANCH"+bytes.fromhex(proof["block"])+proof["directions"].to_bytes(4,"little")+
          bytes([len(proof["branch"])])+b"".join(bytes.fromhex(x) for x in proof["branch"])+bytes.fromhex(anchor["raw"]))
    a.control("fa_anchor",proof=wire.hex());a.generate(1)
    info=a.rpc("getanchorinfo")
    assert info["pending_count"]>0,info
    for _ in range(2):finalize(a,core)
    info=a.rpc("getanchorinfo")
    assert info["anchor_security_milestone"] and info["btc_observed_checkpoint_height"]>=core.rpc("getblockheader",[anchor["block"]])["height"],info
    return info

def submit_reserve(a,core,transaction,fields,nullifier_outpoint=None):
    relay(a,core)
    observed=observe_bitcoin(a,core)
    fields=dict(fields,**core.proof(transaction))
    if nullifier_outpoint:
        witness=a.rpc("getbtcveldmintstatus",[nullifier_outpoint])
        assert not witness["consumed"]
        fields["nullifier_proof"]=witness["proof_hex"]
    a.control("fa_reserve",**fields);a.generate(1)
    return observed

def accounting(a,expected_supply,expected_reserve,expected_open=0):
    peg=a.rpc("getpeginfo");coherent=a.rpc("getbtcveldsupply")
    assert peg["reserve_accounting_holds"],peg
    assert peg["supply_sats"]==expected_supply and peg["reserve_value_sats"]==expected_reserve,peg
    assert peg["open_redemption_principal_sats"]==expected_open,peg
    assert coherent["supply_sats"]==expected_supply,coherent
    return peg

def scenario(a,core,custody,report,binary,directory,nodes):
    checks=report["checks"]
    b=Node(binary,directory/"node-b");nodes.append(b)
    b.control("connect",port=a.p2p)
    wait_admission(a);wait_admission(b)
    a.control("synchronize");b.control("synchronize")
    a.generate(3);wait_equal(a,b);b.stop()
    wait_admission(a,require_peer=False)
    checks["authenticated_loopback_peer_initial_convergence"]=True
    advance(a,None,1000)
    for index in range(1,8):
        a.control("fund",to=index,amount="60");a.generate(1)
    for index in range(1,8):
        a.control("register",wallet=index);a.generate(1)
        governance=a.rpc("getgovernanceinfo")
        assert governance["governance_active"]==(index>=5),governance
    a.control("stake",amount="50");a.generate(1)
    assert a.rpc("getbalance",[a.ready["addresses"][0]])["staked_veld"]==50
    checks["seven_real_bonds_five_validator_governance_and_stake"]=True
    advance(a,None,1920)
    snapshot=a.rpc("getfinalitysnapshot")["snapshot"]
    assert len(snapshot["members"])==7 and not snapshot["active"],snapshot
    checks["first_qualified_epoch_at_1920"]=True
    advance(a,None,2400)
    assert a.rpc("getfinalitysnapshot")["snapshot"]["active"]
    assert not a.rpc("getanchorinfo")["anchor_configured"]
    checks["second_qualified_epoch_enables_finality"]=True
    advance(a,None,2878)
    assert not a.rpc("getanchorinfo")["anchor_configured"]
    a.generate(1)
    assert a.rpc("getanchorinfo")["anchor_configured"]
    assert a.rpc("getpeginfo")["supply_sats"]==0
    a.generate(1)
    assert a.rpc("getanchorinfo")["anchor_configured"]
    report["activation_state"]=a.control("status")
    checks["original_2880_upgrade_and_third_epoch_anchor_warmup"]=True
    finalize(a,core,2880)
    assert a.rpc("getpeginfo")["finality_active"]
    checks["seven_validator_real_prevote_and_precommit_qc"]=True

    # First actual Bitcoin custody deposit, accepted and signed by Core's wallet.
    fields={"wallet":0,"operation":"OPEN","reserve_value":2000000,"mint_amount":2000000}
    auth=a.control("fa_auth",**fields)
    opened=core.send([core.fund(2001000)],[{custody["address"]:btc(2000000)},{"data":auth["payload"]}])
    core.rpc("lockunspent",[False,[{"txid":opened["txid"],"vout":0}]])
    submit_reserve(a,core,opened,fields,opened["txid"]+":0")
    report["opened"]=accounting(a,2000000,2000000)
    mint=a.rpc("getbtcveldmintstatus",[opened["txid"]+":0"])
    assert mint["consumed"] and mint["minted"] and mint["count"]==1,mint
    assert a.rpc("gettokenbalance",["btcVELD",a.ready["addresses"][0]])==2000000
    checks["bitcoin_core_deposit_headers_anchors_observation_and_first_mint"]=True

    def tx(method,*params):
        value=a.control("fa_transaction",wallet=0,method=method,params=[str(p) for p in params])
        a.generate(1)
        return value
    # Consolidate genuine mining rewards into an ordinary self-payment first.
    a.control("fund",to=0,amount="250");a.generate(1)
    checks["ordinary_self_payment_consolidates_mining_rewards"]=True
    tx("prepareammseed",100*100000000,200000)
    pool=a.rpc("getammpool")
    assert pool["reserve_veld"]==100*100000000 and pool["reserve_btcveld"]==200000 and pool["locked_lp"]>0,pool
    anchor=(pool["anchor_veld"],pool["anchor_btcveld"])
    before_lp=a.rpc("getammlp",[a.ready["addresses"][0]])["lp"]
    tx("prepareammadd",10*100000000)
    assert a.rpc("getammlp",[a.ready["addresses"][0]])["lp"]>before_lp
    for direction,amount in [("v2b",100000000),("b2v",2000)]:
        before=a.rpc("getammpool")
        tx("prepareammswap",direction,amount)
        after=a.rpc("getammpool")
        assert after["reserve_veld"]*after["reserve_btcveld"]>=before["reserve_veld"]*before["reserve_btcveld"]
        assert (after["anchor_veld"],after["anchor_btcveld"])==anchor
    lp=a.rpc("getammlp",[a.ready["addresses"][0]])["lp"]
    tx("prepareammremove",lp//10)
    assert a.rpc("getammlp",[a.ready["addresses"][0]])["lp"]==lp-lp//10
    report["amm_state"]=a.rpc("getammpool")
    accounting(a,2000000,2000000)
    checks["amm_authorized_seed_add_both_swap_directions_remove_and_locked_lp"]=True

    # Add backing by spending the current reserve and one real pending deposit.
    pending=core.send([core.fund(502000)],[{custody["address"]:btc(501000)},
                      {"data":("btcVELD:"+a.ready["addresses"][0]).encode().hex()}])
    core.rpc("lockunspent",[False,[{"txid":pending["txid"],"vout":0}]])
    fields={"wallet":0,"operation":"DEPOSIT","reserve_value":2500000,"mint_amount":500000,
            "pending_txid":internal(pending["txid"]),"pending_vout":0,"pending_value":501000}
    auth=a.control("fa_auth",**fields)
    deposited=core.send([dict(opened,vout=0),dict(pending,vout=0)],
                       [{custody["address"]:btc(2500000)},{"data":auth["payload"]}])
    core.rpc("lockunspent",[False,[{"txid":deposited["txid"],"vout":0}]])
    submit_reserve(a,core,deposited,fields,pending["txid"]+":0")
    report["deposited"]=accounting(a,2500000,2500000)
    assert a.rpc("getbtcveldmintstatus",[pending["txid"]+":0"])["minted"]
    assert core.rpc("gettxout",[opened["txid"],0]) is None
    checks["second_deposit_rolls_exact_reserve_and_mints_net_bitcoin_backing"]=True

    core.rpc("createwallet",["recipient"])
    destination=core.rpc("getnewaddress",["redemption-destination","bech32"],wallet="recipient")
    destination_script=core.rpc("getaddressinfo",[destination],wallet="recipient")["scriptPubKey"]
    tx("preparetokenredeem",100000,destination_script)
    accounting(a,2400000,2500000,100000)
    feed=a.rpc("getbtcveldredeems")
    assert len(feed["redeems"])==1,feed
    request=feed["redeems"][0];request_id=request["txid"]
    assert a.control("fa_request",request_id=request_id)["status"]==1
    finalize(a,core)
    assert a.rpc("getbtcveldredeems")["final_height"]>=request["block"]
    fields={"wallet":0,"operation":"PAYOUT","reserve_value":2400000,"mint_amount":0,"request_id":request_id}
    auth=a.control("fa_auth",**fields)
    paid=core.send([dict(deposited,vout=0),core.fund(1000)],
                  [{custody["address"]:btc(2400000)},{destination:btc(100000)},{"data":auth["payload"]}])
    core.rpc("lockunspent",[False,[{"txid":paid["txid"],"vout":0}]])
    submit_reserve(a,core,paid,fields)
    report["paid"]=accounting(a,2400000,2400000)
    fulfilled=a.control("fa_request",request_id=request_id)
    assert fulfilled["status"]==5 and fulfilled["fulfilled_txid"]==internal(paid["txid"]),fulfilled
    assert round(core.rpc("gettxout",[paid["txid"],1])["value"]*100000000)==100000
    assert round(core.rpc("getbalances",wallet="recipient")["mine"]["trusted"]*100000000)==100000
    assert round(core.rpc("gettxout",[paid["txid"],0])["value"]*100000000)==2400000
    report["request"]=dict(fulfilled,request_id=request_id)
    checks["redeem_burn_finality_bitcoin_payout_and_archived_fulfillment"]=True

    # The original upgrade has already executed at 2880. Exercise the new
    # fixes at a distinct synthetic boundary, with populated disposable state.
    advance(a,None,3359)
    before_migration=accounting(a,2400000,2400000)
    before_pool=a.rpc("getammpool")
    a.generate(1)
    after_migration=accounting(a,2400000,2400000)
    assert a.control("fa_request",request_id=request_id)==fulfilled
    assert a.rpc("getammpool")["lp_supply"]==before_pool["lp_supply"]
    checks["new_fixes_at_separate_3360_preserve_populated_balances_and_obligations"]=True
    report["migration_state"]={"before":before_migration,"after":after_migration}
    final=a.control("status");report["final_state"]=final
    a.control("export_history",name="final-history.bin")
    a.stop()
    restarted=Node(binary,a.directory,"-restart");nodes.append(restarted)
    assert restarted.ready["digest"]==final["digest"] and restarted.ready["height"]==final["height"]
    assert restarted.control("fa_request",request_id=request_id)==fulfilled
    assert restarted.rpc("getbtcveldmintstatus",[pending["txid"]+":0"])["minted"]
    checks["populated_first_activation_restart_and_archive_readback"]=True
    fresh=Node(binary,directory/"node-fresh");nodes.append(fresh)
    replay=fresh.control("import_history",name="final-history.bin")
    assert replay["digest"]==final["digest"] and replay["imported_height"]==final["height"],replay
    fresh.control("connect",port=restarted.p2p);wait_equal(fresh,restarted)
    assert fresh.control("fa_request",request_id=request_id)==fulfilled
    assert fresh.rpc("getammpool")["reserve_btcveld"]==report["amm_state"]["reserve_btcveld"]
    checks["fresh_full_validation_replay_and_p2p_state_convergence"]=True
    report["bitcoin_final_height"]=core.rpc("getblockcount")
    report["bitcoin_connections"]=core.rpc("getnetworkinfo")["connections"]
    print("PASS first activation normal-flow integration checks="+str(len(checks)),flush=True)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--bitcoind",type=Path,required=True)
    p.add_argument("--compiler",type=Path,default=Path(r"C:\msys64\clang64\bin\clang++.exe"))
    p.add_argument("--prepare-only",action="store_true")
    args=p.parse_args()
    directory=args.output_dir.resolve();directory.mkdir(parents=True,exist_ok=False)
    report={"status":"running","original_upgrade_height":2880,"test_migration_height":3360,"checks":{},"profile":{"bond_veld":50,"public_bond_veld":10000,
        "validator_count":7,"registration_maturity":480,"finality_warmup_epochs":2,"anchor_warmup_epochs":3,"quorum":5,
        "bitcoin":"regtest","transport":"loopback","production_migration_activation":0}}
    core=None;nodes=[]
    try:
        core=Bitcoin(args.bitcoind.resolve(),directory/"bitcoin")
        fixture=directory/"custody-public.json"
        if fixture.exists():custody=json.loads(fixture.read_text())
        else:
            address=core.rpc("getnewaddress",["reserve-custody","bech32"])
            custody={"address":address,"script":core.rpc("getaddressinfo",[address])["scriptPubKey"]}
            fixture.write_text(json.dumps(custody,indent=2))
        while core.rpc("getblockcount")<2160:
            core.mine(min(256,2160-core.rpc("getblockcount")))
        checkpoint=core.rpc("getblockheader",[core.rpc("getblockhash",[2016])])
        raw=core.rpc("getblockheader",[checkpoint["hash"],False])
        assert sha256d(bytes.fromhex(raw)).hex()==internal(checkpoint["hash"])
        assert checkpoint["confirmations"]>=144 and checkpoint["height"]==2016
        checkpoint["raw_header"]=raw
        checkpoint["prev10"]=[core.rpc("getblockheader",[core.rpc("getblockhash",[h])])["time"] for h in range(2006,2016)]
        (directory/"bitcoin-checkpoint.json").write_text(json.dumps(checkpoint,indent=2))
        binary=compile_node(directory,custody["script"],args.compiler,checkpoint)
        report["binary_sha256"]=hashlib.sha256(binary.read_bytes()).hexdigest()
        if args.prepare_only:
            report["status"]="build_pass"
            return
        a=Node(binary,directory/"node-a");nodes.append(a)
        scenario(a,core,custody,report,binary,directory,nodes)
        report["status"]="integration_pass"
    except BaseException as error:
        report["status"]="integration_failed"
        report["failure"]={"type":type(error).__name__,"message":str(error)}
        traceback.print_exc()
        raise
    finally:
        for node in reversed(nodes):node.stop()
        if core:core.stop()
        report["stopped"]=all(n.process.poll() is not None for n in nodes) and (core is None or core.process.poll() is not None)
        (directory/"first-activation-results.json").write_text(json.dumps(report,indent=2)+"\n")
if __name__=="__main__":main()
