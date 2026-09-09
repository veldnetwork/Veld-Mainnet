"""Source wiring controls complement the native and JavaScript boundary tests."""
from pathlib import Path
import argparse
import json
import shutil
import subprocess
root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--wallet-source", type=Path, help="isolated mutation fixture")
args = parser.parse_args()
def read(path): return (root / path).read_text(encoding="utf-8")
node = read("include/node/node.h")
main = read("src/veld-node.cpp")
pool = read("include/core/mempool.h")
explorer = read("include/network/explorer.h")
wallet = (args.wallet_source.read_text(encoding="utf-8") if args.wallet_source
          else read("include/network/ui_desktop.h"))

def region(source, start, end):
    begin = source.index(start)
    return source[begin:source.index(end, begin)]
watch = region(main, "if (stuck_secs >= STUCK_GRACE_SECS)", "// Detect sustained sibling-fork")
assert "::_exit(" not in watch and "RequestSnapshotRecoveryOnRestart" not in watch
for recovery in ["SetIBDComplete(false)", "SyncTCPIBDFlag()", "ClearRejectCache()", "ClearOrphanPool()", "TriggerTipReconcile()"]:
    assert recovery in watch
carrier = region(node, "bool DecodeDurableFinalityCarrier_", "void RetireDurableFinalityCarrier_")
assert "ResolveDurableCarrierClaim(r.decoded.qc, fin_state_.snapshots, out)" in carrier
assert "FinParseStatus::VALID" in carrier and "Phase::PRECOMMIT" in carrier
redeems = node[node.index("std::string BuildRedeemPageJson_"):]
assert redeems.index("AcquireConsensusTransitionGuard()") < redeems.index("index.ReadPage(") < redeems.index("FinalHeight()")
assert "if (publish_rpc_snapshots)\n            UpdateFinality_(block.height, chain_mutex_already_held);" in node
admission = region(pool, "AddResult AddImpl_", "std::vector<Transaction> GetAllTransactions()")
assert admission.index("if (Contains(txid)) return AddResult::DUPLICATE;") < admission.index("StakeTransactionValid(")
assert "if (entries_.count(key)) return AddResult::DUPLICATE;" in admission
assert "ValidateTransactionLocking(tx, false, &permanent_failure)" in admission
cache = region(admission, "bool permanent_failure = false;", "if (token_family)")
assert cache.index("if (permanent_failure)") < cache.index("recently_rejected_.insert(key)")
summary = region(explorer, "HttpResponse ServeMempoolPage()", "HttpResponse ServeValidatorsPage()")
assert "GetSummaryPage()" in summary
for body_operation in ["GetAllTransactions", "GetUTXO(", ".Serialize()"]:
    assert body_operation not in summary
history = region(explorer, 'if (resource == "blocks" && parts.size() == 5)', 'if (resource == "blocks")')
assert "std::vector<Block>" not in history and "GetBlockRange" not in history
assert "std::vector<std::string> descending_summaries" in history
assert "EXPLORER_BLOCK_PAGE_BODY_BUDGET" in history
classification = region(explorer, "std::string ClassifyUTXOSource", "Blockchain& chain_")
assert "chain_.GetBlock(" not in classification
assert classification.count("budget.Read(") == 2
address = region(explorer, "HttpResponse ServeAddress", "HttpResponse ServeTopologySnapshot")
assert address.count("ExplorerHistoryBudget source_budget") == 1
assert "ClassifyUTXOSource(u, source_budget)" in address
assert "source_labels.count(key)" in address and "sources_coherent" in address
lookup = region(explorer, "HttpResponse ServeTx", "static bool IsStrictBase58Address")
assert "budget.Read(chain_, *next)" in lookup
assert "progress.MarkAvailable(*next)" in lookup
assert "tx_lookup_progress_.size() >= 128" in lookup
assert "Transaction search is incomplete" in lookup
assert 'route == "block" || history || route == "tx"' in explorer
callers = {"autoConsolidateRun": "_veldAutomaticConsolidationBudget()",
           "doConsolidateUtxos": "_veldConsolidationBudget(64)"}
node_binary = shutil.which("node")
if not node_binary:
    raise RuntimeError("Node.js is required to parse the wallet functions")
parsed = subprocess.run(
    [node_binary, str(root / "tests/javascript_function_source.js")],
    input=json.dumps({"source": wallet, "names": list(callers)}),
    text=True, capture_output=True, check=False, timeout=30)
if parsed.returncode:
    raise RuntimeError("Wallet function extraction failed:\n" + parsed.stderr)
sections = json.loads(parsed.stdout)
assert set(sections) == set(callers), "both consolidation callers must be inspected"
for name, budget in callers.items():
    section = sections[name]
    assert budget in section, name + ": missing signing budget"
    assert "inputs_consolidated" not in section, name + ": unverified count"
    assert "verified_consolidation_inputs" in section, name + ": missing verified count"
    assert "signingBudget" in section, name + ": missing shared budget"
    print("CHECKED: " + name)
print("PASS: launcher-independent recovery, finality publication/retirement, cache classification, bounded Explorer routes, both consolidation callers")
