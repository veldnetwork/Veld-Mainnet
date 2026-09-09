"""Verify the isolated fixture cannot alter public bond/checkpoint profiles."""
from pathlib import Path
import argparse,json,subprocess
p=argparse.ArgumentParser()
p.add_argument("--compiler",required=True)
p.add_argument("--fixture-header",type=Path,required=True)
p.add_argument("--output-dir",type=Path,required=True)
a=p.parse_args()
root=Path(__file__).resolve().parents[1]
out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
source=out/"first-activation-contract.cpp"
source.write_text("""#include "consensus/finality_qc.h"
#include "consensus/btcveld_spv_params.h"
#include "consensus/security_state_migration.h"
static_assert(veld::CONSENSUS_SECURITY_UPGRADE_HEIGHT == 2880);
static_assert(veld::SECURITY_STATE_MIGRATION_HEIGHT == EXPECT_MIGRATION_HEIGHT);
static_assert(veld::finality::qc::BOND_PER_KEY_UNITS == EXPECT_BOND * veld::VELD_UNITS);
static_assert(veld::finality::qc::MIN_VALIDATOR_COUNT == 7);
static_assert(veld::finality::qc::REGISTRATION_MATURITY == 480);
static_assert(veld::finality::qc::EPOCH_BLOCKS == 480);
int main() {
#ifdef VELD_FIRST_ACTIVATION_NETWORK
    auto cp=veld::BtcVeldCheckpoint();
    return cp.height!=2016 || cp.time!=VELD_FIRST_ACTIVATION_BTC_CHECKPOINT_TIME ||
        cp.bits!=VELD_FIRST_ACTIVATION_BTC_CHECKPOINT_BITS ||
        veld::HashToHex(cp.hash)!=VELD_FIRST_ACTIVATION_BTC_CHECKPOINT_HASH;
#else
    return 0;
#endif
}
""")
public=["-DVELD_MAINNET_POW","-DVELD_PUBLIC_RELEASE","-DVELD_PUBLIC_MAINNET"]
isolated=["-DVELD_FIRST_ACTIVATION_NETWORK","-include",str(a.fixture_header.resolve()),
          "-include",str(root/"tests/security_first_activation_profile.h")]
cases=[("public_10000_bond",public,10000,3840,True),
       ("existing_regtest_10000_finality",["-include",str(root/"tests/security_state_migration_profile.h")],10000,2880,True),
       ("isolated_consistent_50_bond",isolated,50,3360,True),
       ("reject_unscoped_first_activation",["-DVELD_FIRST_ACTIVATION_NETWORK"],50,0,False),
       ("reject_public_first_activation",public+isolated,50,3360,False)]
results=[]
for name,flags,bond,height,allowed in cases:
    cmd=[a.compiler,"-std=c++20","-fsyntax-only","-I"+str(root/"include"),"-DEXPECT_BOND="+str(bond),"-DEXPECT_MIGRATION_HEIGHT="+str(height),*flags,str(source)]
    r=subprocess.run(cmd,capture_output=True,text=True,encoding="utf-8",errors="replace")
    (out/(name+".log")).write_text(r.stdout+r.stderr)
    passed=(r.returncode==0)==allowed
    if not allowed:passed=passed and ("isolated" in r.stderr or "public releases" in r.stderr)
    results.append({"case":name,"pass":passed,"exit_code":r.returncode,"command":cmd})
    assert passed,name
cmd=[a.compiler,"-std=c++20","-I"+str(root/"include"),"-DEXPECT_BOND=50","-DEXPECT_MIGRATION_HEIGHT=3360",*isolated,str(source),"-o",str(out/"checkpoint-contract.exe")]
subprocess.run(cmd,check=True,capture_output=True)
subprocess.run([str(out/"checkpoint-contract.exe")],check=True)
results.append({"case":"compiled_checkpoint_matches_core_fixture","pass":True})
(out/"profile-results.json").write_text(json.dumps(results,indent=2)+"\n")
print("PASS first activation profile contracts="+str(len(results)))
