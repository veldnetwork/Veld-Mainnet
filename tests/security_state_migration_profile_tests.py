"""Compile the migration/profile contracts without running a public node."""
from pathlib import Path
import argparse, json, subprocess

parser=argparse.ArgumentParser()
parser.add_argument("--compiler",required=True)
parser.add_argument("--output-dir",type=Path,required=True)
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
out=args.output_dir.resolve(); out.mkdir(parents=True,exist_ok=True)
source=out/"profile-contract.cpp"
source.write_text('''#include "consensus/security_state_migration.h"
static_assert(veld::CONSENSUS_SECURITY_UPGRADE_HEIGHT == 2880);
static_assert(veld::SECURITY_STATE_MIGRATION_HEIGHT == EXPECT_MIGRATION_HEIGHT);
static_assert(!veld::SecurityStateMigrationActive(2879));
static_assert(veld::SecurityStateMigrationActive(2880) ==
              (EXPECT_MIGRATION_HEIGHT != 0 && EXPECT_MIGRATION_HEIGHT <= 2880));
static_assert(EXPECT_MIGRATION_HEIGHT == 0 ||
              !veld::SecurityStateMigrationActive(EXPECT_MIGRATION_HEIGHT - 1));
static_assert(veld::SecurityStateMigrationActive(EXPECT_MIGRATION_HEIGHT) ==
              (EXPECT_MIGRATION_HEIGHT != 0));
''')
public=["-DVELD_MAINNET_POW","-DVELD_PUBLIC_RELEASE","-DVELD_PUBLIC_MAINNET"]
isolated=["-include",str(root/"tests/security_state_migration_profile.h")]
cases=[
    ("unscheduled_default",[],0,True),
    ("scheduled_public",public,3840,True),
    ("isolated_combined_2880",isolated,2880,True),
    ("reject_unscoped_height_override",["-DVELD_SECURITY_STATE_MIGRATION_TEST_HEIGHT=2880"],2880,False),
    ("reject_public_test_override",public+isolated,2880,False),
    ("reject_unscoped_local_transport",["-DVELD_LOCAL_TEST_NETWORK"],0,False),
]
results=[]
for name,flags,height,allowed in cases:
    command=[args.compiler,"-std=c++20","-fsyntax-only","-I"+str(root/"include"),
             "-DEXPECT_MIGRATION_HEIGHT="+str(height),*flags,str(source)]
    result=subprocess.run(command,capture_output=True,text=True,encoding="utf-8",errors="replace")
    (out/(name+".log")).write_text(result.stdout+result.stderr)
    passed=(result.returncode==0)==allowed
    if not allowed:
        passed=passed and ("isolated" in result.stderr or "public releases" in result.stderr)
    results.append(dict(name=name,passed=passed,expected_compile_success=allowed,exit_code=result.returncode,command=command))
    assert passed, name
(out/"profile-results.json").write_text(json.dumps(results,indent=2)+"\n")
print("PASS security_state_migration_profile_tests cases="+str(len(results)))
