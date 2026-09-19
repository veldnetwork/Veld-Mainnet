"""Independent unbounded-integer oracle for the shared native NMS interval."""
import argparse
import random
import subprocess

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',required=True)
    args=parser.parse_args();space=1<<256;rng=random.Random(9294)
    cases=[]
    targets=[1,2,(1<<254)-1,1<<254,(1<<254)+1,(1<<255)-1,space-1]
    targets += [rng.randrange(1,space) for _ in range(2048)]
    for target in targets:
        proofs=[0,target-1,target,target+1,4*target-1,4*target,4*target+1,space-1]
        proofs += [rng.randrange(space) for _ in range(4)]
        cases.extend((target,proof) for proof in proofs if 0<=proof<space)
    request=''.join(f'{target:064x} {proof:064x}\n' for target,proof in cases)
    result=subprocess.run([args.binary],input=request,text=True,capture_output=True,timeout=30,check=True)
    actual=result.stdout.splitlines()
    expected=[str(int(4*target<space and target<proof<=4*target)) for target,proof in cases]
    assert actual==expected,'NMS interval differs from exact integer reference'
    print(f'PASS {len(cases)} native NMS range comparisons, exact endpoints and overflow')

if __name__=='__main__':main()
