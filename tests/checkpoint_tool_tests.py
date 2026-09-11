"""Verify the actual native checkpoint tool using signed public data."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile

tool=Path(sys.argv[1]).resolve()
root=Path(__file__).resolve().parents[1]
fixture=json.loads((root/'tests/fixtures/mainnet-checkpoint.json').read_bytes())
checks=0
with tempfile.TemporaryDirectory() as folder:
    path=Path(folder)/'feed.json'
    def verify(value, expected, count=1):
        global checks
        path.write_text(json.dumps(value))
        result=subprocess.run([str(tool),'verify',str(path),str(count)],capture_output=True,timeout=15)
        assert (result.returncode==0)==expected, 'Native checkpoint verification result mismatch'
        checks+=1
    verify(fixture,True)
    verify(fixture,False,2)
    for field,value in [('height',2801),('hash','a'*64),('signed_at',fixture[0]['signed_at']+1),('sig','0'*6618)]:
        verify([dict(fixture[0],**{field:value})],False)
    verify([fixture[0],fixture[0]],False,2)
    verify([dict(fixture[0],signed_at=1)],False)
    path.write_bytes(b'invalid encrypted keystore')
    result=subprocess.run([str(tool),'identity',str(path)],input=b'test-password-must-not-appear\n',capture_output=True,timeout=15)
    assert result.returncode!=0 and b'test-password-must-not-appear' not in result.stdout+result.stderr
    checks+=1
print(json.dumps(dict(passed=True,native_checks=checks)))
