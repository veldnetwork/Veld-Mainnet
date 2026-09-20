"""External process fault harness around the real service, not a replacement ledger.

Always runs in an isolated namespace. Uses native signing and actual node RPC.
Its only fault operations terminate this process or discard a real response.
"""
import os
from pathlib import Path
import sys
from .. import service
from ..backend import Node
from ..payments import Payments
from .isolation import require_isolated_network


def main():
    if len(sys.argv)!=5:raise SystemExit('FAULT MARKER --config PRIVATE_CONFIG required')
    fault,marker=sys.argv[1:3];sys.argv=[sys.argv[0],*sys.argv[3:]]
    require_isolated_network()
    allowed={'before_sign','after_native_signature','after_signed_journal','after_broadcast',
             'after_confirmation_before_journal','after_confirmation_journal','lost_response'}
    if fault not in allowed:raise SystemExit('unknown controlled fault')
    marker=Path(marker)
    if marker.exists():raise SystemExit('fault marker already exists')
    fired=False
    def hit():
        nonlocal fired
        if fired:return False
        fired=True
        fd=os.open(marker,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as file:file.write(fault+'\n');file.flush();os.fsync(file.fileno())
        if fault!='lost_response':os._exit(77)
        return True
    original_sign=Payments.sign;original_record=Payments.record;original_rpc=Node.call
    original_run=service.subprocess.run
    def sign(self,identity):
        if fault=='before_sign':hit()
        return original_sign(self,identity)
    def record(self,kind,value):
        result=original_record(self,kind,value)
        if fault=='after_signed_journal' and kind=='payment_signed':hit()
        if fault=='after_confirmation_journal' and kind=='payment_state' and value.get('state')=='confirmed':hit()
        return result
    def rpc(self,method,*parameters):
        result=original_rpc(self,method,*parameters)
        if method=='sendrawtransaction':
            if fault=='after_broadcast':hit()
            if fault=='lost_response' and hit():raise OSError('injected loss of actual accepted broadcast response')
        if method in ('getrawtransaction','gettransaction') and isinstance(result,dict) and result.get('confirmations',0)>0:
            if fault=='after_confirmation_before_journal' and result.get('coinbase') is False:hit()
        return result
    def run(command,*args,**kwargs):
        result=original_run(command,*args,**kwargs)
        if fault=='after_native_signature' and len(command)==3 and result.returncode==0:hit()
        return result
    Payments.sign=sign;Payments.record=record;Node.call=rpc;service.subprocess.run=run
    service.main()

if __name__=='__main__':main()
