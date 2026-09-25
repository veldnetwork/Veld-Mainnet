"""Ephemeral P-256 signed commands for the native, non-mining lifecycle test."""
from pathlib import Path
import base64, hashlib, json, os, re, sys, time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes

def create(root):
    root.mkdir(exist_ok=False)
    b64=lambda x:base64.urlsafe_b64encode(x).decode().rstrip('=')
    signer=ec.generate_private_key(ec.SECP256R1())
    n=signer.public_key().public_numbers();x=b64(n.x.to_bytes(32,'big'));y=b64(n.y.to_bytes(32,'big'))
    kid=hashlib.sha256(f'VELD_PORTAL_KEY_V1\n{x}\n{y}'.encode()).hexdigest()
    now=int(time.time())
    for seq,(name,action) in enumerate((('pool.start','pool.start'),('pool.start-ready','pool.start'),('pool.start-actual','pool.start'),('pool.stop','pool.stop'),('pool.restart','pool.start'),('pool.final-stop','pool.stop')),1):
        nonce=b64(os.urandom(16))
        envelope=f'VELD_PORTAL_COMMAND_V3\n17\n{seq}\n{now}\n{now+180}\n{nonce}\n{action}\n{{}}'
        r,s=decode_dss_signature(signer.sign(envelope.encode(),ec.ECDSA(hashes.SHA256())))
        order=int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',16)
        command=dict(id=seq,sequence=seq,issued_at=now,expires_at=now+180,nonce=nonce,action=action,payload={},key_id=kid,signature=b64(r.to_bytes(32,'big')+min(s,order-s).to_bytes(32,'big')))
        reply=dict(portal_protocol=4,device_id=17,paired=True,pair_code=None,pair_expires=0,report_interval=5,command_key=dict(id=kid,x=x,y=y),command=command)
        (root/(name+'.json')).write_text(json.dumps(reply))
    source=Path(__file__).resolve().parents[1]
    version=int(re.search(r'VELD_ADDR_VERSION_MAINNET\s*=\s*(0x[0-9a-fA-F]+)',(source/'include/core/script.h').read_text()).group(1),16)
    payload=bytes([version])+os.urandom(20)
    checksum=hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number=int.from_bytes(payload+checksum,'big');address='';alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    while number:number,r=divmod(number,58);address=alphabet[r]+address
    (root/'client.json').write_text(json.dumps(dict(endpoint='https://pool-fixture.invalid',payout_address=address,ca_file='',threads='2')))

if __name__=='__main__':create(Path(sys.argv[1]))
