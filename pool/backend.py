import http.client
import ipaddress
import threading
import urllib.parse
from pathlib import Path
from .protocol import decode, encode, require, hex64, Refused, Busy, MAX_BLOCK_BYTES, MAX_RPC_BYTES
from .private_file import read_private

# The canonical builder checks the same readiness gates before construction,
# before publication and when issuing the final authorization. A transient
# loss of readiness at any of those stages supplies no usable work. Replay,
# independent validation and an unstable or expiring peer view can recover.
# Workers wait and request fresh fully checked work; authority/trust failures
# and writes retain their existing refusal behavior.
WORK_READINESS_REFUSALS=frozenset(
    prefix+reason
    for prefix in ('getblocktemplate refused: ',
                   'getblocktemplate closed before publication: ',
                   'getblocktemplate authorization refused: ')
    for reason in ('sync_incomplete','startup_replay_incomplete',
                   'independent_validation_incomplete','peer_view_unsafe'))

# Fixed operator diagnostics only: never log RPC parameters, credentials, raw
# responses or arbitrary node-provided text. These codes do not alter admission.
_TEMPLATE_REASONS=frozenset(('none','role_denied','node_not_running','unwired',
    'startup_replay_incomplete','independent_validation_incomplete','sync_incomplete',
    'snapshot_state_untrusted','durable_state_unproven','datadir_identity_unproven',
    'checkpoint_anchor_unproven','tip_unknown','runtime_closed','peer_view_unsafe',
    'subject_not_canonical','binding_missing','binding_mismatch'))

class NodeRefused(Refused):
    def __init__(self,method,error):
        super().__init__('node refused '+method+': '+str(error)[:300])
        self.diagnostic='node_rpc_refused'
        if method!='getblocktemplate':return
        message=error['message']
        for prefix,stage in (('getblocktemplate refused: ','initial'),
                ('getblocktemplate closed before publication: ','publication'),
                ('getblocktemplate authorization refused: ','authorization')):
            if error['code']==-32010 and message.startswith(prefix):
                reason=message[len(prefix):]
                if reason in _TEMPLATE_REASONS:self.diagnostic='template_'+stage+'_'+reason
                return
        if error['code']==-32603 and message=='getblocktemplate canonical builder binding or preflight failed':
            self.diagnostic='template_builder_preflight_failed'

class Node:
    """Private, pinned node connection. Never follows redirects or environment proxies."""
    def __init__(self, url, token_path, genesis):
        endpoint = urllib.parse.urlsplit(url)
        require(endpoint.scheme == 'http' and not endpoint.username and not endpoint.password and
                endpoint.path in ('', '/') and not endpoint.query and not endpoint.fragment, 'private RPC URL')
        require(ipaddress.ip_address(endpoint.hostname).is_loopback, 'RPC must be loopback')
        self.host, self.port = endpoint.hostname, endpoint.port
        require(self.port is not None and self.port > 1024, 'RPC port')
        self.token_path = Path(token_path)
        self.genesis = hex64(genesis)
        self.lock = threading.Lock()
        self.counter = 0

    def call(self, method, *parameters):
        # Token rotation is read for every request; stale cached authority is not used.
        token = read_private(self.token_path, 128).decode('ascii').strip()
        require(len(token) == 64 and all(c in '0123456789abcdef' for c in token), 'RPC credential unavailable')
        with self.lock:
            self.counter += 1
            identity = self.counter
        request = encode({'jsonrpc':'2.0','id':identity,'method':method,'params':list(parameters)})
        require(len(request) <= MAX_RPC_BYTES, 'RPC request limit')
        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            connection.request('POST', '/', request, {'Authorization':'Bearer '+token, 'Content-Type':'application/json'})
            response = connection.getresponse()
            raw = response.read(MAX_RPC_BYTES + 1)
            require(response.status == 200, 'RPC HTTP failure')
            result = decode(raw, MAX_RPC_BYTES)
            require(result.get('id') == identity, 'RPC response identity')
            if result.get('error') is not None:
                error=result['error']
                require(isinstance(error,dict) and type(error.get('code')) is int and
                        isinstance(error.get('message'),str),'RPC error schema')
                # Native work admission remains closed until the node is ready.
                # Tell workers to wait through replay/IBD and peer-view changes.
                # This returns no template or token and never opens admission.
                if method=='getblocktemplate' and error['code']==-32010 and error['message'] in WORK_READINESS_REFUSALS:
                    raise Busy('node work readiness incomplete; retry when safe')
                # A canonical commit closes the admission coordinator with
                # BindingMismatch while its acquired leases drain. Opening it
                # for template authorization can therefore refuse a READ even
                # though no caller-supplied binding is involved. Discard that
                # response and let the bounded worker backoff request fresh
                # fully checked authority. The final publication check also
                # compares an INTERNAL prior binding with fresh validation
                # generation; a generation change there needs a fresh read.
                # No caller-supplied binding is accepted by either path.
                # submitblock and transaction writes remain hard refusals.
                if (method=='getblocktemplate' and error['code']==-32010 and
                        error['message'] in {
                            'getblocktemplate authorization refused: binding_mismatch',
                            'getblocktemplate closed before publication: binding_mismatch'}):
                    raise Busy('node canonical work transition; request fresh work')
                if error['code']==-32005 or (error['code']==-32010 and
                    ('local-work-unavailable' in error['message'] or 'capacity' in error['message'])):
                    raise Busy('node temporarily unavailable; retry the same operation')
                raise NodeRefused(method,error)
            require('result' in result, 'RPC result missing')
            return result['result']
        except http.client.HTTPException as error:
            # During local listener startup/restart a TCP connection can close
            # mid-frame (and a Linux ephemeral port can self-connect to a not
            # yet listening port). No malformed HTTP is usable RPC evidence.
            # Surface a bounded retryable failure; writes are reconciled by
            # their existing exact-byte intent rather than retried here.
            raise Busy('node returned an incomplete or invalid HTTP response') from error
        finally:
            connection.close()

    def check_chain(self):
        require(self.call('getblockhash', '0') == self.genesis, 'wrong node genesis')
        require(self.call('getcompiledgenesis') == self.genesis, 'wrong compiled genesis')

    def require_transaction_index(self):
        # Complete canonical lookup is a prerequisite for funds-bearing pool
        # operations, including recovery after a fork or extended downtime.
        # The native bit means enabled AND operational, not just configured.
        info=self.call('getblockchaininfo')
        require(isinstance(info,dict) and info.get('txindex_enabled') is True,
                'pool signing requires an operational transaction index; enable --txindex and finish validation')

    def template(self, address, identity=None):
        self.check_chain()
        result = self.call('getblocktemplate', address,hex64(identity)) if identity is not None else self.call('getblocktemplate', address)
        require(isinstance(result, dict), 'template object')
        for key in ('block_hex','work_binding','work_token','work_ttl_ms','height','target','prev_block_hash'):
            require(key in result, 'template missing '+key)
        encoded = result['block_hex']
        # Bound before decoding or allocating a second full candidate copy.
        require(isinstance(encoded, str) and 184 <= len(encoded) <= 2*MAX_BLOCK_BYTES,
                'template encoding')
        try:
            raw = bytes.fromhex(encoded)
        except ValueError as error:
            raise Refused('template encoding') from error
        require(raw.hex() == encoded, 'template encoding')
        require(raw[80:88] == bytes(8), 'template nonce')
        hex64(result['target']); hex64(result['prev_block_hash'])
        require(type(result['height']) is int and result['height'] > 0, 'template height')
        require(type(result['work_ttl_ms']) is int and 0 < result['work_ttl_ms'] <= 10000, 'template deadline')
        require(result.get('reserved_miner_destination') is False,'protocol destination is not a pool identity')
        require(isinstance(result.get('miner_receipts'),list) and len(result['miner_receipts'])<=1,'canonical miner category')
        return result

    def renew(self,template,address):
        import hashlib
        header=bytes.fromhex(template['block_hex'][:176]);require(header[80:88]==bytes(8),'unsigned template nonce')
        identity=hashlib.sha256(hashlib.sha256(header).digest()).hexdigest()
        renewed=self.template(address,identity)
        require(renewed['block_hex']==template['block_hex'] and renewed['target']==template['target'] and
                renewed['height']==template['height'],'renewal must preserve exact candidate')
        return renewed

    def submit(self, template, nonce):
        raw = bytearray.fromhex(template['block_hex'])
        raw[80:88] = nonce.to_bytes(8, 'little')
        return self.call('submitblock', raw.hex(), template['work_binding'], template['work_token'])
