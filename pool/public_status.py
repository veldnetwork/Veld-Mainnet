"""Strict, credential-free projection for cross-origin public Pool tabs."""
import re
from .protocol import require

def public_status(response):
    require(type(response) is dict and response.get('ok') is True, 'health unavailable')
    value=response.get('result')
    require(type(value) is dict, 'health shape')
    out={}
    for key in ('active_accounts','verified_shares','reconciled_height'):
        item=value.get(key)
        if key=='reconciled_height' and item is None:
            out[key]=None;continue
        require(type(item) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}',item), 'public count')
        out[key]=item
    chain=value.get('chain')
    require(type(chain) is str and re.fullmatch('[a-f0-9]{64}',chain), 'public chain')
    out['chain']=chain
    for key in ('payments_enabled','co_mining_enabled'):
        require(type(value.get(key)) is bool, 'public flag');out[key]=value[key]
    out['status']='Service responding' if value.get('status')=='Service responding' else 'Reconciliation paused or starting'
    policy=value.get('payment_policy')
    if policy is not None:
        require(type(policy) is dict,'public policy shape')
        out['payment_policy']={}
        for key in ('minimum_units','batch_seconds','fee_ppm','revision'):
            item=policy.get(key)
            require(type(item) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}',item),'public policy value')
            out['payment_policy'][key]=item
    # Do not forward future coordinator fields, identifiers, endpoints, or errors.
    return {'ok':True,'result':out}
