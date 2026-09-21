"""Strict, credential-free projection for cross-origin public Pool tabs."""
import re
from .protocol import require

def overview(value):
    require(type(value) is dict and type(value.get('version')) is int and value['version']==1,'overview version')
    def number(item):
        require(type(item) is str and re.fullmatch(r'0|[1-9][0-9]{0,79}',item),'overview integer')
        return item
    def counts(item,keys):
        require(type(item) is dict,'overview counters')
        return {k:number(item.get(k)) for k in keys}
    out={'version':1,'blocks_won':number(value.get('blocks_won')),
         'reward_totals':counts(value.get('reward_totals'),('mining','comine_payout','staking_distribution')),
         'payments':counts(value.get('payments'),('paid_units','confirmed_transactions'))}
    work=value.get('work');require(type(work) is dict and work.get('method')=='verified-expected-work','work estimator')
    require(type(work.get('warming_up')) is bool,'work warmup flag')
    out['work']={**counts(work,('window_seconds','sample_shares','bucket_seconds')),
        'hashrate_hs':None if work.get('hashrate_hs') is None else number(work['hashrate_hs']),
        'warming_up':work['warming_up'],'method':'verified-expected-work'}
    require(int(out['work']['window_seconds'])<=600 and out['work']['bucket_seconds']=='10','work window bounds')
    rows=value.get('recent_blocks');require(type(rows) is list and len(rows)<=12,'public block bound')
    out['recent_blocks']=[]
    for row in rows:
        require(type(row) is dict and type(row.get('hash')) is str and re.fullmatch('[a-f0-9]{64}',row['hash']),'public block identity')
        require(row.get('state') in ('pending','available','orphaned'),'public block state')
        out['recent_blocks'].append({**counts(row,('height','amount_units','confirmations')),'hash':row['hash'],'state':row['state']})
    return out

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
    if 'overview' in value:out['overview']=overview(value['overview'])
    queue=value.get('verification_queue')
    if queue is not None:
        require(type(queue) is dict and all(type(queue.get(k)) is int and 0<=queue[k]<=256 for k in ('waiting','capacity')),'public queue')
        out['verification_queue']={k:queue[k] for k in ('waiting','capacity')}
    return {'ok':True,'result':out}
