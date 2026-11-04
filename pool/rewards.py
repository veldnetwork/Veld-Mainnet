"""Frozen contribution windows for actual chain lottery and staking receipts.

The final seed block is deliberately excluded: seal before issuing work at D-1,
using contributions at [previous D+1,D-2]. A missed seal quarantines income.
Neither a payment-time participant list nor a sender-supplied marker is evidence.
"""

from fractions import Fraction
from .accounting import allocate_policy, window_weights, text
from .protocol import require, units, hex64


class Rewards:
    def __init__(self, pool, window_blocks, yield_blocks):
        self.pool, self.node = pool, pool.node
        require(type(window_blocks) is int and window_blocks >= 3, 'lottery window policy')
        require(type(yield_blocks) is int and yield_blocks >= 3, 'staking window policy')
        self.intervals = {'comine_payout': window_blocks, 'staking_distribution': yield_blocks}
        self.seals = {}
        self.quarantined = {}
        self.observed = {}
        for event in pool.journal.events():
            self.apply(event['kind'], event['payload'])

    def apply(self, kind, value):
        if kind == 'reward_seal':
            self.seals[value['id']] = value
        elif kind == 'reward_quarantine':
            self.quarantined[value['id']] = value
        elif kind == 'reward_observed':
            self.observed[value['id']] = value

    def record(self, kind, value):
        self.pool.journal.append(kind, value)
        self.apply(kind, value)

    def seal(self, height, parent):
        # Caller holds pool.lock. This runs BEFORE fetching a template at D-1.
        # The authoritative parent height/hash is checked again by work().
        for category, interval in self.intervals.items():
            if (height + 1) % interval:
                continue
            draw = height + 1
            identity = category + ':' + str(draw) + ':' + hex64(parent)
            if identity in self.seals:
                continue
            self.record(
                'reward_seal',
                {
                    'id': identity,
                    'category': category,
                    'draw': draw,
                    'first': max(1, draw - interval + 1),
                    'last': draw - 2,
                    'parent': parent,
                    'cutoff': self.pool.journal.sequence,
                    'policy': 'verified-window-shared-yield-share-policy-v2',
                },
            )

    def reconcile(self):
        # Bounded native address index pagination. Each tick processes at most
        # 50 rows; the cursor survives within this process and restarts at tip.
        cursor = getattr(self, 'cursor', '')
        page = self.node.call('getaddresshistory', self.pool.pool_address, '50', cursor)
        require(
            isinstance(page, dict)
            and isinstance(page.get('entries'), list)
            and len(page['entries']) <= 50,
            'reward history shape',
        )
        self.cursor = page['next_cursor'] if page.get('has_more') else ''
        for row in page['entries']:
            category = row.get('type')
            if category not in self.intervals:
                continue
            height = row['block_height']
            require(type(height) is int and height > 0, 'reward height')
            block = hex64(self.node.call('getblockhash', str(height)))
            txid = hex64(row['txid'])
            identity = block + ':' + txid
            if identity in self.pool.incomes:
                continue
            # The native index classifies validated protocol funding inputs;
            # exact values come from the canonical transaction, never decimals.
            tx = self.node.call('gettransaction', txid, block)
            require(
                tx.get('block_hash') == block and tx.get('coinbase') is False, 'reward inclusion'
            )
            outputs = [
                o
                for o in tx['vout']
                if o['address'] == self.pool.pool_address and units(o['value_units']) > 0
            ]
            if not outputs:
                continue
            amount = sum(units(o['value_units']) for o in outputs)
            parent = self.node.call('getblockhash', str(height - 2))
            seal = self.seals.get(category + ':' + str(height) + ':' + parent)
            if seal is None:
                if identity not in self.quarantined:
                    self.record(
                        'reward_quarantine',
                        {
                            'id': identity,
                            'block': block,
                            'txid': txid,
                            'amount': str(amount),
                            'reason': 'no pre-result contribution seal',
                        },
                    )
                continue
            if self.pool.unresolved(seal['cutoff']):
                continue
            receipts = self.pool.receipts.select(
                status='verified', cutoff=seal['cutoff'], first=seal['first'], last=seal['last']
            )
            weights = window_weights(
                receipts, seal['first'], seal['last'], seal['cutoff'], fee_policy=True
            )
            if not weights:
                if identity not in self.quarantined:
                    self.record(
                        'reward_quarantine',
                        {
                            'id': identity,
                            'block': block,
                            'txid': txid,
                            'amount': str(amount),
                            'reason': 'no verified contributors',
                        },
                    )
                continue
            credits, fee = allocate_policy(amount, weights)
            self.pool.record(
                'income',
                {
                    'id': identity,
                    'block': block,
                    'height': height,
                    'txid': txid,
                    'outputs': [{'vout': o['n'], 'units': o['value_units']} for o in outputs],
                    'amount': str(amount),
                    'category': category,
                    'policy': seal['policy'],
                    'seal': seal['id'],
                    'cutoff': seal['cutoff'],
                    'credits': {a: text(v) for a, v in credits.items()},
                    'operator_fee': text(fee),
                    'state': 'pending',
                },
            )

    def status(self):
        return {
            'sealed_windows': str(len(self.seals)),
            'quarantined_receipts': str(len(self.quarantined)),
            'staking_yield': 'Shared with verified pool contributors',
        }
