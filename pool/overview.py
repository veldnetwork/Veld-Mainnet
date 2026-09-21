"""Credential-free display projections. Never used for money or work admission.

Lifetime totals rebuild from the journal; recent rows and live rate buckets are
bounded. A restart deliberately warms the rate estimate from new verified work.
"""
from collections import deque
from fractions import Fraction
import time
from .accounting import expected_work

CATEGORIES=('mining','comine_payout','staking_distribution')

class IncomeOverview:
    def __init__(self):
        self.totals={key:0 for key in CATEGORIES};self.blocks=0;self.recent={}

    def update(self,old,new):
        for sign,value in ((-1,old),(1,new)):
            if value and value.get('state') in ('pending','available'):
                category=value.get('category','mining')
                if category in self.totals:
                    self.totals[category]+=sign*int(value.get('amount','0'))
                    if category=='mining':self.blocks+=sign
        if new.get('category','mining')=='mining' and len(new['id'])==64:
            self.recent[new['id']]={'hash':new['id'],'height':str(new['height']),
                'amount_units':str(new.get('amount','0')),'state':new['state']}
            self.recent=dict(sorted(self.recent.items(),key=lambda p:int(p[1]['height']),reverse=True)[:12])

    def snapshot(self,height):
        rows=[]
        for value in self.recent.values():
            row=dict(value);row['confirmations']=str(max(0,height-int(row['height'])+1)) if row['state']!='orphaned' else '0'
            rows.append(row)
        return {'blocks_won':str(self.blocks),'reward_totals':{k:str(v) for k,v in self.totals.items()},'recent_blocks':rows}

class PaymentOverview:
    def __init__(self):self.paid=0;self.count=0
    def update(self,old,new):
        for sign,value in ((-1,old),(1,new)):
            if value and value.get('state')=='confirmed':
                self.paid+=sign*sum(int(v) for v in value['deductions'].values());self.count+=sign
    def snapshot(self):return {'paid_units':str(self.paid),'confirmed_transactions':str(self.count)}

class WorkOverview:
    WINDOW=600
    BUCKET=10
    def __init__(self,clock=time.monotonic):
        self.clock=clock;self.started=clock();self.bins=deque()
    def _prune(self,now):
        while self.bins and self.bins[0][0] < now-self.WINDOW:self.bins.popleft()
    def add(self,target):
        now=self.clock();self._prune(now);bucket=int(now//self.BUCKET)*self.BUCKET
        if not self.bins or self.bins[-1][0]!=bucket:self.bins.append([bucket,Fraction(),0])
        self.bins[-1][1]+=expected_work(target);self.bins[-1][2]+=1
    def snapshot(self):
        now=self.clock();self._prune(now);seconds=min(self.WINDOW,max(0,int(now-self.started)))
        weight=sum((row[1] for row in self.bins),Fraction());count=sum(row[2] for row in self.bins)
        # Account for the partially expired ten-second bucket conservatively.
        value=weight/max(1,seconds)
        return {'hashrate_hs':str(value.numerator//value.denominator) if seconds>=60 else None,
                'window_seconds':str(seconds),'sample_shares':str(count),'bucket_seconds':str(self.BUCKET),
                'method':'verified-expected-work','warming_up':seconds<60}
