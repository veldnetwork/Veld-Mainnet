// Shared public Pool-tab view, embedded in Explorer and portal by the source generator.
// No account identifiers, cookies, pairing credentials or private tokens leave the page.
(function(){
  'use strict';
  var page=document.querySelector('.pool-page');
  if(!page||page.dataset.poolStatusController)return;
  page.dataset.poolStatusController='2';
  var busy=false, next=0, last=null, failed=false, lastAt=0, operator=null, operatorFailed=false;
  function put(id,value){var e=document.getElementById(id);if(e)e.textContent=value;}
  function render(){
    var paused=operator&&operator.state==='paused_by_operator';
    var stale=failed||paused;
    page.dataset.poolOperatorState=paused?'paused':'unknown';
    page.dataset.poolStatisticsState=last?(stale?'stale':'fresh'):'unavailable';
    var message=paused?'Pool mining is paused by the operator. New work and payouts are stopped.':
      failed?'The statistics refresh is delayed. This does not confirm a pool outage. Retrying automatically.':
      last?last.status:'Connecting to Veld Pool…';
    if(paused&&operatorFailed)message+=' The operator notice could not be refreshed.';
    if(lastAt)message+=(stale?' Last received ':' Updated ')+new Date(lastAt).toLocaleString()+'.';
    if(stale&&lastAt)message+=' Figures below are the last received values.';
    put('pool-public-status',message);
    ['active_accounts','verified_shares','reconciled_height'].forEach(function(k){
      put('pool-public-'+k,last&&last[k]!==null?BigInt(last[k]).toLocaleString():'—');
    });
    put('pool-public-payments',paused?'Paused':!last?'Unknown':(failed?'Last reported: ':'')+(last.payments_enabled?'Enabled':'Not enabled'));
    put('pool-public-comining',paused?'Paused':!last?'Unknown':(failed?'Last reported: ':'')+(last.co_mining_enabled?'Participating':'Not participating yet'));
    put('pool-public-comining-note',paused?'Pool participation is paused. Earlier earned rewards remain recorded.':
      last?(failed?'Last reported: ':'')+(last.co_mining_enabled?'The pool is participating in co-mining. Only confirmed winnings create earnings.':'The pool needs 1,000 VELD staked to qualify for co-mining.'):
      'Co-mining participation has not loaded yet.');
    var intro=page.querySelector('.pool-intro');if(intro)intro.textContent='Pool activity, setup and rewards.';
    page.querySelectorAll('h3').forEach(function(h){if(h.textContent==='Start pool mining'||h.dataset.poolSetup){h.dataset.poolSetup='true';h.textContent=paused?'Pool setup for when mining resumes':'Start pool mining';}});
    var p=last&&last.payment_policy;
    put('pool-public-minimum',p?amount(p.minimum_units,8)+' VELD':'—');
    function amount(v,scale){var n=BigInt(v),d=10n**BigInt(scale);return (n/d+'.'+(n%d).toString().padStart(scale,'0')).replace(/\.?0+$/,'');}
    put('pool-public-policy',p?(stale?'Last reported policy: ':'')+amount(p.fee_ppm,4)+'% service fee · '+amount(p.minimum_units,8)+' VELD minimum per payout address · batches every '+(Number(p.batch_seconds)/3600)+' hours.':paused?'Payout processing is paused.':'Payment policy has not loaded yet.');
  }
  async function operatorStatus(){
    if(document.hidden)return;
    var stop=new AbortController(),timer=setTimeout(function(){stop.abort();},4000);
    try{
      var r=await fetch('/assets/pool-service-state.json',{credentials:'omit',redirect:'error',cache:'no-store',signal:stop.signal});
      if(!r.ok||!r.body)throw Error('notice unavailable');
      var reader=r.body.getReader(),parts=[],size=0;
      for(;;){var part=await reader.read();if(part.done)break;size+=part.value.length;if(size>2048){await reader.cancel();throw Error('notice size');}parts.push(part.value);}
      var bytes=new Uint8Array(size),offset=0;parts.forEach(function(p){bytes.set(p,offset);offset+=p.length;});
      var value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
      if(value.version!==1||!['paused_by_operator','no_operator_pause'].includes(value.state)||
         value.chain!=='7be77ab9e820bd9ffb60b269b45ced48288056e5839a1135fafc2f8557000a88'||
         typeof value.updated_at!=='string'||!Number.isFinite(Date.parse(value.updated_at)))throw Error('notice invalid');
      operator=value;operatorFailed=false;
    }catch(_){operatorFailed=true;}finally{clearTimeout(timer);render();document.dispatchEvent(new Event('veld-pool-state'));}
  }
  async function refresh(){
    if(!document.getElementById('pool-public-status')||document.hidden)return;
    render();if(busy||Date.now()<next)return;busy=true;next=Date.now()+15000;
    var stop=new AbortController(),timer=setTimeout(function(){stop.abort();},8000);
    try{
      var r=await fetch('https://pool.veld.network/v1/public',{credentials:'omit',referrerPolicy:'no-referrer',cache:'no-store',redirect:'error',signal:stop.signal});
      if(!r.ok||!r.body)throw Error('unavailable');
      var reader=r.body.getReader(),parts=[],size=0;
      for(;;){var part=await reader.read();if(part.done)break;size+=part.value.length;if(size>32768){await reader.cancel();throw Error('response limit');}parts.push(part.value);}
      var bytes=new Uint8Array(size),offset=0;parts.forEach(function(p){bytes.set(p,offset);offset+=p.length;});
      var j=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)),s=j&&j.result;
      if(j.ok!==true||!s||s.chain!=='7be77ab9e820bd9ffb60b269b45ced48288056e5839a1135fafc2f8557000a88')throw Error('network');
      ['active_accounts','verified_shares','reconciled_height'].forEach(function(k){if(k==='reconciled_height'&&s[k]===null)return;if(typeof s[k]!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(s[k]))throw Error('count');});
      if(typeof s.payments_enabled!=='boolean'||typeof s.co_mining_enabled!=='boolean')throw Error('flags');
      if(!['Service responding','Reconciliation paused or starting'].includes(s.status))throw Error('status');
      if(s.payment_policy!==undefined){
        if(!s.payment_policy||typeof s.payment_policy!=='object'||Array.isArray(s.payment_policy))throw Error('policy');
        ['fee_ppm','minimum_units','batch_seconds','revision'].forEach(function(k){if(typeof s.payment_policy[k]!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(s.payment_policy[k]))throw Error('policy value');});
        if(BigInt(s.payment_policy.fee_ppm)>100000n||BigInt(s.payment_policy.minimum_units)<100000000n||BigInt(s.payment_policy.minimum_units)>1000000000000n||BigInt(s.payment_policy.batch_seconds)<3600n||BigInt(s.payment_policy.batch_seconds)>604800n)throw Error('policy bounds');
      }
      last=s;lastAt=Date.now();failed=false;
    }catch(_){failed=true;}finally{clearTimeout(timer);busy=false;render();}
  }
  setInterval(refresh,1000);setInterval(operatorStatus,30000);operatorStatus();refresh();
})();
