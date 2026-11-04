// Shared public Pool-tab view, embedded in Explorer and portal by the source generator.
// No account identifiers, cookies, pairing credentials or private tokens leave the page.
(function(){
  'use strict';
  var busy=false, next=0, last=null, failed=false;
  function put(id,value){var e=document.getElementById(id);if(e)e.textContent=value;}
  function render(){
    put('pool-public-status',failed?'Pool status unavailable. Retrying.':last?last.status:'Connecting to Veld Pool…');
    ['active_accounts','verified_shares','reconciled_height'].forEach(function(k){
      put('pool-public-'+k,!failed&&last&&last[k]!==null?BigInt(last[k]).toLocaleString():'—');
    });
    put('pool-public-payments',failed||!last?'Unknown':last.payments_enabled?'Enabled':'Not enabled');
    put('pool-public-comining',failed||!last?'Unknown':last.co_mining_enabled?'Enabled':'Not enabled');
    var p=!failed&&last&&last.payment_policy;
    function amount(v,scale){var n=BigInt(v),d=10n**BigInt(scale);return (n/d+'.'+(n%d).toString().padStart(scale,'0')).replace(/\.?0+$/,'');}
    put('pool-public-policy',p?amount(p.fee_ppm,4)+'% service fee · '+amount(p.minimum_units,8)+' VELD minimum per payout address · batches every '+(Number(p.batch_seconds)/3600)+' hours.':'Payment policy unavailable. Check the pool dashboard.');
  }
  async function refresh(){
    if(!document.getElementById('pool-public-status')||document.hidden)return;
    render();if(busy||Date.now()<next)return;busy=true;next=Date.now()+15000;
    var stop=new AbortController(),timer=setTimeout(function(){stop.abort();},5000);
    try{
      var r=await fetch('https://pool.veld.network/v1/public',{credentials:'omit',referrerPolicy:'no-referrer',cache:'no-store',redirect:'error',signal:stop.signal});
      if(!r.ok||!r.body)throw Error('unavailable');
      var reader=r.body.getReader(),parts=[],size=0;
      for(;;){var part=await reader.read();if(part.done)break;size+=part.value.length;if(size>4096){await reader.cancel();throw Error('response limit');}parts.push(part.value);}
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
      last=s;failed=false;
    }catch(_){failed=true;last=null;}finally{clearTimeout(timer);busy=false;render();}
  }
  setInterval(refresh,1000);refresh();
})();
