#pragma once
#include <string>
namespace veld {
namespace explorer_dispatch {

inline const char* kDispatchJs = R"DISPATCHJS(
(function(){
  var ACTIONS = {
    change: {
      e4e01b891: function(event){ toggleProposalType() },
    },
    click: {
      ef4b2d1c3: function(event){ toggleExplorerMore() },
      ec2e03555: function(event){ doSearch() },
      etog_theme: function(event){ if (typeof toggleVeldTheme==='function') toggleVeldTheme(); },
      // checkBalance / sendWBTC / requestDeposit / requestRedeem
      // / loadMyBalance / submitMM / placeOrder / cancelOrder dispatch entries
      // removed with the WBTC /tokens page and the VELD/WBTC /exchange page.
      e4d75da55: function(event){ checkTier() },
      ea2b0b337: function(event){ checkEligibility() },
      ef71aa4a1: function(event){ submitProposal() },
      e638a47af: function(event){ loadProposals() },
      e3f7ea4c9: function(event){ filterProposals('all',this) },
      e68a464f9: function(event){ filterProposals('open',this) },
      e22f51807: function(event){ filterProposals('passed',this) },
      e5482e327: function(event){ filterProposals('rejected',this) },
      edebab07a: function(event){ filterProposals('expired',this) },
      e1b5d37d9: function(event){ voteOnProposal(this.dataset.voteId, this.dataset.voteChoice) },
      e18bb4b3a: function(event){ voteOnProposal(this.dataset.voteId, this.dataset.voteChoice) },
      e33c1e1c9: function(event){ voteOnProposal(this.dataset.voteId, this.dataset.voteChoice) },
      e1b7713ed: function(event){ (function(btn,text){var ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;left:-9999px;top:-9999px';document.body.appendChild(ta);ta.focus();ta.select();try{document.execCommand('copy')}catch(e){}document.body.removeChild(ta);var o=btn.textContent;btn.textContent='Copied!';btn.style.color='#32F06E';setTimeout(function(){btn.textContent=o;btn.style.color=''},1500)})(this, this.dataset.copyText) },
      edc3f8af2: function(event){ jumpToHeight() },
      ee150c68b: function(event){ prevPage() },
      e0f954e79: function(event){ nextPage() },
      e8162979f: function(event){ checkBal() },
      e1b711487: function(event){ listUTXOs() },
    },
    keydown: {
      e9dd9760b: function(event){ if(event.key==='Enter')checkEligibility() },
    },
  };
  function dispatch(ev, e) {
    var map = ACTIONS[ev]; if (!map) return;
    var el = e.target;
    var attr = "data-act-" + ev;
    while (el && el.nodeType === 1) {
      if (el.hasAttribute(attr)) {
        var fn = map[el.getAttribute(attr)];
        if (fn) { try { fn.call(el, e); } catch(err){ console.error("explorer act "+ev+": ", err); } return; }
      }
      el = el.parentNode;
    }
  }
  ["click","input","change","keydown","keyup","submit"].forEach(function(ev){
    document.addEventListener(ev, function(e){ dispatch(ev, e); }, true);
  });
})();
)DISPATCHJS";

}
} // namespace veld
