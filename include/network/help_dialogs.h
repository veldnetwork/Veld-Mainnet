#pragma once
#include <string>

namespace veld {
// Shared presentation only. The original controls and live-value nodes are
// moved, not copied, so their identifiers and event handlers remain intact.
inline std::string WithHelpDialogs(std::string html) {
    static constexpr char assets[] = R"HELP(
<style>
[data-veld-help]>:not(button){display:none}
[data-veld-help]>button,.veld-help-open{appearance:none;display:inline-flex;align-items:center;gap:6px;min-height:36px;padding:6px 10px;border:1px solid var(--b2,#424742);border-radius:8px;background:var(--s2,#202420);color:var(--text,#f0f2ef);font:inherit;text-align:left;cursor:pointer}
[data-veld-help]>button:focus-visible,.veld-help-dialog button:focus-visible{outline:2px solid var(--em,#80cf40);outline-offset:3px}
.veld-help-dialog{box-sizing:border-box;width:min(560px,calc(100vw - 32px));max-height:calc(100dvh - 32px);margin:auto;padding:20px;border:1px solid var(--b2,#424742);border-radius:14px;background:var(--s1,#171b17);color:var(--text,#f0f2ef);font:inherit;overflow:auto;overscroll-behavior:contain}
.veld-help-dialog::backdrop{background:rgba(0,0,0,.65)}
.veld-help-dialog header{position:static;display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:16px;height:auto;padding:0;background:none;border:0}
.veld-help-dialog h2{font:inherit;font-size:18px;font-weight:650;margin:0}
.veld-help-dialog header button{appearance:none;flex:none;min-height:40px;padding:8px 12px;border:1px solid var(--b2,#424742);border-radius:8px;background:var(--s2,#202420);color:inherit;font:inherit;cursor:pointer}
.veld-help-body{line-height:1.6;overflow-wrap:anywhere}
.veld-help-body .help-body,.veld-help-body .spx-help-body{position:static!important;display:block!important;width:auto!important;max-width:none!important;margin:0!important;padding:0!important;border:0!important;box-shadow:none!important;background:none!important;color:inherit!important}
.veld-help-body table{width:100%;min-width:0;table-layout:fixed}.veld-help-body th,.veld-help-body td{white-space:normal!important;overflow-wrap:anywhere}
.veld-help-body p+p{margin-top:12px}
</style>
<script nonce="__CSP_NONCE__">
(function(){
  'use strict';
  var serial=0,opened=0,previousOverflow='';
  function prepare(scope){
    var sections=Array.from(scope.querySelectorAll('[data-veld-help]')).reverse();
    sections.forEach(function(section){
      if(section.dataset.veldHelpReady)return;
      var button=section.firstElementChild;
      if(!button||button.tagName!=='BUTTON')return;
      section.dataset.veldHelpReady='1';
      button.type='button';button.classList.add('veld-help-open');
      var label=button.getAttribute('aria-label')||button.textContent.trim();
      if(label==='Details'){
        var heading=section.previousElementSibling;
        label=heading?heading.textContent.trim():'More information';
        button.textContent='Read explanation';
      }
      var dialog=document.createElement('dialog');dialog.className='veld-help-dialog';
      dialog.id='veld-help-'+(++serial);
      var header=document.createElement('header'),title=document.createElement('h2'),close=document.createElement('button');
      title.id=dialog.id+'-title';title.textContent=label;
      close.type='button';close.textContent='Close';close.autofocus=true;
      var body=document.createElement('div');body.className='veld-help-body';
      while(button.nextSibling)body.appendChild(button.nextSibling);
      header.append(title,close);dialog.append(header,body);document.body.appendChild(dialog);
      dialog.setAttribute('aria-labelledby',title.id);
      button.setAttribute('aria-haspopup','dialog');button.setAttribute('aria-controls',dialog.id);
      button.addEventListener('click',function(){
        if(dialog.open)return;
        dialog.showModal();
        if(opened++===0){previousOverflow=document.body.style.overflow;document.body.style.overflow='hidden';}
      });
      close.addEventListener('click',function(){dialog.close();});
      dialog.addEventListener('keydown',function(event){
        if(event.key!=='Tab')return;
        var controls=Array.from(dialog.querySelectorAll('button,a[href],input,select,textarea,[tabindex]'))
          .filter(function(el){return !el.disabled&&el.tabIndex>=0&&el.getClientRects().length;});
        var first=controls[0],last=controls[controls.length-1];
        if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}
        else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}
      });
      dialog.addEventListener('click',function(event){
        if(event.target!==dialog)return;
        var rect=dialog.getBoundingClientRect();
        if(event.clientX<rect.left||event.clientX>rect.right||event.clientY<rect.top||event.clientY>rect.bottom)dialog.close();
      });
      dialog.addEventListener('close',function(){
        opened=Math.max(0,opened-1);
        if(!opened)document.body.style.overflow=previousOverflow;
        if(button.isConnected)button.focus();
      });
    });
  }
  function start(){
    prepare(document);
    new MutationObserver(function(records){
      if(records.some(function(record){return record.addedNodes.length;}))prepare(document);
    }).observe(document.body,{childList:true,subtree:true});
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start,{once:true});else start();
})();
</script>
)HELP";
    const auto head = html.find("</head>");
    if (head != std::string::npos)
        html.insert(head, assets);
    return html;
}
} // namespace veld
