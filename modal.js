(function(){
  function ensureStyles(){
    if (document.getElementById('app-modal-styles')) return;
    const css = `
      .app-modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;z-index:99999}
      .app-modal{background:#fff;max-width:420px;width:90%;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.2);overflow:hidden;font-family:Segoe UI,system-ui,Arial,sans-serif}
      .app-modal-header{padding:14px 16px;font-weight:600;border-bottom:1px solid #eee}
      .app-modal-body{padding:16px;color:#2D3748}
      .app-modal-input{width:100%;padding:10px 12px;border:1px solid #cbd5e0;border-radius:8px;margin-top:10px;font-size:14px}
      .app-modal-footer{display:flex;gap:10px;justify-content:flex-end;padding:12px 16px;background:#f9fafb;border-top:1px solid #eee}
      .app-btn{padding:8px 14px;border-radius:8px;border:0;cursor:pointer;font-weight:600}
      .app-btn-primary{background:#1d2b64;color:#fff}
      .app-btn-secondary{background:#e2e8f0;color:#2d3748}
    `;
    const style = document.createElement('style'); style.id='app-modal-styles'; style.textContent = css; document.head.appendChild(style);
  }
  function showModal({title,message,showInput=false,defaultValue=''}){
    ensureStyles();
    return new Promise(resolve=>{
      const backdrop = document.createElement('div'); backdrop.className='app-modal-backdrop';
      const modal = document.createElement('div'); modal.className='app-modal';
      const h = document.createElement('div'); h.className='app-modal-header'; h.textContent = title || 'Message';
      const b = document.createElement('div'); b.className='app-modal-body'; b.textContent = message || '';
      let input = null; if (showInput){ input=document.createElement('input'); input.className='app-modal-input'; input.value=defaultValue||''; b.appendChild(input); setTimeout(()=>input.focus(),0); }
      const f = document.createElement('div'); f.className='app-modal-footer';
      const ok = document.createElement('button'); ok.className='app-btn app-btn-primary'; ok.textContent='OK';
      const cancel = document.createElement('button'); cancel.className='app-btn app-btn-secondary'; cancel.textContent='Cancel';
      ok.onclick=()=>{ cleanup(); resolve(showInput? (input.value) : true); };
      cancel.onclick=()=>{ cleanup(); resolve(showInput? null : false); };
      function onKey(e){ if(e.key==='Escape'){ cleanup(); resolve(showInput? null:false);} if(e.key==='Enter'){ ok.click(); } }
      function cleanup(){ document.removeEventListener('keydown', onKey); backdrop.remove(); }
      document.addEventListener('keydown', onKey);
      f.appendChild(cancel); f.appendChild(ok);
      modal.appendChild(h); modal.appendChild(b); modal.appendChild(f); backdrop.appendChild(modal); document.body.appendChild(backdrop);
    });
  }

  window.appAlert = function(message, title='Notice'){ return showModal({title,message}).then(()=>{}); };
  window.appConfirm = function(message, title='Confirm'){ return showModal({title,message}).then(v=>!!v); };
  window.appPrompt = function(message, defaultValue='', title='Input'){ return showModal({title,message,showInput:true,defaultValue}); };

  // Override native dialogs (can be toggled by commenting out)
  const nativeAlert = window.alert, nativeConfirm = window.confirm, nativePrompt = window.prompt;
  window.alert = (msg)=>{ return appAlert(String(msg)); };
  window.confirm = (msg)=>{ return appConfirm(String(msg)); };
  window.prompt = (msg, defVal='')=>{ return appPrompt(String(msg), String(defVal||'')); };
})();


