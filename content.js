
// FiShield Content Script — injects the alert overlay into pages

let overlayEl = null;

function injectOverlay(result) {
  if (overlayEl) overlayEl.remove();

  const verdictEmoji = result.verdict === 'PHISHING' ? '⛔' : '⚠️';
  const bgGradient   = result.verdict === 'PHISHING'
    ? 'linear-gradient(135deg, #b71c1c 0%, #e53935 100%)'
    : 'linear-gradient(135deg, #e65100 0%, #fb8c00 100%)';

  const reasonsHTML = result.reasons.map(r =>
    `<div style="margin:4px 0;font-size:13px;line-height:1.4">${r}</div>`
  ).join('');

  overlayEl = document.createElement('div');
  overlayEl.id = 'fishield-overlay';
  overlayEl.innerHTML = `
    <div id="fishield-overlay-inner">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <div style="display:flex;align-items:center;gap:10px">
          <div style="font-size:32px">${verdictEmoji}</div>
          <div>
            <div style="font-size:11px;opacity:.8;letter-spacing:1px;text-transform:uppercase">FiShield Alert</div>
            <div style="font-size:20px;font-weight:700;letter-spacing:.5px">${result.verdict}</div>
          </div>
        </div>
        <button id="fishield-close" title="Dismiss">✕</button>
      </div>

      <div style="background:rgba(0,0,0,.25);border-radius:8px;padding:10px 14px;margin-bottom:12px">
        <div style="font-size:11px;opacity:.7;margin-bottom:4px">URL ANALYSED</div>
        <div style="font-size:12px;word-break:break-all;opacity:.95">${result.url.slice(0,90)}${result.url.length>90?'…':''}</div>
      </div>

      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
        <div style="flex:1">
          <div style="font-size:11px;opacity:.7;margin-bottom:4px">ML CONFIDENCE</div>
          <div style="height:8px;background:rgba(0,0,0,.3);border-radius:4px;overflow:hidden">
            <div style="height:100%;width:${result.confidence}%;background:#fff;border-radius:4px;transition:width .6s ease"></div>
          </div>
        </div>
        <div style="text-align:right">
          <div style="font-size:28px;font-weight:800;line-height:1">${result.confidence}%</div>
          <div style="font-size:10px;opacity:.7">confidence</div>
        </div>
      </div>

      <div style="margin-bottom:14px">
        <div style="font-size:11px;opacity:.7;margin-bottom:6px">DETECTED SIGNALS</div>
        ${reasonsHTML}
      </div>

      <div style="display:flex;gap:8px">
        <button id="fishield-leave" style="flex:1;padding:9px;background:rgba(255,255,255,.15);color:#fff;border:1px solid rgba(255,255,255,.3);border-radius:6px;cursor:pointer;font-size:13px;font-weight:600">
          ← Go Back
        </button>
        <button id="fishield-proceed" style="flex:1;padding:9px;background:rgba(0,0,0,.25);color:rgba(255,255,255,.7);border:1px solid rgba(255,255,255,.2);border-radius:6px;cursor:pointer;font-size:12px">
          Proceed anyway
        </button>
      </div>
    </div>
  `;

  const style = document.createElement('style');
  style.textContent = `
    #fishield-overlay {
      position: fixed; top: 0; left: 0; right: 0; bottom: 0; z-index: 2147483647;
      background: rgba(0,0,0,.55); backdrop-filter: blur(4px);
      display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      animation: fishieldFadeIn .25s ease;
    }
    #fishield-overlay-inner {
      background: ${bgGradient};
      color: #fff; padding: 22px; border-radius: 16px;
      max-width: 400px; width: calc(100% - 40px);
      box-shadow: 0 24px 60px rgba(0,0,0,.5);
    }
    #fishield-close {
      background: rgba(0,0,0,.2); border: none; color: #fff;
      width: 28px; height: 28px; border-radius: 50%; cursor: pointer;
      font-size: 14px; display: flex; align-items: center; justify-content: center;
    }
    #fishield-leave:hover   { background: rgba(255,255,255,.25) !important; }
    #fishield-proceed:hover { background: rgba(0,0,0,.4) !important; }
    @keyframes fishieldFadeIn { from { opacity:0; transform: scale(.96); } to { opacity:1; transform: scale(1); } }
  `;

  document.head.appendChild(style);
  document.documentElement.appendChild(overlayEl);

  document.getElementById('fishield-close').onclick   = removeOverlay;
  document.getElementById('fishield-proceed').onclick  = removeOverlay;
  document.getElementById('fishield-leave').onclick    = () => { removeOverlay(); history.back(); };
}

function removeOverlay() {
  if (overlayEl) { overlayEl.remove(); overlayEl = null; }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'FISHIELD_ALERT') injectOverlay(msg.result);
  if (msg.type === 'CLOSE_OVERLAY')  removeOverlay();
});
