// ================================================================
// PhishGuard — content.js
// MODULE 3: User Alert & Protection Module
// Injects real-time visual warnings and protection UI into pages
// ================================================================

let overlay = null;

// ── Listen for messages from background (Module 1) ─────────────
chrome.runtime.onMessage.addListener((msg) => {
  switch (msg.type) {
    case "SHOW_WARNING":       showPhishingWarning(msg);   break;  // [04-08]
    case "ANALYSIS_COMPLETE":  showSafeBadge(msg);          break;
    case "ANALYSIS_ERROR":     /* silent fail */             break;
  }
});

// ── [01-08] Full phishing warning overlay ──────────────────────
// [01] ML model detected phishing → [02] result returned → [03] severity evaluated
function showPhishingWarning(data) {
  if (overlay) overlay.remove();
  overlay = document.createElement("div");
  overlay.id = "pg-overlay";

  const confidence = Math.round((data.confidence || 0) * 100);
  const host       = safeHost(data.url);
  const risk       = (data.risk_level || "high").toUpperCase();
  const reasons    = (data.reasons || []).slice(0, 4);

  // [05-06] Warning message + visual indicators displayed
  overlay.innerHTML = `
    <div id="pg-backdrop"></div>
    <div id="pg-modal">
      <div id="pg-modal-top">
        <div id="pg-shield-icon">
          <svg width="52" height="52" viewBox="0 0 52 52" fill="none">
            <path d="M26 4L6 13v12c0 11.05 8.56 21.38 20 23.8C37.44 46.38 46 36.05 46 25V13L26 4z"
                  fill="rgba(255,59,48,0.12)" stroke="#FF3B30" stroke-width="2.5"/>
            <path d="M26 18v10M26 33v1" stroke="#FF3B30" stroke-width="3" stroke-linecap="round"/>
          </svg>
        </div>
        <div>
          <div id="pg-badge-risk">${risk} RISK</div>
          <h1 id="pg-title">Phishing Website Detected</h1>
          <p id="pg-subtitle">PhishGuard AI has flagged this page as dangerous</p>
        </div>
      </div>

      <div id="pg-body">
        <div class="pg-info-row">
          <span class="pg-info-label">SUSPICIOUS DOMAIN</span>
          <span class="pg-info-value" title="${data.url}">${host}</span>
        </div>

        <div class="pg-info-row">
          <span class="pg-info-label">THREAT CONFIDENCE</span>
          <div id="pg-bar-wrap">
            <div id="pg-bar-track">
              <div id="pg-bar-fill" style="width:0%"></div>
            </div>
            <span id="pg-bar-pct">${confidence}%</span>
          </div>
        </div>

        ${reasons.length ? `
        <div id="pg-reasons">
          <span class="pg-info-label">WHY THIS IS SUSPICIOUS</span>
          <ul>${reasons.map(r => `<li>${r}</li>`).join("")}</ul>
        </div>` : ""}

        <!-- [07] Advice not to enter sensitive info -->
        <div id="pg-advice">
          🔒 Do <strong>NOT</strong> enter passwords, credit card numbers, or any personal data on this page.
        </div>
      </div>

      <div id="pg-actions">
        <!-- [08] Option to leave the site -->
        <button id="pg-btn-back">← Leave This Site</button>
        <button id="pg-btn-proceed">Proceed at Own Risk</button>
      </div>

      <div id="pg-feedback-row">
        <span>Was this a false alarm?</span>
        <button class="pg-fb-btn" data-v="safe">Mark as Safe</button>
        <button class="pg-fb-btn" data-v="phishing">Confirm Phishing</button>
      </div>
    </div>`;

  const style = document.createElement("style");
  style.textContent = styles();
  overlay.appendChild(style);
  document.body.appendChild(overlay);

  // Animate confidence bar
  requestAnimationFrame(() => {
    setTimeout(() => {
      const bar = document.getElementById("pg-bar-fill");
      if (bar) bar.style.width = confidence + "%";
    }, 120);
  });

  // [08] Leave site button
  document.getElementById("pg-btn-back").onclick = () => window.history.back();

  // [09] Proceed — record user decision
  document.getElementById("pg-btn-proceed").onclick = () => {
    recordFeedback(data.url, "user_proceeded");
    overlay.remove(); overlay = null;
  };

  // [09] Feedback buttons
  overlay.querySelectorAll(".pg-fb-btn").forEach(btn => {
    btn.onclick = () => {
      recordFeedback(data.url, btn.dataset.v);
      btn.textContent = "✓ Recorded";
      btn.disabled = true;
    };
  });
}

// ── [10] Safe badge — browsing resumed normally ────────────────
function showSafeBadge(data) {
  const badge = document.createElement("div");
  badge.id = "pg-safe-badge";
  badge.innerHTML = `
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z"
            fill="rgba(52,199,89,0.2)" stroke="#34C759" stroke-width="2"/>
      <path d="M9 12l2 2 4-4" stroke="#34C759" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>Protected`;

  const s = document.createElement("style");
  s.textContent = `
    #pg-safe-badge{position:fixed;bottom:20px;right:20px;background:rgba(0,0,0,0.82);
      color:#34C759;padding:7px 14px;border-radius:20px;font-family:-apple-system,sans-serif;
      font-size:12px;font-weight:600;display:flex;align-items:center;gap:6px;
      z-index:2147483647;border:1px solid rgba(52,199,89,0.25);pointer-events:none;
      animation:pg-si .3s ease,pg-fo .4s ease 2.4s forwards;}
    @keyframes pg-si{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
    @keyframes pg-fo{to{opacity:0}}`;
  document.head.appendChild(s);
  document.body.appendChild(badge);
  setTimeout(() => badge.remove(), 3000);
}

// ── [09] Record user decision for system feedback ──────────────
function recordFeedback(url, verdict) {
  chrome.runtime.sendMessage({
    type: "USER_FEEDBACK",
    feedback: { url, verdict, timestamp: new Date().toISOString() }
  }).catch(() => {});
}

function safeHost(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

// ── Styles ─────────────────────────────────────────────────────
function styles() {
  return `
  #pg-overlay{position:fixed;inset:0;z-index:2147483647;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
  #pg-backdrop{position:absolute;inset:0;background:rgba(0,0,0,0.88);backdrop-filter:blur(6px)}
  #pg-modal{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
    background:#111113;border:1px solid rgba(255,59,48,0.35);border-radius:18px;
    width:min(520px,92vw);overflow:hidden;
    box-shadow:0 0 80px rgba(255,59,48,0.2),0 24px 60px rgba(0,0,0,0.6);
    animation:pg-in .4s cubic-bezier(.34,1.56,.64,1)}
  @keyframes pg-in{from{opacity:0;transform:translate(-50%,-47%) scale(.94)}
    to{opacity:1;transform:translate(-50%,-50%) scale(1)}}
  #pg-modal-top{background:linear-gradient(135deg,#1d0808,#111113);
    padding:22px 24px;display:flex;align-items:center;gap:18px;
    border-bottom:1px solid rgba(255,59,48,0.15)}
  #pg-badge-risk{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.12em;
    color:#FF3B30;background:rgba(255,59,48,0.12);border:1px solid rgba(255,59,48,0.25);
    padding:3px 9px;border-radius:4px;margin-bottom:6px}
  #pg-title{font-size:19px;font-weight:700;color:#fff;margin:0 0 3px}
  #pg-subtitle{font-size:12px;color:#777;margin:0}
  #pg-body{padding:18px 24px;display:flex;flex-direction:column;gap:14px}
  .pg-info-row{display:flex;flex-direction:column;gap:5px}
  .pg-info-label{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:#555;font-weight:600}
  .pg-info-value{font-size:15px;color:#eee;font-weight:600;word-break:break-all}
  #pg-bar-wrap{display:flex;align-items:center;gap:10px}
  #pg-bar-track{flex:1;height:7px;background:rgba(255,255,255,0.08);border-radius:4px;overflow:hidden}
  #pg-bar-fill{height:100%;background:linear-gradient(90deg,#FF9500,#FF3B30);
    border-radius:4px;transition:width .9s cubic-bezier(.4,0,.2,1)}
  #pg-bar-pct{font-size:13px;font-weight:700;color:#FF3B30;min-width:36px;text-align:right}
  #pg-reasons ul{margin:7px 0 0;padding-left:17px;color:#aaa;font-size:13px;line-height:1.75}
  #pg-advice{background:rgba(255,159,10,0.08);border:1px solid rgba(255,159,10,0.18);
    border-radius:8px;padding:11px 14px;font-size:12.5px;color:#e5a200;line-height:1.5}
  #pg-actions{padding:14px 24px;display:flex;gap:10px;border-top:1px solid rgba(255,255,255,0.07)}
  #pg-btn-back{flex:1;padding:12px;background:#FF3B30;color:#fff;border:none;border-radius:9px;
    font-size:14px;font-weight:600;cursor:pointer;transition:background .2s}
  #pg-btn-back:hover{background:#d42b21}
  #pg-btn-proceed{padding:12px 16px;background:transparent;color:#555;
    border:1px solid rgba(255,255,255,0.1);border-radius:9px;font-size:13px;cursor:pointer;transition:.2s}
  #pg-btn-proceed:hover{color:#888;border-color:rgba(255,255,255,0.2)}
  #pg-feedback-row{padding:10px 24px 14px;display:flex;align-items:center;gap:8px;
    font-size:11.5px;color:#555;border-top:1px solid rgba(255,255,255,0.05)}
  .pg-fb-btn{font-size:11px;color:#888;background:rgba(255,255,255,0.06);
    border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:4px 10px;
    cursor:pointer;font-family:-apple-system,sans-serif;transition:.2s}
  .pg-fb-btn:hover{color:#ddd;border-color:rgba(255,255,255,0.2)}
  .pg-fb-btn:disabled{opacity:.5;cursor:default}`;
}
