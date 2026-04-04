// ================================================================
// PhishGuard — content.js
// MODULE 4: User Alert & Protection Module
//
// Displays phishing warning or safe indicator on EVERY page load.
// Buttons are fully functional (leave site, proceed, feedback).
// ================================================================

let warningOverlay = null;
let safeBadge = null;

// ── Listen for messages from background.js ─────────────────────
chrome.runtime.onMessage.addListener((message) => {
  console.log("[PhishGuard content.js] Received:", message.type);

  if (message.type === "SHOW_WARNING") {
    showPhishingWarning(message);
  } else if (message.type === "SAFE_SITE") {
    showSafeIndicator(message);
  } else if (message.type === "ANALYSIS_ERROR") {
    console.warn("[PhishGuard] Analysis error:", message.error);
  }
});

// ================================================================
// PHISHING WARNING
// Red alert box, fixed position, high z-index
// Appears automatically without clicking the extension
// ================================================================
function showPhishingWarning(data) {
  // Remove any existing overlays
  removeExisting();

  const confidence = Math.round((data.confidence || 0) * 100);
  const hostname = getHostname(data.url);

  // Create overlay
  warningOverlay = document.createElement("div");
  warningOverlay.id = "phishguard-warning";
  warningOverlay.setAttribute("style",
    "position:fixed; inset:0; z-index:2147483647; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
  );

  warningOverlay.innerHTML = `
    <div style="position:absolute; inset:0; background:rgba(0,0,0,0.88); backdrop-filter:blur(8px);"></div>
    <div id="pg-box" style="
      position:fixed; top:50%; left:50%; transform:translate(-50%,-50%);
      background:#1a1010; border:2px solid #FF3B30; border-radius:16px;
      width:500px; max-width:92vw; overflow:hidden;
      box-shadow:0 0 60px rgba(255,59,48,0.3), 0 20px 50px rgba(0,0,0,0.7);
      z-index:2147483647;
    ">
      <!-- Header -->
      <div style="background:linear-gradient(135deg,#2d0a0a,#1a1010); padding:24px; display:flex; align-items:center; gap:18px; border-bottom:1px solid rgba(255,59,48,0.2);">
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
          <path d="M24 4L4 12v10c0 10.2 8 19.8 20 22 12-2.2 20-11.8 20-22V12L24 4z" fill="rgba(255,59,48,0.15)" stroke="#FF3B30" stroke-width="2.5"/>
          <path d="M24 16v10M24 30v2" stroke="#FF3B30" stroke-width="3" stroke-linecap="round"/>
        </svg>
        <div>
          <div style="display:inline-block; font-size:10px; font-weight:800; letter-spacing:0.15em; color:#FF3B30; background:rgba(255,59,48,0.15); border:1px solid rgba(255,59,48,0.3); padding:4px 12px; border-radius:4px; margin-bottom:8px;">PHISHING DETECTED</div>
          <h1 style="font-size:18px; font-weight:700; color:#fff; margin:0 0 4px;">Warning: Potential phishing website detected</h1>
          <p style="font-size:12px; color:#888; margin:0;">PhishGuard AI has flagged this page as dangerous</p>
        </div>
      </div>

      <!-- Body -->
      <div style="padding:20px 24px; display:flex; flex-direction:column; gap:16px;">
        <div>
          <div style="font-size:10px; text-transform:uppercase; letter-spacing:0.1em; color:#666; font-weight:600; margin-bottom:6px;">SUSPICIOUS URL</div>
          <div style="font-size:15px; color:#eee; font-weight:600; word-break:break-all;">${hostname}</div>
        </div>

        <div>
          <div style="font-size:10px; text-transform:uppercase; letter-spacing:0.1em; color:#666; font-weight:600; margin-bottom:6px;">THREAT CONFIDENCE</div>
          <div style="display:flex; align-items:center; gap:12px;">
            <div style="flex:1; height:8px; background:rgba(255,255,255,0.08); border-radius:4px; overflow:hidden;">
              <div id="pg-conf-bar" style="height:100%; width:${confidence}%; background:linear-gradient(90deg,#FF9500,#FF3B30); border-radius:4px; transition:width 1s;"></div>
            </div>
            <span style="font-size:14px; font-weight:700; color:#FF3B30;">${confidence}%</span>
          </div>
        </div>

        <div style="background:rgba(255,59,48,0.08); border:1px solid rgba(255,59,48,0.2); border-radius:8px; padding:14px 16px; font-size:13px; color:#ff8a80; line-height:1.6;">
          <strong style="color:#FF3B30;">DO NOT</strong> enter passwords, credit card numbers, or any personal information on this page.
        </div>
      </div>

      <!-- Buttons -->
      <div style="padding:16px 24px; display:flex; gap:10px; border-top:1px solid rgba(255,255,255,0.07);">
        <button id="pg-btn-leave" style="
          flex:1; padding:14px; background:#FF3B30; color:#fff; border:none; border-radius:10px;
          font-size:15px; font-weight:600; cursor:pointer; font-family:inherit;
        ">Leave This Site</button>
        <button id="pg-btn-proceed" style="
          padding:14px 18px; background:transparent; color:#555;
          border:1px solid rgba(255,255,255,0.1); border-radius:10px;
          font-size:13px; cursor:pointer; font-family:inherit;
        ">Continue at Own Risk</button>
      </div>

      <!-- Feedback -->
      <div style="padding:12px 24px 16px; display:flex; align-items:center; gap:8px; font-size:12px; color:#555; border-top:1px solid rgba(255,255,255,0.05);">
        <span>False alarm?</span>
        <button class="pg-fb" data-v="safe" style="font-size:11px; color:#888; background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.1); border-radius:6px; padding:5px 12px; cursor:pointer; font-family:inherit;">Mark Safe</button>
        <button class="pg-fb" data-v="phishing" style="font-size:11px; color:#888; background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.1); border-radius:6px; padding:5px 12px; cursor:pointer; font-family:inherit;">Confirm Phishing</button>
      </div>
    </div>
  `;

  document.body.appendChild(warningOverlay);

  // ── Attach button click handlers AFTER element is in DOM ──
  const leaveBtn = document.getElementById("pg-btn-leave");
  const proceedBtn = document.getElementById("pg-btn-proceed");

  if (leaveBtn) {
    leaveBtn.onclick = function() {
      console.log("[PhishGuard] User clicked Leave This Site");
      window.history.back();
    };
  }

  if (proceedBtn) {
    proceedBtn.onclick = function() {
      console.log("[PhishGuard] User clicked Continue at Own Risk");
      sendFeedback(data.url, "user_proceeded");
      if (warningOverlay) {
        warningOverlay.remove();
        warningOverlay = null;
      }
    };
  }

  // Feedback buttons
  const fbBtns = document.querySelectorAll(".pg-fb");
  fbBtns.forEach(function(btn) {
    btn.onclick = function() {
      sendFeedback(data.url, btn.getAttribute("data-v"));
      btn.textContent = "Recorded";
      btn.disabled = true;
      btn.style.opacity = "0.5";
    };
  });

  console.log("[PhishGuard] Warning overlay displayed for:", hostname);
}

// ================================================================
// SAFE STATUS INDICATOR
// Small green notification: "Website scanned — safe"
// Shows for EVERY safe website
// ================================================================
function showSafeIndicator(data) {
  // Remove existing
  removeExisting();

  safeBadge = document.createElement("div");
  safeBadge.id = "phishguard-safe";
  safeBadge.setAttribute("style", `
    position:fixed; bottom:24px; right:24px;
    background:rgba(10,10,10,0.92); color:#34C759;
    padding:10px 18px; border-radius:24px;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    font-size:13px; font-weight:600;
    display:flex; align-items:center; gap:8px;
    z-index:2147483647;
    border:1px solid rgba(52,199,89,0.3);
    box-shadow:0 4px 20px rgba(0,0,0,0.4);
    pointer-events:none;
    animation: pgFadeIn 0.3s ease;
  `);

  safeBadge.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z" fill="rgba(52,199,89,0.25)" stroke="#34C759" stroke-width="2"/>
      <path d="M9 12l2 2 4-4" stroke="#34C759" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <span>Website scanned &mdash; safe</span>
  `;

  // Add animation keyframes
  const style = document.createElement("style");
  style.textContent = `
    @keyframes pgFadeIn { from { opacity:0; transform:translateY(12px); } to { opacity:1; transform:translateY(0); } }
  `;
  document.head.appendChild(style);
  document.body.appendChild(safeBadge);

  console.log("[PhishGuard] Safe badge displayed for:", getHostname(data.url));

  // Auto-remove after 3 seconds
  setTimeout(function() {
    if (safeBadge) {
      safeBadge.style.transition = "opacity 0.4s";
      safeBadge.style.opacity = "0";
      setTimeout(function() {
        if (safeBadge) {
          safeBadge.remove();
          safeBadge = null;
        }
      }, 400);
    }
  }, 3000);
}

// ── Helpers ─────────────────────────────────────────────────────
function removeExisting() {
  if (warningOverlay) { warningOverlay.remove(); warningOverlay = null; }
  if (safeBadge) { safeBadge.remove(); safeBadge = null; }

  // Also remove by ID in case of stale references
  const oldWarn = document.getElementById("phishguard-warning");
  if (oldWarn) oldWarn.remove();
  const oldSafe = document.getElementById("phishguard-safe");
  if (oldSafe) oldSafe.remove();
}

function sendFeedback(url, verdict) {
  chrome.runtime.sendMessage({
    type: "USER_FEEDBACK",
    feedback: { url: url, verdict: verdict, timestamp: new Date().toISOString() }
  }).catch(function() {});
}

function getHostname(url) {
  try { return new URL(url).hostname; } catch(e) { return url; }
}
