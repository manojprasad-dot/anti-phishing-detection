// ============================================================
// PhishGuard - Content Script
// Shows status indicator on every page load
// ============================================================

let statusBadge = null;

// Show "Scanning..." immediately when page loads
showScanningBadge();

// Listen for messages from background service worker
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case "SHOW_WARNING":
      showPhishingBadge(message);
      break;
    case "ANALYSIS_COMPLETE":
      showSafeBadge(message);
      break;
    case "ANALYSIS_ERROR":
      showErrorBadge(message.error);
      break;
  }
});

// ─── Inject Styles Once ──────────────────────────────────────
const style = document.createElement("style");
style.textContent = `
  #phishguard-badge {
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 10px 18px;
    border-radius: 12px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 13px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 8px;
    z-index: 2147483647;
    animation: pg-badge-in 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
    cursor: default;
    user-select: none;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    transition: opacity 0.5s ease, transform 0.5s ease;
  }
  #phishguard-badge.scanning {
    background: rgba(30,30,30,0.95);
    color: #aaa;
    border: 1px solid rgba(255,255,255,0.1);
  }
  #phishguard-badge.safe {
    background: rgba(20,30,20,0.95);
    color: #34C759;
    border: 1px solid rgba(52,199,89,0.3);
  }
  #phishguard-badge.warning {
    background: rgba(40,15,15,0.95);
    color: #FF3B30;
    border: 1px solid rgba(255,59,48,0.4);
  }
  #phishguard-badge.error {
    background: rgba(30,25,10,0.95);
    color: #FF9500;
    border: 1px solid rgba(255,149,0,0.3);
  }
  #phishguard-badge .pg-spinner {
    width: 14px; height: 14px;
    border: 2px solid rgba(255,255,255,0.2);
    border-top-color: #aaa;
    border-radius: 50%;
    animation: pg-spin 0.8s linear infinite;
  }
  #phishguard-badge .pg-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  #phishguard-badge .pg-dot.green { background: #34C759; box-shadow: 0 0 6px rgba(52,199,89,0.5); }
  #phishguard-badge .pg-dot.red { background: #FF3B30; box-shadow: 0 0 6px rgba(255,59,48,0.5); }
  #phishguard-badge .pg-dot.orange { background: #FF9500; }
  @keyframes pg-badge-in {
    from { transform: translateY(20px) scale(0.9); opacity: 0; }
    to { transform: translateY(0) scale(1); opacity: 1; }
  }
  @keyframes pg-spin {
    to { transform: rotate(360deg); }
  }
  @keyframes pg-fade-out {
    to { opacity: 0; transform: translateY(10px); }
  }
`;
document.head.appendChild(style);

// ─── Scanning Badge (shown immediately) ──────────────────────
function showScanningBadge() {
  removeBadge();
  statusBadge = document.createElement("div");
  statusBadge.id = "phishguard-badge";
  statusBadge.className = "scanning";
  statusBadge.innerHTML = `
    <div class="pg-spinner"></div>
    <span>PhishGuard scanning...</span>
  `;
  document.body.appendChild(statusBadge);
}

// ─── Safe Badge ──────────────────────────────────────────────
function showSafeBadge(data) {
  removeBadge();
  statusBadge = document.createElement("div");
  statusBadge.id = "phishguard-badge";
  statusBadge.className = "safe";

  const conf = Math.round((1 - (data.confidence || 0)) * 100);
  statusBadge.innerHTML = `
    <div class="pg-dot green"></div>
    <span>Safe — verified by PhishGuard</span>
  `;
  document.body.appendChild(statusBadge);

  // Fade out after 5 seconds
  setTimeout(() => {
    if (statusBadge) {
      statusBadge.style.animation = "pg-fade-out 0.5s ease forwards";
      setTimeout(() => removeBadge(), 600);
    }
  }, 5000);
}

// ─── Phishing Badge (backup — main flow uses warning.html) ───
function showPhishingBadge(data) {
  removeBadge();
  statusBadge = document.createElement("div");
  statusBadge.id = "phishguard-badge";
  statusBadge.className = "warning";

  const conf = Math.round((data.confidence || 0) * 100);
  statusBadge.innerHTML = `
    <div class="pg-dot red"></div>
    <span>⚠ Phishing detected (${conf}% confidence)</span>
  `;
  document.body.appendChild(statusBadge);
  // This badge stays visible (no auto-hide for phishing)
}

// ─── Error Badge ─────────────────────────────────────────────
function showErrorBadge(error) {
  removeBadge();
  statusBadge = document.createElement("div");
  statusBadge.id = "phishguard-badge";
  statusBadge.className = "error";
  statusBadge.innerHTML = `
    <div class="pg-dot orange"></div>
    <span>PhishGuard: could not scan</span>
  `;
  document.body.appendChild(statusBadge);

  // Fade out after 4 seconds
  setTimeout(() => {
    if (statusBadge) {
      statusBadge.style.animation = "pg-fade-out 0.5s ease forwards";
      setTimeout(() => removeBadge(), 600);
    }
  }, 4000);
}

// ─── Remove Badge ────────────────────────────────────────────
function removeBadge() {
  if (statusBadge) {
    statusBadge.remove();
    statusBadge = null;
  }
  // Also remove any leftover badges
  const old = document.getElementById("phishguard-badge");
  if (old) old.remove();
}
