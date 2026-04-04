// ================================================================
// PhishGuard — background.js
// MODULE 1: Browser Extension Monitoring Module
//
// Automatically scans every website using chrome.tabs.onUpdated
// Sends URL to /check_url and forwards result to content.js
// ================================================================

const API_BASE = "https://phishguard-api-6dmc.onrender.com";
const CHECK_URL_ENDPOINT = `${API_BASE}/check_url`;

// ── Runtime stats ──────────────────────────────────────────────
let stats = { totalScanned: 0, phishingDetected: 0, safeDetected: 0, errors: 0 };

// ── Extension installed ────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishGuard] Extension installed and activated.");
  chrome.storage.local.set({ stats, alerts: [], feedbackLog: [] });
});

// ── Automatic website scanning: chrome.tabs.onUpdated ──────────
// Fires every time a tab finishes loading — for EVERY website
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only act when the page has fully loaded
  if (changeInfo.status !== "complete") return;

  const url = tab.url;

  // Skip non-HTTP pages (chrome://, about:, extensions, etc.)
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return;

  console.log(`[PhishGuard] Page loaded — scanning: ${url}`);

  // Always send for analysis (no cache — so popup shows EVERY time)
  await sendForAnalysis(url, tabId);
});

// ── Send URL to backend /check_url ─────────────────────────────
async function sendForAnalysis(url, tabId) {
  try {
    const res = await fetch(CHECK_URL_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Extension-ID": chrome.runtime.id
      },
      body: JSON.stringify({ url: url })
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    // Response: { "result": "safe" | "phishing", "confidence": 0.95 }
    const result = await res.json();

    console.log(`[PhishGuard] Result: ${result.result} (${(result.confidence * 100).toFixed(0)}%) — ${url}`);

    // Update stats
    stats.totalScanned++;
    if (result.result === "phishing") {
      stats.phishingDetected++;
    } else {
      stats.safeDetected++;
    }
    chrome.storage.local.set({ stats });

    // Send result to content.js for on-page display
    // Small delay to ensure content.js (document_idle) is ready
    setTimeout(() => {
      sendToContentScript(tabId, result, url);
    }, 500);

  } catch (err) {
    console.error("[PhishGuard] API error:", err.message);
    stats.errors++;
    chrome.storage.local.set({ stats });
  }
}

// ── Send result to content.js ──────────────────────────────────
function sendToContentScript(tabId, result, url) {
  const isPhishing = result.result === "phishing";

  // Update badge
  chrome.action.setBadgeText({
    text: isPhishing ? "!" : "OK",
    tabId: tabId
  });
  chrome.action.setBadgeBackgroundColor({
    color: isPhishing ? "#FF3B30" : "#34C759",
    tabId: tabId
  });

  // Send to content.js
  const message = {
    type: isPhishing ? "SHOW_WARNING" : "SAFE_SITE",
    url: url,
    result: result.result,
    confidence: result.confidence
  };

  chrome.tabs.sendMessage(tabId, message).catch((err) => {
    console.warn(`[PhishGuard] Could not reach content.js on tab ${tabId}:`, err.message);
  });

  // System notification for phishing
  if (isPhishing) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "PhishGuard Alert",
      message: `Phishing detected! ${safeHostname(url)}`,
      priority: 2
    });
  }

  // Save to alert history
  chrome.storage.local.get(["alerts"], (data) => {
    const alerts = [
      {
        url: url,
        result: result.result,
        confidence: result.confidence,
        is_phishing: isPhishing,
        timestamp: new Date().toISOString()
      },
      ...(data.alerts || [])
    ].slice(0, 50);
    chrome.storage.local.set({ alerts });
  });
}

// ── Popup message handler ──────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "GET_STATS") {
    reply({ stats });
  }
  if (msg.type === "CLEAR_HISTORY") {
    stats = { totalScanned: 0, phishingDetected: 0, safeDetected: 0, errors: 0 };
    chrome.storage.local.set({ stats, alerts: [] });
    reply({ ok: true });
  }
  if (msg.type === "USER_FEEDBACK") {
    chrome.storage.local.get(["feedbackLog"], (d) => {
      const feedbackLog = [msg.feedback, ...(d.feedbackLog || [])].slice(0, 200);
      chrome.storage.local.set({ feedbackLog });
    });
    reply({ ok: true });
  }
  return true;
});

function safeHostname(url) {
  try { return new URL(url).hostname; } catch { return url; }
}
