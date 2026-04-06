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

// Pages already scanned in this session (avoid double-scanning)
const scannedTabs = new Map();

// ── Extension installed ────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishGuard] Extension installed and activated.");
  chrome.storage.local.set({ stats, alerts: [], feedbackLog: [] });
});

// ── Automatic website scanning: chrome.tabs.onUpdated ──────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only act when the page has fully loaded
  if (changeInfo.status !== "complete") return;

  const url = tab.url;

  // Skip non-HTTP pages (chrome://, about:, extensions, etc.)
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return;

  // Skip if we already scanned this exact URL in this tab
  if (scannedTabs.get(tabId) === url) return;
  scannedTabs.set(tabId, url);

  console.log(`[PhishGuard] Page loaded — scanning: ${url}`);
  await sendForAnalysis(url, tabId);
});

// Clean up when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  scannedTabs.delete(tabId);
});

// ── Send URL to backend /check_url (with retry for cold starts) ─
async function sendForAnalysis(url, tabId) {
  const MAX_RETRIES = 3;
  let lastError = null;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      // First attempt: 30s (Render cold start), retries: 15s
      const timeoutMs = attempt === 0 ? 30000 : 15000;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      const res = await fetch(CHECK_URL_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Extension-ID": chrome.runtime.id
        },
        body: JSON.stringify({ url }),
        signal: controller.signal
      });

      clearTimeout(timeout);

      if (!res.ok) {
        throw new Error(`Backend returned status ${res.status}`);
      }

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

      // Send result to content.js immediately
      sendToContentScript(tabId, result, url);

      return; // Success — exit retry loop

    } catch (err) {
      lastError = err;

      if (attempt < MAX_RETRIES) {
        // Render cold start takes ~30s — give it time
        const delay = attempt === 0 ? 5000 : 3000;
        console.warn(`[PhishGuard] Attempt ${attempt + 1} failed: ${err.message}. Retrying in ${delay/1000}s...`);
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }

  // All retries failed
  console.error(`[PhishGuard] Analysis failed: ${lastError.message}`);
  stats.errors++;
  chrome.storage.local.set({ stats });

  // Notify content.js about the error
  chrome.tabs.sendMessage(tabId, {
    type: "ANALYSIS_ERROR",
    error: lastError.message,
    url: url
  }).catch(() => {});
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

  if (isPhishing) {
    // Redirect to warning page (works even if page didn't load)
    const reasons = (result.reasons || []).join("|");
    const warningUrl = chrome.runtime.getURL("warning.html") +
      `?url=${encodeURIComponent(url)}` +
      `&confidence=${result.confidence}` +
      `&reasons=${encodeURIComponent(reasons)}`;

    chrome.tabs.update(tabId, { url: warningUrl });

    // Also try to send to content.js (backup for pages that loaded)
    chrome.tabs.sendMessage(tabId, {
      type: "SHOW_WARNING",
      url: url,
      result: result.result,
      confidence: result.confidence,
      reasons: result.reasons || []
    }).catch(() => {});

    // System notification
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "PhishGuard Alert",
      message: `Phishing detected! ${safeHostname(url)}`,
      priority: 2
    });
  } else {
    // Safe site — send indicator to content.js
    chrome.tabs.sendMessage(tabId, {
      type: "ANALYSIS_COMPLETE",
      url: url,
      result: result.result,
      confidence: result.confidence,
      is_phishing: false
    }).catch(() => {});
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

// ── Keyboard shortcut: Ctrl+Shift+P ────────────────────────────
chrome.commands.onCommand.addListener(async (command) => {
  if (command === "quick-scan") {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return;
    if (!tab.url.startsWith("http://") && !tab.url.startsWith("https://")) return;

    console.log(`[PhishGuard] Quick Scan (Ctrl+Shift+P): ${tab.url}`);

    // Force rescan (clear cache for this tab)
    scannedTabs.delete(tab.id);

    // Show scanning notification
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "PhishGuard — Quick Scan",
      message: `Scanning: ${safeHostname(tab.url)}`,
      priority: 1
    });

    await sendForAnalysis(tab.url, tab.id);
  }
});

// ── Popup message handler ──────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "GET_STATS") {
    reply({ stats });
  }
  if (msg.type === "QUICK_SCAN") {
    // Force rescan from popup
    scannedTabs.delete(msg.tabId);
    sendForAnalysis(msg.url, msg.tabId);
    reply({ ok: true });
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
  if (msg.type === "REPORT_WEBSITE") {
    const report = {
      url: msg.url,
      reason: msg.reason || "User reported as suspicious",
      timestamp: new Date().toISOString()
    };

    // Save to local reports
    chrome.storage.local.get(["reports"], (d) => {
      const reports = [report, ...(d.reports || [])].slice(0, 100);
      chrome.storage.local.set({ reports });
    });

    // Send report to backend (fire and forget)
    fetch(`${API_BASE}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report)
    }).catch(() => {});

    // Notify user
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "PhishGuard — Report Submitted",
      message: `Thank you! ${safeHostname(msg.url)} has been reported.`,
      priority: 1
    });

    reply({ ok: true });
  }
  return true;
});

function safeHostname(url) {
  try { return new URL(url).hostname; } catch { return url; }
}
