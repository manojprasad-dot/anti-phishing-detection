// ================================================================
// PhishGuard — background.js
// MODULE 1: Browser Extension Monitoring Module
// Monitors all navigation events and coordinates the full pipeline
// ================================================================

const API_BASE    = "http://localhost:5000";
const ANALYZE_URL = `${API_BASE}/analyze`;

// ── In-memory cache: url → { result, ts } ──────────────────────
const cache    = new Map();
const CACHE_MS = 5 * 60 * 1000; // 5 min

// ── Runtime stats ──────────────────────────────────────────────
let stats = { totalScanned: 0, phishingDetected: 0, safeDetected: 0, errors: 0 };

// ── [01] Extension installed ───────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishGuard] Extension installed and activated.");
  chrome.storage.local.set({ stats, alerts: [], feedbackLog: [] });
});

// ── [02] Background monitoring via webNavigation ───────────────
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;                         // main frame only
  const url = details.url;
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;

  // [03] User navigated to a website
  console.log(`[PhishGuard] Navigation captured: ${url}`);

  // [04] URL captured — check cache first
  const cached = getCache(url);
  if (cached) {
    handleResult(cached, url, details.tabId);
    return;
  }

  // [05] Prepare analysis payload
  const payload = { url, timestamp: new Date().toISOString(), tab_id: details.tabId };

  // [06] Send to backend API
  await sendForAnalysis(payload, details.tabId);
});

// ── [06-08] API call ───────────────────────────────────────────
async function sendForAnalysis(payload, tabId) {
  try {
    // [06] Secure request to backend
    const res = await fetch(ANALYZE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Extension-ID": chrome.runtime.id },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    // [08] Response received
    const result = await res.json();
    setCache(payload.url, result);

    // Stats
    stats.totalScanned++;
    result.is_phishing ? stats.phishingDetected++ : stats.safeDetected++;
    chrome.storage.local.set({ stats });

    // [09] Process result
    handleResult(result, payload.url, tabId);

  } catch (err) {
    console.error("[PhishGuard] API error:", err);
    stats.errors++;
    chrome.storage.local.set({ stats });
    chrome.tabs.sendMessage(tabId, { type: "ANALYSIS_ERROR", error: err.message }).catch(() => {});
  }
}

// ── [09-10] Handle result from backend ────────────────────────
function handleResult(result, url, tabId) {
  // Update badge
  chrome.action.setBadgeText({ text: result.is_phishing ? "!" : "✓", tabId });
  chrome.action.setBadgeBackgroundColor({ color: result.is_phishing ? "#FF3B30" : "#34C759", tabId });

  // Forward to content script (Module 3)
  chrome.tabs.sendMessage(tabId, {
    type: result.is_phishing ? "SHOW_WARNING" : "ANALYSIS_COMPLETE",
    url, ...result
  }).catch(() => {});

  // [10] Security warning if phishing
  if (result.is_phishing) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "⚠️ PhishGuard Alert",
      message: `Phishing detected!\n${safeHostname(url)}`,
      priority: 2
    });
  }

  // Save to alert history
  chrome.storage.local.get(["alerts"], (data) => {
    const alerts = [
      { url, ...result, timestamp: new Date().toISOString() },
      ...(data.alerts || [])
    ].slice(0, 50);
    chrome.storage.local.set({ alerts });
  });
}

// ── Popup message handler ──────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "GET_STATS")        reply({ stats });
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

// ── Cache helpers ──────────────────────────────────────────────
function getCache(url) {
  const e = cache.get(url);
  if (!e || Date.now() - e.ts > CACHE_MS) { cache.delete(url); return null; }
  return e.result;
}
function setCache(url, result) {
  if (cache.size > 500) cache.delete(cache.keys().next().value);
  cache.set(url, { result, ts: Date.now() });
}
function safeHostname(url) {
  try { return new URL(url).hostname; } catch { return url; }
}
