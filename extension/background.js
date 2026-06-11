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

// Track tabs with in-flight scans to prevent duplicate concurrent requests.
// Unlike before, this does NOT permanently cache results — every new page load
// triggers a fresh scan.
const scanningTabs = new Set();

// ── Extension installed / updated ──────────────────────────────
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log(`[PhishGuard] Extension ${details.reason} (v${chrome.runtime.getManifest().version}).`);

  // Only reset stats on fresh install, not on update
  if (details.reason === "install") {
    chrome.storage.local.set({ stats, alerts: [], feedbackLog: [] });
  }

  // Re-inject content scripts into all already-open tabs so the extension
  // works immediately after update — no need to delete and reinstall.
  await reinjectContentScripts();
});

// ── Re-inject content scripts into all open HTTP tabs ──────────
async function reinjectContentScripts() {
  const tabs = await chrome.tabs.query({ url: ["http://*/*", "https://*/*"] });
  console.log(`[PhishGuard] Re-injecting content scripts into ${tabs.length} open tab(s)...`);

  for (const tab of tabs) {
    try {
      // Inject the main content script into every HTTP tab
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["content.js"]
      });

      // Inject gmail_scanner.js only into Gmail/Outlook tabs
      const isEmailTab = /mail\.google\.com|outlook\.(live|office|office365)\.com/.test(tab.url);
      if (isEmailTab) {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ["gmail_scanner.js"]
        });
      }

      console.log(`[PhishGuard]   ✓ Injected into tab ${tab.id}: ${tab.url.slice(0, 60)}`);
    } catch (err) {
      // Some tabs may refuse injection (e.g. chrome:// pages that slipped through)
      console.warn(`[PhishGuard]   ✗ Could not inject into tab ${tab.id}: ${err.message}`);
    }
  }
}

// ── Automatic website scanning: chrome.tabs.onUpdated ──────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only act when the page has fully loaded
  if (changeInfo.status !== "complete") return;

  const url = tab.url;

  // Skip non-HTTP pages (chrome://, about:, extensions, etc.)
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return;

  // Skip only if this tab already has a scan in-flight (prevents duplicates)
  if (scanningTabs.has(tabId)) return;

  console.log(`[PhishGuard] Page loaded — scanning: ${url}`);
  scanningTabs.add(tabId);
  try {
    await sendForAnalysis(url, tabId);
  } finally {
    scanningTabs.delete(tabId);
  }
});

// Clean up when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  scanningTabs.delete(tabId);
});

// ── Wake-up ping: nudge Render out of cold sleep ────────────────
async function wakeUpBackend() {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort("wake-up ping timeout"), 10000);
    await fetch(`${API_BASE}/health`, {
      method: "GET",
      signal: controller.signal
    });
    clearTimeout(timeout);
    console.log("[PhishGuard] Backend is awake.");
  } catch {
    // Doesn't matter if it fails — the purpose is just to trigger the spin-up
    console.log("[PhishGuard] Wake-up ping sent (backend may still be starting).");
  }
}

// ── Send URL to backend /check_url (with retry for cold starts) ─
async function sendForAnalysis(url, tabId) {
  const MAX_RETRIES = 3;
  let lastError = null;

  // On first attempt, send a lightweight ping to wake up the Render server.
  // This triggers the cold-start process so the real request has a warm server.
  await wakeUpBackend();

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      // Generous timeouts: Render free tier can take 50-90s on cold start
      const timeoutMs = attempt === 0 ? 90000 : 30000;
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(`Request timed out after ${timeoutMs / 1000}s`),
        timeoutMs
      );

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
        // Exponential backoff: 8s → 12s → 16s (gives Render time to fully boot)
        const delay = 8000 + (attempt * 4000);
        console.warn(`[PhishGuard] Attempt ${attempt + 1}/${MAX_RETRIES + 1} failed: ${err.message}. Retrying in ${delay / 1000}s...`);
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }

  // All retries failed
  console.error(`[PhishGuard] Analysis failed after ${MAX_RETRIES + 1} attempts: ${lastError.message}`);
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
async function sendToContentScript(tabId, result, url) {
  const isPhishing = result.result === "phishing";

  // Guard: check if the tab still exists before interacting with it.
  // The tab may have been closed while the backend was responding.
  try {
    await chrome.tabs.get(tabId);
  } catch {
    console.warn(`[PhishGuard] Tab ${tabId} no longer exists — skipping UI update for ${url}`);
    // Still save to alert history below
    saveToAlertHistory(url, result, isPhishing);
    return;
  }

  try {
    // Update badge
    await chrome.action.setBadgeText({
      text: isPhishing ? "!" : "OK",
      tabId: tabId
    });
    await chrome.action.setBadgeBackgroundColor({
      color: isPhishing ? "#FF3B30" : "#34C759",
      tabId: tabId
    });
  } catch {
    // Tab may have closed between the check and the badge update — ignore
  }

  if (isPhishing) {
    // Redirect to warning page (works even if page didn't load)
    const reasons = (result.reasons || []).join("|");
    const warningUrl = chrome.runtime.getURL("warning.html") +
      `?url=${encodeURIComponent(url)}` +
      `&confidence=${result.confidence}` +
      `&reasons=${encodeURIComponent(reasons)}`;

    try {
      await chrome.tabs.update(tabId, { url: warningUrl });
    } catch {
      // Tab closed — warning can't be shown
    }

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
  saveToAlertHistory(url, result, isPhishing);
}

// ── Persist scan result to chrome.storage alert history ─────────
function saveToAlertHistory(url, result, isPhishing) {
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
    // Force rescan from popup — no cache to clear, every scan is fresh
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
