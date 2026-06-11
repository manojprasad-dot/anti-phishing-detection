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

// ── Wake-up ping: poll Render until the server is alive ─────────
// Render free tier takes 50-90s to cold start. We poll /health
// every few seconds and only proceed once we get a 200 OK.
async function wakeUpBackend(tabId) {
  const MAX_WAIT_MS = 120_000; // 2 minutes max
  const POLL_INTERVAL = 5_000; // check every 5s
  const startTime = Date.now();

  // Quick check — server might already be warm
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(`${API_BASE}/health`, { signal: controller.signal });
    clearTimeout(t);
    if (res.ok) {
      console.log("[PhishGuard] Backend is already warm.");
      return true;
    }
  } catch { /* expected during cold start */ }

  // Server is cold — start polling and notify the user
  console.log("[PhishGuard] Backend is cold — waiting for it to wake up...");
  notifyTab(tabId, {
    type: "SCANNING_DELAYED",
    message: "Server waking up — please wait..."
  });

  while (Date.now() - startTime < MAX_WAIT_MS) {
    await new Promise(r => setTimeout(r, POLL_INTERVAL));

    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(`${API_BASE}/health`, { signal: controller.signal });
      clearTimeout(t);

      if (res.ok) {
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
        console.log(`[PhishGuard] Backend is awake after ${elapsed}s.`);
        return true;
      }
    } catch {
      // Still booting — keep waiting
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
      console.log(`[PhishGuard] Still waiting for backend... (${elapsed}s)`);
    }
  }

  // Gave up after 2 minutes
  console.error("[PhishGuard] Backend did not wake up within 2 minutes.");
  return false;
}

// ── Safe helper to message a tab (fire-and-forget) ──────────────
function notifyTab(tabId, message) {
  chrome.tabs.sendMessage(tabId, message).catch(() => {});
}

// ── Send URL to backend /check_url ──────────────────────────────
async function sendForAnalysis(url, tabId) {
  // Step 1: Make sure the backend is alive before sending the real request
  const serverReady = await wakeUpBackend(tabId);

  if (!serverReady) {
    stats.errors++;
    chrome.storage.local.set({ stats });
    notifyTab(tabId, {
      type: "ANALYSIS_ERROR",
      error: "Backend server is unavailable. Please try again later.",
      url: url
    });
    return;
  }

  // Step 2: Server is warm — send the real request (with 1 retry for safety)
  const MAX_RETRIES = 1;
  let lastError = null;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort("Request timed out"),
        30000 // 30s is plenty for a warm server
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

      return; // Success — exit

    } catch (err) {
      lastError = err;

      if (attempt < MAX_RETRIES) {
        console.warn(`[PhishGuard] Attempt ${attempt + 1} failed: ${err.message}. Retrying in 3s...`);
        await new Promise(r => setTimeout(r, 3000));
      }
    }
  }

  // All retries failed
  console.error(`[PhishGuard] Analysis failed: ${lastError.message}`);
  stats.errors++;
  chrome.storage.local.set({ stats });

  notifyTab(tabId, {
    type: "ANALYSIS_ERROR",
    error: lastError.message,
    url: url
  });
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
