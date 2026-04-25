document.addEventListener("DOMContentLoaded", async () => {
  // Check if update is required
  const { update_required, update_info } = await chrome.storage.local.get(["update_required", "update_info"]);
  if (update_required && update_info) {
    document.getElementById("update-modal").style.display = "flex";
    document.getElementById("update-btn").href = update_info.download_url;
    return; // Block loading rest of the UI
  }

  await loadTab();
  await loadStats();
  await loadAlerts();
  await loadFeedback();

  // Tab switching
  document.querySelectorAll(".tab").forEach(t => {
    t.onclick = () => {
      document.querySelectorAll(".tab,.panel").forEach(el => el.classList.remove("active"));
      t.classList.add("active");
      document.getElementById(`panel-${t.dataset.panel}`).classList.add("active");
    };
  });

  // Clear history
  document.getElementById("btn-clear").onclick = async () => {
    chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" });
    await loadStats(); await loadAlerts(); await loadFeedback();
  };

  // ── Report Website Button ──────────────────────────────────────
  document.getElementById("btn-report").onclick = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      document.getElementById("report-url").textContent = new URL(tab.url).hostname;
      document.getElementById("report-modal").style.display = "flex";
    }
  };

  document.getElementById("report-cancel").onclick = () => {
    document.getElementById("report-modal").style.display = "none";
  };

  document.getElementById("report-submit").onclick = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const reason = document.getElementById("report-reason").value;
    const notes = document.getElementById("report-notes").value;

    chrome.runtime.sendMessage({
      type: "REPORT_WEBSITE",
      url: tab.url,
      reason: `${reason}${notes ? ': ' + notes : ''}`
    });

    document.getElementById("report-modal").style.display = "none";
    document.getElementById("report-notes").value = "";

    // Show success briefly
    const btn = document.getElementById("btn-report");
    const orig = btn.innerHTML;
    btn.innerHTML = '✓ Reported!';
    btn.style.background = 'rgba(52,199,89,.15)';
    btn.style.color = '#34C759';
    setTimeout(() => { btn.innerHTML = orig; btn.style.background = ''; btn.style.color = ''; }, 2000);
  };

  // ── Quick Scan Button ──────────────────────────────────────────
  document.getElementById("btn-quickscan").onclick = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url || !tab.url.startsWith("http")) return;

    const btn = document.getElementById("btn-quickscan");
    btn.innerHTML = '⟳ Scanning...';

    // Trigger rescan via background
    chrome.runtime.sendMessage({ type: "QUICK_SCAN", tabId: tab.id, url: tab.url });

    // Close popup after small delay
    setTimeout(() => window.close(), 800);
  };
  // ── Email Scanner Button ────────────────────────────────────────
  document.getElementById("btn-email-scanner").onclick = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("email_scanner.html") });
  };
});

async function loadTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  const urlEl = document.getElementById("cur-url");
  const stEl  = document.getElementById("cur-st");
  const ico   = document.getElementById("st-ico");
  const txt   = document.getElementById("st-txt");
  try {
    const u = new URL(tab.url);
    urlEl.textContent = u.hostname + (u.pathname.length > 28 ? u.pathname.slice(0,28)+"…" : u.pathname);
    const { alerts = [] } = await chrome.storage.local.get(["alerts"]);
    const hit = alerts.find(a => a.url === tab.url);
    if (hit) {
      const isPhish = hit.is_phishing || hit.result === "phishing";
      stEl.className = `url-st ${isPhish ? "danger" : "safe"}`;
      ico.textContent = isPhish ? "⚠" : "✓";
      txt.textContent = isPhish
        ? `Phishing Detected (${pct(hit.confidence)}% confidence)`
        : "Safe";
    } else if (tab.url.startsWith("http")) {
      stEl.className = "url-st scan"; ico.textContent = "⟳"; txt.textContent = "Scanning…";
    } else {
      stEl.className = "url-st"; stEl.style.color = "#555";
      ico.textContent = "–"; txt.textContent = "Not applicable";
    }
  } catch { urlEl.textContent = "–"; }
}

async function loadStats() {
  const { stats = {} } = await chrome.storage.local.get(["stats"]);
  document.getElementById("s-total").textContent = stats.totalScanned    || 0;
  document.getElementById("s-phish").textContent = stats.phishingDetected || 0;
  document.getElementById("s-safe" ).textContent = stats.safeDetected     || 0;
}

async function loadAlerts() {
  const { alerts = [] } = await chrome.storage.local.get(["alerts"]);
  const el = document.getElementById("al-list");
  if (!alerts.length) {
    el.innerHTML = `<div class="empty"><div class="empty-ico">🛡️</div>No activity yet.<br>Browse to start scanning.</div>`;
    return;
  }
  el.innerHTML = alerts.map(a => {
    const host = safeHost(a.url);
    const isPhish = a.is_phishing || a.result === "phishing";
    const cls  = isPhish ? "p" : "s";
    const lbl  = isPhish ? "Phishing" : "Safe";
    return `<div class="al">
      <div class="aldot ${cls}"></div>
      <div class="al-info">
        <div class="al-host" title="${a.url}">${host}</div>
        <div class="al-time">${ago(a.timestamp)}</div>
      </div>
      <div class="albadge ${cls}">${lbl}</div>
    </div>`;
  }).join("");
}

async function loadFeedback() {
  const { feedbackLog = [] } = await chrome.storage.local.get(["feedbackLog"]);
  const el = document.getElementById("fb-list");
  if (!feedbackLog.length) {
    el.innerHTML = `<div class="empty"><div class="empty-ico">💬</div>No feedback submitted yet.</div>`;
    return;
  }
  el.innerHTML = feedbackLog.map(f => {
    const labels = { safe:"Safe", phishing:"Phishing", user_proceeded:"Proceeded" };
    return `<div class="fb">
      <div class="fb-info" style="flex:1;overflow:hidden">
        <div style="font-size:11px;color:#999;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${safeHost(f.url)}</div>
        <div style="font-size:10px;color:#555">${ago(f.timestamp)}</div>
      </div>
      <div class="fb-verdict ${f.verdict}">${labels[f.verdict] || f.verdict}</div>
    </div>`;
  }).join("");
}

function safeHost(u) { try { return new URL(u).hostname; } catch { return u; } }
function pct(v) { return Math.round((v||0)*100); }
function ago(ts) {
  const s = Math.floor((Date.now() - new Date(ts)) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s/60); if (m < 60) return `${m}m ago`;
  return `${Math.floor(m/60)}h ago`;
}
