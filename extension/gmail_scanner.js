// ============================================================
// PhishGuard — gmail_scanner.js
// MODULE 7: Automatic Email Phishing Scanner
//
// Automatically detects when a user opens an email in Gmail or
// Outlook and scans it for phishing indicators in real-time.
//
// Supported:
//   ✔ Gmail (mail.google.com)
//   ✔ Outlook Web (outlook.live.com, outlook.office.com)
// ============================================================

const API_BASE = "https://phishguard-api-6dmc.onrender.com";
const CHECK_EMAIL_URL = `${API_BASE}/check_email`;

// Track scanned emails to avoid re-scanning
const scannedEmails = new Set();

// Detect which email provider we're on
const HOST = window.location.hostname;
const IS_GMAIL = HOST.includes("mail.google.com");
const IS_OUTLOOK = HOST.includes("outlook.live.com") || HOST.includes("outlook.office.com") || HOST.includes("outlook.office365.com");

console.log(`[PhishGuard Email] Active on ${IS_GMAIL ? "Gmail" : IS_OUTLOOK ? "Outlook" : HOST}`);

// ── Start observing for opened emails ────────────────────────

if (IS_GMAIL || IS_OUTLOOK) {
  // Wait for page to be fully interactive
  setTimeout(() => startObserver(), 2000);
}

function startObserver() {
  // Watch for DOM changes (email opens trigger DOM mutations)
  const observer = new MutationObserver(debounce(() => {
    checkForOpenEmail();
  }, 800));

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });

  // Also check immediately on load
  checkForOpenEmail();
  console.log("[PhishGuard Email] Observer started — watching for opened emails");
}

// ── Check if an email is currently open ──────────────────────

function checkForOpenEmail() {
  if (IS_GMAIL) {
    checkGmail();
  } else if (IS_OUTLOOK) {
    checkOutlook();
  }
}

// ── Gmail Extraction ─────────────────────────────────────────

function checkGmail() {
  // Gmail email body container
  const emailBodies = document.querySelectorAll(".a3s.aiL");
  if (!emailBodies.length) return;

  // Get the latest/visible email body
  const emailBody = emailBodies[emailBodies.length - 1];
  const bodyText = emailBody.innerText || emailBody.textContent || "";

  if (!bodyText || bodyText.length < 20) return;

  // Create a fingerprint to avoid re-scanning
  const fingerprint = hashString(bodyText.substring(0, 200));
  if (scannedEmails.has(fingerprint)) return;
  scannedEmails.add(fingerprint);

  // Extract sender
  let sender = "";
  // Gmail sender: span with email attribute or .gD class
  const senderEl = document.querySelector(".gD[email]") ||
                   document.querySelector("span[email]");
  if (senderEl) {
    sender = senderEl.getAttribute("email") || senderEl.textContent || "";
  }

  // Extract subject
  let subject = "";
  const subjectEl = document.querySelector("h2.hP") ||
                    document.querySelector("[data-thread-perm-id] h2") ||
                    document.querySelector(".ha h2");
  if (subjectEl) {
    subject = subjectEl.textContent || "";
  }

  // Get full HTML for link analysis
  const bodyHtml = emailBody.innerHTML || "";

  console.log(`[PhishGuard Email] Gmail email detected — sender: ${sender}, subject: ${subject.substring(0, 40)}`);
  scanEmail(bodyText, bodyHtml, sender, subject, emailBody);
}

// ── Outlook Extraction ───────────────────────────────────────

function checkOutlook() {
  // Outlook reading pane
  const readingPane = document.querySelector("[role='document']") ||
                      document.querySelector(".ReadingPaneContents") ||
                      document.querySelector("[aria-label='Message body']") ||
                      document.querySelector(".wide-content-host");

  if (!readingPane) return;

  const bodyText = readingPane.innerText || readingPane.textContent || "";
  if (!bodyText || bodyText.length < 20) return;

  const fingerprint = hashString(bodyText.substring(0, 200));
  if (scannedEmails.has(fingerprint)) return;
  scannedEmails.add(fingerprint);

  // Extract sender
  let sender = "";
  const senderEl = document.querySelector("[role='heading'] span[title*='@']") ||
                   document.querySelector(".lpc_hdr_m span") ||
                   document.querySelector("[autoid='__header_sender']");
  if (senderEl) {
    sender = senderEl.getAttribute("title") || senderEl.textContent || "";
    const emailMatch = sender.match(/[\w.+-]+@[\w.-]+/);
    if (emailMatch) sender = emailMatch[0];
  }

  // Extract subject
  let subject = "";
  const subjectEl = document.querySelector("[role='heading']") ||
                    document.querySelector(".lpc_hdr_s");
  if (subjectEl) {
    subject = subjectEl.textContent || "";
  }

  const bodyHtml = readingPane.innerHTML || "";

  console.log(`[PhishGuard Email] Outlook email detected — sender: ${sender}, subject: ${subject.substring(0, 40)}`);
  scanEmail(bodyText, bodyHtml, sender, subject, readingPane);
}

// ── Send email to backend for analysis ───────────────────────

async function scanEmail(bodyText, bodyHtml, sender, subject, containerEl) {
  // Show scanning indicator
  showEmailBanner(containerEl, "scanning", null);

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    const res = await fetch(CHECK_EMAIL_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Extension-ID": chrome.runtime.id,
      },
      body: JSON.stringify({
        email_text: bodyHtml || bodyText,  // Prefer HTML for link analysis
        sender: sender,
        subject: subject,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!res.ok) throw new Error(`Server ${res.status}`);

    const result = await res.json();

    console.log(`[PhishGuard Email] Result: ${result.result} (${(result.confidence * 100).toFixed(0)}%)`);

    // Show result banner
    showEmailBanner(containerEl, result.result, result);

  } catch (err) {
    console.warn(`[PhishGuard Email] Scan failed: ${err.message}`);
    showEmailBanner(containerEl, "error", { error: err.message });
  }
}

// ── Show inline banner above/below the email ─────────────────

function showEmailBanner(containerEl, status, result) {
  // Remove existing banner
  const existingBanner = containerEl.parentElement?.querySelector(".pg-email-banner");
  if (existingBanner) existingBanner.remove();

  const banner = document.createElement("div");
  banner.className = "pg-email-banner";

  if (status === "scanning") {
    banner.innerHTML = `
      <div class="pg-email-banner-inner pg-scanning">
        <div class="pg-email-spinner"></div>
        <span>PhishGuard is scanning this email...</span>
      </div>
    `;
  } else if (status === "phishing") {
    const confidence = Math.round((result.confidence || 0) * 100);
    const reasons = (result.reasons || []).slice(0, 4);
    banner.innerHTML = `
      <div class="pg-email-banner-inner pg-phishing">
        <div class="pg-email-banner-header">
          <div class="pg-email-icon-warn">⚠</div>
          <div class="pg-email-banner-text">
            <strong>PhishGuard: Phishing Email Detected</strong>
            <span class="pg-email-conf">Threat confidence: ${confidence}%</span>
          </div>
        </div>
        ${reasons.length > 0 ? `
          <div class="pg-email-reasons">
            ${reasons.map(r => `<div class="pg-email-reason">• ${escapeHtml(r)}</div>`).join("")}
          </div>
        ` : ""}
        <div class="pg-email-actions">
          <span class="pg-email-tip">Do not click any links or download attachments from this email.</span>
        </div>
      </div>
    `;
  } else if (status === "safe") {
    banner.innerHTML = `
      <div class="pg-email-banner-inner pg-safe">
        <div class="pg-email-icon-safe">✓</div>
        <div class="pg-email-banner-text">
          <strong>PhishGuard: Email appears safe</strong>
        </div>
      </div>
    `;
    // Auto-hide safe banner after 6 seconds
    setTimeout(() => {
      banner.style.transition = "opacity 0.5s, max-height 0.5s";
      banner.style.opacity = "0";
      banner.style.maxHeight = "0";
      setTimeout(() => banner.remove(), 600);
    }, 6000);
  } else if (status === "error") {
    banner.innerHTML = `
      <div class="pg-email-banner-inner pg-error">
        <span>⚡ PhishGuard: Could not scan this email</span>
      </div>
    `;
    setTimeout(() => {
      banner.style.transition = "opacity 0.5s";
      banner.style.opacity = "0";
      setTimeout(() => banner.remove(), 600);
    }, 5000);
  }

  // Insert banner before the email body
  containerEl.parentElement?.insertBefore(banner, containerEl);
}

// ── Inject banner styles ─────────────────────────────────────

const emailStyles = document.createElement("style");
emailStyles.textContent = `
  .pg-email-banner {
    margin: 8px 0 12px 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    animation: pgEmailSlide 0.35s cubic-bezier(0.34, 1.2, 0.64, 1);
    overflow: hidden;
  }
  @keyframes pgEmailSlide {
    from { opacity: 0; transform: translateY(-8px); max-height: 0; }
    to { opacity: 1; transform: translateY(0); max-height: 300px; }
  }
  .pg-email-banner-inner {
    border-radius: 12px;
    padding: 14px 18px;
    font-size: 13px;
    line-height: 1.5;
  }
  /* Scanning */
  .pg-scanning {
    background: #1a1a2e;
    border: 1px solid rgba(100,100,255,0.2);
    color: #aab;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .pg-email-spinner {
    width: 16px; height: 16px;
    border: 2px solid rgba(100,100,255,0.2);
    border-top-color: #7878ff;
    border-radius: 50%;
    animation: pgSpin 0.7s linear infinite;
    flex-shrink: 0;
  }
  @keyframes pgSpin { to { transform: rotate(360deg); } }

  /* Phishing */
  .pg-phishing {
    background: linear-gradient(135deg, #2a0a0a, #1a0505);
    border: 1px solid rgba(255,59,48,0.35);
    color: #f5bbb5;
  }
  .pg-email-banner-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
  }
  .pg-email-icon-warn {
    width: 36px; height: 36px;
    background: rgba(255,59,48,0.15);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px; flex-shrink: 0;
    animation: pgPulseRed 2s ease infinite;
  }
  @keyframes pgPulseRed {
    0%, 100% { box-shadow: 0 0 0 0 rgba(255,59,48,0.3); }
    50% { box-shadow: 0 0 0 10px rgba(255,59,48,0); }
  }
  .pg-email-banner-text strong {
    display: block;
    color: #FF3B30;
    font-size: 14px;
    font-weight: 700;
  }
  .pg-email-conf {
    font-size: 12px;
    color: #ff8a80;
  }
  .pg-email-reasons {
    margin: 8px 0 8px 48px;
    padding: 8px 12px;
    background: rgba(255,59,48,0.06);
    border-radius: 8px;
    border-left: 3px solid rgba(255,59,48,0.4);
  }
  .pg-email-reason {
    font-size: 12px;
    color: #e8a8a0;
    padding: 2px 0;
  }
  .pg-email-actions {
    margin-left: 48px;
  }
  .pg-email-tip {
    font-size: 11px;
    color: #FF6B5E;
    font-weight: 600;
  }

  /* Safe */
  .pg-safe {
    background: #0a1a0f;
    border: 1px solid rgba(52,199,89,0.25);
    color: #89d9a0;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .pg-email-icon-safe {
    width: 28px; height: 28px;
    background: rgba(52,199,89,0.15);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 14px; flex-shrink: 0;
    color: #34C759;
    font-weight: bold;
  }
  .pg-safe strong { color: #34C759; }

  /* Error */
  .pg-error {
    background: #1a1508;
    border: 1px solid rgba(255,149,0,0.2);
    color: #c9a060;
    font-size: 12px;
    padding: 10px 16px;
  }
`;
document.head.appendChild(emailStyles);


// ── Utility functions ────────────────────────────────────────

function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0; // Convert to 32bit integer
  }
  return hash.toString(36);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
