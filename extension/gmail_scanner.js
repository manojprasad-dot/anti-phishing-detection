// ============================================================
// PhishGuard — gmail_scanner.js
// MODULE 7: Automatic Email Phishing Scanner
//
// Automatically detects when a user opens an email in Gmail or
// Outlook and scans it for phishing indicators in real-time.
//
// Uses simple polling (every 1.5s) to detect email changes.
// This is the most reliable approach for SPAs like Gmail that
// don't trigger page reloads when navigating between emails.
//
// Supported:
//   ✔ Gmail (mail.google.com)
//   ✔ Outlook Web (outlook.live.com, outlook.office.com)
// ============================================================

const API_BASE = "https://phishguard-api-6dmc.onrender.com";
const CHECK_EMAIL_URL = `${API_BASE}/check_email`;

// The fingerprint of the last scanned email — prevents re-scanning
// the same email while it's still on screen.
let lastScannedFingerprint = null;

// Track the last URL to detect navigation
let lastUrl = window.location.href;

// Flag to prevent overlapping scans
let isScanning = false;

// Detect which email provider we're on
const HOST = window.location.hostname;
const IS_GMAIL = HOST.includes("mail.google.com");
const IS_OUTLOOK = HOST.includes("outlook.live.com") || HOST.includes("outlook.office.com") || HOST.includes("outlook.office365.com");

console.log(`[PhishGuard Email] Loaded on ${IS_GMAIL ? "Gmail" : IS_OUTLOOK ? "Outlook" : HOST}`);

// ── Start the scanner ────────────────────────────────────────

if (IS_GMAIL || IS_OUTLOOK) {
  // Give the page time to load, then start polling
  setTimeout(() => {
    console.log("[PhishGuard Email] Scanner started — polling every 1.5s");
    setInterval(pollForEmail, 1500);
    pollForEmail(); // Check immediately
  }, 2500);
}

// ── Main polling function ────────────────────────────────────
// Runs every 1.5 seconds. Checks if the user is viewing an email
// and whether it's different from the last one we scanned.

function pollForEmail() {
  try {
    // Detect URL changes (Gmail changes hash on navigation)
    const currentUrl = window.location.href;
    if (currentUrl !== lastUrl) {
      console.log("[PhishGuard Email] Navigation detected");
      lastUrl = currentUrl;
      lastScannedFingerprint = null; // Force rescan on navigation
    }

    if (IS_GMAIL) {
      pollGmail();
    } else if (IS_OUTLOOK) {
      pollOutlook();
    }
  } catch (err) {
    console.warn("[PhishGuard Email] Poll error:", err.message);
  }
}

// ── Gmail: Find and scan the currently visible email ─────────

function pollGmail() {
  // Find all email body elements — try multiple selectors
  // .a3s.aiL = expanded email body (primary)
  // .a3s = email body container (fallback)
  // .ii.gt = another Gmail email body class
  let emailBodies = document.querySelectorAll(".a3s.aiL");
  if (!emailBodies.length) emailBodies = document.querySelectorAll(".a3s");
  if (!emailBodies.length) emailBodies = document.querySelectorAll(".ii.gt");

  if (!emailBodies.length) {
    // No email is open (user is on inbox/list view)
    lastScannedFingerprint = null;
    return;
  }

  // Find the VISIBLE email body (Gmail may keep old ones in DOM)
  let emailBody = null;
  for (const el of emailBodies) {
    if (el.offsetHeight > 0 && el.offsetWidth > 0) {
      emailBody = el; // Take the last visible one
    }
  }
  if (!emailBody) emailBody = emailBodies[emailBodies.length - 1];

  const bodyText = (emailBody.innerText || emailBody.textContent || "").trim();
  if (bodyText.length < 20) return;

  // Extract sender
  let sender = "";
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
    subject = (subjectEl.textContent || "").trim();
  }

  // Build fingerprint from URL hash + sender + subject + body snippet
  // Using URL hash ensures different emails always get different fingerprints
  const urlHash = window.location.hash || "";
  const fingerprint = hashString(`${urlHash}|${sender}|${subject}|${bodyText.substring(0, 300)}`);

  // Skip if we already scanned this exact email
  if (fingerprint === lastScannedFingerprint) return;

  // Skip if another scan is in progress
  if (isScanning) return;

  // New email detected — scan it!
  lastScannedFingerprint = fingerprint;
  const bodyHtml = emailBody.innerHTML || "";

  console.log(`[PhishGuard Email] New email detected — sender: ${sender}, subject: ${subject.substring(0, 40)}`);
  scanEmail(bodyText, bodyHtml, sender, subject, emailBody);
}

// ── Outlook: Find and scan the currently visible email ───────

function pollOutlook() {
  const readingPane = document.querySelector("[role='document']") ||
                      document.querySelector(".ReadingPaneContents") ||
                      document.querySelector("[aria-label='Message body']") ||
                      document.querySelector(".wide-content-host");

  if (!readingPane) {
    lastScannedFingerprint = null;
    return;
  }

  const bodyText = (readingPane.innerText || readingPane.textContent || "").trim();
  if (bodyText.length < 20) return;

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
    subject = (subjectEl.textContent || "").trim();
  }

  // Build fingerprint
  const fingerprint = hashString(`${sender}|${subject}|${bodyText.substring(0, 300)}`);

  if (fingerprint === lastScannedFingerprint) return;
  if (isScanning) return;

  lastScannedFingerprint = fingerprint;
  const bodyHtml = readingPane.innerHTML || "";

  console.log(`[PhishGuard Email] Outlook email detected — sender: ${sender}, subject: ${subject.substring(0, 40)}`);
  scanEmail(bodyText, bodyHtml, sender, subject, readingPane);
}

// ── Send email to backend for analysis ───────────────────────

async function scanEmail(bodyText, bodyHtml, sender, subject, containerEl) {
  isScanning = true;

  // Remove any existing PhishGuard banners on the page
  document.querySelectorAll(".pg-email-banner").forEach(b => b.remove());

  // Show scanning indicator
  showEmailBanner(containerEl, "scanning", null);

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort("Email scan timed out"), 60000);

    const res = await fetch(CHECK_EMAIL_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Extension-ID": chrome.runtime.id,
      },
      body: JSON.stringify({
        email_text: bodyText,
        email_html: bodyHtml || "",
        sender: sender,
        subject: subject,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!res.ok) throw new Error(`Server ${res.status}`);

    const result = await res.json();

    console.log(`[PhishGuard Email] Result: ${result.result} (${(result.confidence * 100).toFixed(0)}%)`);

    // Show result banner (only if user is still on the same email)
    showEmailBanner(containerEl, result.result, result);

  } catch (err) {
    console.warn(`[PhishGuard Email] Scan failed: ${err.message}`);
    showEmailBanner(containerEl, "error", { error: err.message });
  } finally {
    isScanning = false;
  }
}

// ── Show inline banner above the email ───────────────────────

function showEmailBanner(containerEl, status, result) {
  // Remove ALL existing banners (clean slate)
  document.querySelectorAll(".pg-email-banner").forEach(b => b.remove());

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
  if (containerEl && containerEl.parentElement) {
    containerEl.parentElement.insertBefore(banner, containerEl);
  }
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

function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  return hash.toString(36);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
