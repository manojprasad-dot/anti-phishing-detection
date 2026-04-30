// PhishGuard — email_scanner.js
// Handles email scanning UI: file upload, paste, API calls, and result display

const API_BASE = "https://phishguard-api-6dmc.onrender.com";
const CHECK_EMAIL_ENDPOINT = `${API_BASE}/check_email`;

// ── Example emails ──────────────────────────────────────────────

const EXAMPLES = {
  "ex-phish-1": {
    sender: "security@paypal-verification.xyz",
    subject: "Urgent: Your account has been suspended",
    body: `Dear Customer,

We have detected unauthorized access to your PayPal account. Your account has been temporarily suspended due to suspicious activity.

You must verify your identity immediately to restore access:
http://paypal-secure-login.tk/verify?id=892341

Failure to verify within 24 hours will result in permanent account closure.

⚠ WARNING: Do not ignore this message.

Please download and fill the attached verification form: verify_form.exe

PayPal Security Team
support@paypal-verification.xyz`
  },
  "ex-phish-2": {
    sender: "winner@international-lottery.buzz",
    subject: "CONGRATULATIONS! You've Won $1,000,000!!!",
    body: `CONGRATULATIONS!!!

Dear Sir/Madam,

You have been selected as the WINNER of the International Online Lottery Program! You've won ONE MILLION DOLLARS ($1,000,000.00)!

Claim your prize NOW: http://bit.ly/claim-prize-now

To claim your reward, click the link above and provide your:
- Full Name
- Bank Account Number
- Social Security Number

This is a LIMITED TIME offer. Act NOW or lose your prize forever!

<form action="http://lottery-claim.pw/collect">
<input type="text" placeholder="Enter SSN">
<input type="password" placeholder="Enter bank PIN">
</form>

International Lottery Commission`
  },
  "ex-safe-1": {
    sender: "noreply@github.com",
    subject: "New login to your GitHub account",
    body: `Hi John,

We noticed a new sign-in to your GitHub account.

Device: Chrome on Windows 11
Location: San Francisco, CA
Time: April 9, 2026

If this was you, no action is needed. If you don't recognize this activity, please review your security settings:

https://github.com/settings/security

For more information about securing your account, visit:
https://docs.github.com/en/authentication/keeping-your-account-and-data-secure

Thanks,
The GitHub Team`
  },
  "ex-safe-2": {
    sender: "notifications@slack.com",
    subject: "Weekly digest from Engineering workspace",
    body: `Hi Sarah,

Here's what happened in your Slack workspace this week:

#general - 45 new messages
#engineering - 23 new messages  
#design - 12 new messages
#random - 8 new messages

Top threads:
- "Q2 roadmap discussion" — 15 replies
- "New CI/CD pipeline" — 9 replies

3 new members joined this week.

Open Slack: https://app.slack.com/

Manage notification preferences:
https://slack.com/settings/notifications

—
Slack Notifications`
  }
};

// ── DOM elements ─────────────────────────────────────────────────

const bodyEl = document.getElementById("email-body");
const senderEl = document.getElementById("email-sender");
const subjectEl = document.getElementById("email-subject");
const scanBtn = document.getElementById("btn-scan");
const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("file-input");
const resultsPanel = document.getElementById("results-panel");

// ── Example buttons ──────────────────────────────────────────────

Object.keys(EXAMPLES).forEach(id => {
  const btn = document.getElementById(id);
  if (btn) {
    btn.addEventListener("click", () => {
      const ex = EXAMPLES[id];
      bodyEl.value = ex.body;
      senderEl.value = ex.sender;
      subjectEl.value = ex.subject;
      // Scroll to textarea
      bodyEl.scrollIntoView({ behavior: "smooth", block: "center" });
      bodyEl.focus();
    });
  }
});

// ── File upload / drag-and-drop ──────────────────────────────────

dropZone.addEventListener("click", () => fileInput.click());

dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("drag-over");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("drag-over");
});

dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("drag-over");
  const file = e.dataTransfer.files[0];
  if (file) loadFile(file);
});

fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) loadFile(fileInput.files[0]);
});

function loadFile(file) {
  const reader = new FileReader();
  reader.onload = (e) => {
    const content = e.target.result;
    parseEmailContent(content);
  };
  reader.readAsText(file);
}

function parseEmailContent(raw) {
  // Try to parse .eml format (headers + body)
  const lines = raw.split("\n");
  let sender = "";
  let subject = "";
  let bodyStart = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (line.toLowerCase().startsWith("from:")) {
      sender = line.substring(5).trim();
      // Extract email from "Name <email>" format
      const emailMatch = sender.match(/<([^>]+)>/);
      if (emailMatch) sender = emailMatch[1];
    }
    if (line.toLowerCase().startsWith("subject:")) {
      subject = line.substring(8).trim();
    }
    // Empty line separates headers from body in .eml
    if (line === "" && bodyStart === -1 && i > 0) {
      bodyStart = i + 1;
    }
  }

  if (bodyStart > 0 && (sender || subject)) {
    // It's a proper .eml file
    senderEl.value = sender;
    subjectEl.value = subject;
    bodyEl.value = lines.slice(bodyStart).join("\n").trim();
  } else {
    // Plain text file
    bodyEl.value = raw;
  }

  bodyEl.scrollIntoView({ behavior: "smooth", block: "center" });
}

// ── Scan button ──────────────────────────────────────────────────

scanBtn.addEventListener("click", async () => {
  const emailText = bodyEl.value.trim();
  if (!emailText) {
    bodyEl.style.borderColor = "rgba(255,59,48,0.5)";
    bodyEl.focus();
    setTimeout(() => { bodyEl.style.borderColor = ""; }, 2000);
    return;
  }

  // Set scanning state
  scanBtn.disabled = true;
  scanBtn.classList.add("scanning");
  scanBtn.innerHTML = `
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="animation: spin 1s linear infinite">
      <circle cx="12" cy="12" r="10" stroke-dasharray="30 70"/>
    </svg>
    Analyzing Email...
  `;

  // Add spin animation
  const style = document.createElement("style");
  style.textContent = "@keyframes spin { to { transform: rotate(360deg) } }";
  document.head.appendChild(style);

  try {
    const response = await fetch(CHECK_EMAIL_ENDPOINT, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "X-API-Key": "PG-API-KEY-2026"
      },
      body: JSON.stringify({
        email_text: emailText,
        sender: senderEl.value.trim(),
        subject: subjectEl.value.trim(),
      }),
    });

    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    const result = await response.json();
    displayResults(result);

  } catch (err) {
    displayError(err.message);
  } finally {
    scanBtn.disabled = false;
    scanBtn.classList.remove("scanning");
    scanBtn.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
      Scan Email
    `;
  }
});

// ── Display results ──────────────────────────────────────────────

function displayResults(result) {
  const isPhishing = result.result === "phishing";
  const confidence = Math.round((result.confidence || 0) * 100);

  // Show panel
  resultsPanel.classList.add("visible");
  resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });

  // Icon
  const iconEl = document.getElementById("result-icon");
  iconEl.className = `result-icon ${isPhishing ? "phishing" : "safe"}`;
  iconEl.textContent = isPhishing ? "⚠" : "✓";

  // Title
  const titleEl = document.getElementById("result-title");
  titleEl.className = `result-title ${isPhishing ? "phishing" : "safe"}`;
  titleEl.textContent = isPhishing ? "Phishing Email Detected" : "Email Appears Safe";

  // Subtitle
  const subEl = document.getElementById("result-sub");
  subEl.textContent = isPhishing
    ? "This email shows signs of a phishing attempt"
    : "No significant phishing indicators found";

  // Confidence bar
  const confValue = document.getElementById("conf-value");
  const confFill = document.getElementById("conf-fill");
  confValue.textContent = confidence + "%";

  // Animate the bar
  confFill.style.width = "0%";
  confFill.className = "conf-fill";
  if (confidence >= 70) confFill.classList.add("high");
  else if (confidence >= 40) confFill.classList.add("medium");
  else confFill.classList.add("low");

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      confFill.style.width = confidence + "%";
    });
  });

  // Reasons
  const reasonsContainer = document.getElementById("reasons-container");
  const reasonsList = document.getElementById("reasons-list");
  const reasons = result.reasons || [];

  if (reasons.length > 0) {
    reasonsContainer.style.display = "block";
    reasonsList.innerHTML = reasons.map(r =>
      `<div class="reason-item">
        <div class="reason-dot"></div>
        <span>${escapeHtml(r)}</span>
      </div>`
    ).join("");
  } else {
    reasonsContainer.style.display = "none";
  }

  // Links analysis
  const linksSection = document.getElementById("links-section");
  const linksStats = document.getElementById("links-stats");

  if (result.links_analyzed && result.links_analyzed > 0) {
    linksSection.style.display = "block";
    const avgScore = Math.round((result.avg_link_score || 0) * 100);
    linksStats.innerHTML = `
      <span class="link-stat">URLs found: <b>${result.links_analyzed}</b></span>
      <span class="link-stat">Avg threat score: <b style="color: ${avgScore > 50 ? 'var(--red)' : 'var(--grn)'}">${avgScore}%</b></span>
    `;
  } else {
    linksSection.style.display = "none";
  }
}

function displayError(message) {
  resultsPanel.classList.add("visible");
  resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });

  document.getElementById("result-icon").className = "result-icon";
  document.getElementById("result-icon").textContent = "✕";
  document.getElementById("result-icon").style.background = "rgba(255,159,10,0.12)";

  const titleEl = document.getElementById("result-title");
  titleEl.className = "result-title";
  titleEl.style.color = "var(--ylw)";
  titleEl.textContent = "Analysis Failed";

  document.getElementById("result-sub").textContent = message;
  document.getElementById("conf-value").textContent = "—";
  document.getElementById("conf-fill").style.width = "0%";
  document.getElementById("reasons-container").style.display = "none";
  document.getElementById("links-section").style.display = "none";
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
