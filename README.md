# 🛡️ PhishGuard 3.0 — AI-Augmented Browser Anti-Phishing Extension

A complete **6-module** phishing detection system: Chrome Extension + Flask API + ML Classifier + Email Scanner + Heuristic Engine + Real-time Alerts.

🌐 **Live Final Website & Download:** [https://phishguard26.netlify.app/](https://phishguard26.netlify.app/)

---

## 📁 Project Structure

```
phishguard/
│
├── extension/                        ← MODULE 1 + MODULE 4 (Chrome Extension)
│   ├── manifest.json                 ← Manifest V3: permissions, service worker config
│   ├── background.js                 ← MODULE 1: URL monitoring, API calls, cache, stats
│   ├── content.js                    ← MODULE 4: In-page warning overlay, user alerts
│   ├── popup.html                    ← Dashboard UI: stats, alerts, feedback log
│   ├── popup.js                      ← Popup logic
│   └── icons/                        ← Extension icons (icon16/48/128.png)
│
└── backend/                          ← MODULE 2 + MODULE 3
    ├── app.py                        ← MODULE 2: Flask API server (central hub)
    ├── requirements.txt
    ├── features/
    │   ├── __init__.py
    │   └── extractor.py              ← MODULE 2: Feature extraction (38 URL features)
    └── ml/
        ├── __init__.py
        ├── detector.py               ← MODULE 3: ML engine — heuristic + sklearn classifier
        └── model.pkl                 ← (auto-generated after training)
```

---

## 🏗️ Architecture — 4 Modules

```
  USER BROWSER
  ┌─────────────────────────────────────────────────────┐
  │  MODULE 1: Browser Extension Monitoring             │
  │  background.js                                      │
  │  [01] Installed → [02] Monitor → [03] Navigate →   │
  │  [04] Capture URL → [05] Prepare → [06] Send API   │
  └─────────────────┬───────────────────────────────────┘
                    │ POST /analyze
                    ▼
  ┌─────────────────────────────────────────────────────┐
  │  MODULE 2: Backend API Processing                   │
  │  app.py + features/extractor.py                     │
  │  [04] Validate → [05] Normalize → [06] Extract →   │
  │  [07] Format → [08] Forward to ML                  │
  └─────────────────┬───────────────────────────────────┘
                    │
                    ▼
  ┌─────────────────────────────────────────────────────┐
  │  MODULE 3: Analytics & Machine Learning             │
  │  ml/detector.py                                     │
  │  [08] Receive vector → [09] Classify →             │
  │  Confidence + Risk Level + Reasons                  │
  └─────────────────┬───────────────────────────────────┘
                    │ JSON response
                    ▼
  ┌─────────────────────────────────────────────────────┐
  │  MODULE 4: User Alert & Protection                  │
  │  content.js                                         │
  │  [02] Receive → [03] Evaluate severity →           │
  │  [04-06] Trigger alert + visual indicators →       │
  │  [07] Advise user → [08] Option to leave →         │
  │  [09] Record decision → [10] Resume safe browsing  │
  └─────────────────────────────────────────────────────┘
```

---

## 📦 Module Descriptions

### 1️⃣ Browser Extension Monitoring Module

This module operates directly within the user's web browser and continuously monitors browsing activity to detect potentially malicious websites. Implemented as a Chrome extension using JavaScript, HTML, and CSS, it captures the URLs of webpages visited by the user in real time. The extension sends the collected URL data to the backend API for phishing analysis. By operating silently in the background, the extension provides seamless protection without interrupting normal browsing. It also handles communication with the backend system and displays alerts when a suspicious website is detected.

**📂 Files:** `extension/background.js`

### 2️⃣ Backend API Processing Module

This module serves as the central communication layer between the browser extension and the machine learning detection system. Built using Python and Flask, the backend API receives incoming URL analysis requests from the browser extension. It processes the requests, performs feature extraction on the URL, and forwards the processed data to the machine learning model for classification. After the model generates a prediction, the API formats the result and sends it back to the browser extension. This modular backend design ensures scalability, maintainability, and efficient real-time communication between system components.

**📂 Files:** `backend/app.py`, `backend/features/extractor.py`

### 3️⃣ Analytics & Machine Learning Module

This module contains the core intelligence of the system — the phishing detection engine. It implements a dual-strategy classification approach: a **weighted heuristic rule engine** that works out-of-the-box with 22 weighted security signals and combo-boosting, and an optional **scikit-learn RandomForestClassifier** (400 trees) trained on 50K URLs for 99.55% accuracy. The module receives extracted feature vectors, evaluates them against phishing indicators, and generates a classification result including confidence scores, risk levels, and human-readable explanations of why a URL was flagged.

**📂 Files:** `backend/ml/detector.py`

### 4️⃣ User Alert & Protection Module

This module is responsible for informing users when a phishing threat is detected and preventing interaction with malicious websites. When the machine learning model identifies a suspicious website, the system immediately generates a warning notification within the browser interface. The extension displays a popup alert, highlights the risk level, and blocks the webpage from loading fully. This real-time notification system ensures that users are warned before entering sensitive information such as login credentials or banking details. By providing immediate feedback, the module enhances user awareness and promotes safer browsing behavior.

**📂 Files:** `extension/content.js`

---

## 🔄 Module Process Flows

### Module 1 — Browser Extension Monitoring

| Step | Description |
|------|-------------|
| [01] | Browser extension installed and activated in Google Chrome |
| [02] | Extension runs background monitoring service |
| [03] | User navigates to a website or clicks a link |
| [04] | Extension captures the current page URL |
| [05] | URL data prepared for analysis request |
| [06] | Secure request sent to backend API server |
| [07] | Extension waits for classification result |
| [08] | Response received from backend analysis system |
| [09] | Extension processes detection result |
| [10] | Security warning triggered if a phishing site is identified |

### Module 2 — Backend API Processing

| Step | Description |
|------|-------------|
| [01] | Backend Flask server initialized and running |
| [02] | API endpoint exposed for URL analysis requests |
| [03] | Browser extension sends URL analysis request |
| [04] | API receives and validates incoming request |
| [05] | URL preprocessing performed to normalize input |
| [06] | Feature extraction module activated |
| [07] | Extracted features formatted for ML model input |
| [08] | Feature vector forwarded to the phishing detection model |
| [09] | Prediction result generated by model |
| [10] | API sends classification response back to browser extension |

### Module 3 — Analytics & Machine Learning

| Step | Description |
|------|-------------|
| [01] | Feature vector received from backend API |
| [02] | Model selection: sklearn (if trained) or heuristic fallback |
| [03] | Heuristic engine evaluates 22 weighted security signals with combo-boosting |
| [04] | Brand impersonation checks performed |
| [05] | Lookalike character detection activated |
| [06] | Domain reputation and TLD risk assessed |
| [07] | URL structure and obfuscation patterns analyzed |
| [08] | Composite phishing confidence score calculated |
| [09] | Risk level assigned: safe / low / medium / high |
| [10] | Classification result with reasons returned to API |

### Module 4 — User Alert & Protection

| Step | Description |
|------|-------------|
| [01] | Machine learning model detects potential phishing website |
| [02] | Detection result returned to browser extension |
| [03] | Extension evaluates threat severity level |
| [04] | Security alert triggered within browser interface |
| [05] | Warning message displayed to the user |
| [06] | Visual indicators highlight phishing risk |
| [07] | User advised not to enter sensitive information |
| [08] | Option provided to leave the suspicious website |
| [09] | User decision recorded for system feedback |
| [10] | Safe browsing resumed after alert acknowledgement |

---

## 🚀 Setup & Run

### Step 1 — Start the Backend

```bash
cd backend

# Install dependencies
pip install flask flask-cors scikit-learn

# Run server
python app.py
```

Server starts at: **http://localhost:5000**

| Endpoint         | Method | Description                     |
|------------------|--------|---------------------------------|
| `/analyze`       | POST   | Main URL analysis endpoint      |
| `/test`          | GET    | Run batch test with sample URLs |
| `/analytics`     | GET    | Aggregated scan statistics      |
| `/health`        | GET    | Server health check             |
| `/feedback`      | POST   | Receive user-reported feedback  |

---

### Step 2 — Load the Chrome Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer Mode** (top-right toggle)
3. Click **"Load unpacked"**
4. Select the `extension/` folder
5. PhishGuard icon appears in Chrome toolbar ✅

---

## 🔍 Feature Extraction (38 URL + 28 Email Features)

### URL Features (38)

| Category       | Features                                                                 |
|----------------|--------------------------------------------------------------------------|
| Length (5)     | `url_length`, `hostname_length`, `path_length`, `query_length`, `path_depth` |
| Count (7)      | `num_dots`, `num_hyphens`, `num_underscores`, `num_digits`, `num_subdomains`, `num_query_params`, `num_special_chars` |
| Ratio (4)      | `digit_ratio`, `letter_ratio`, `special_char_ratio`, `hostname_entropy`  |
| Boolean (11)   | `uses_https`, `is_ip_address`, `is_known_tld_suspicious`, `has_suspicious_keyword`, `has_at_symbol`, `has_double_slash`, `has_redirect_param`, `has_encoded_chars`, `is_known_legitimate`, `brand_in_hostname`, `brand_hyphenated` |
| Advanced (3)   | `has_lookalike_chars`, `has_sensitive_path`, `is_shortened_url`          |
| NEW v3.0 (8)   | `has_punycode`, `tld_length`, `subdomain_length`, `has_port_number`, `path_has_double_extension`, `digit_ratio_in_subdomain`, `vowel_consonant_ratio`, `domain_token_count` |

### Email Features (28)

| Category         | Features                                                               |
|------------------|------------------------------------------------------------------------|
| Urgency (4)      | `has_urgent_language`, `urgent_keyword_count`, `has_threat_language`, `has_reward_language` |
| Links (5)        | `link_count`, `has_suspicious_links`, `suspicious_link_ratio`, `has_html_form`, `has_mismatched_url` |
| Sender (4)       | `sender_domain_mismatch`, `sender_is_freemail`, `has_spoofed_sender`, `sender_suspicious_tld` |
| Content (4)      | `has_generic_greeting`, `body_length`, `capitalization_ratio`, `special_char_ratio` |
| Structure (3)    | `has_dangerous_attachment`, `spelling_error_score`, `url_phishing_score` |
| NEW v3.0 (8)     | `has_base64_content`, `has_javascript`, `link_to_text_ratio`, `has_hidden_text`, `reply_to_mismatch`, `has_tracking_pixel`, `urgency_in_subject`, `body_entropy` |

---

## 🤖 ML Model

The system runs a **heuristic rule engine** by default (no training needed).

To use a **scikit-learn RandomForestClassifier**, train it with labelled data:

```python
from ml.detector import train

urls   = ["https://google.com", "http://paypa1-login.xyz/signin", ...]
labels = [0, 1, ...]  # 0=safe, 1=phishing

train(urls, labels, save_path="ml/model.pkl")
```

The API auto-detects and loads `model.pkl` on startup.

**Public datasets for training:**
- [PhishTank](https://www.phishtank.com/) — real phishing URLs
- [UCI ML Phishing Dataset](https://archive.ics.uci.edu/dataset/327/phishing+websites)
- [Alexa Top 1M](https://www.alexa.com/topsites) — safe URLs

---

## 🧪 Test Results (Sample)

```
URL                                         Expected    Predicted   Confidence
──────────────────────────────────────────────────────────────────────────────
https://www.google.com                      safe        safe        1%
https://github.com                          safe        safe        2%
https://paypal-secure-login.xyz/verify      phishing    phishing    85%
http://192.168.1.1/phishing-page            phishing    phishing    80%
https://amazon-account-update.club/login    phishing    phishing    78%
https://secure.paypa1.com/signin            phishing    phishing    72%
```

---

## 📄 License

MIT License — Free for academic and personal use.
