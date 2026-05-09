"""
PhishGuard -- features/email_extractor.py
MODULE 5: Email Phishing Detection — Feature Extraction

Extracts 28 structured features from email content for ML classification.
Cross-references links found in emails with the existing URL phishing model.

Features:
  [01-04]  Urgency & threat indicators
  [05-09]  Link analysis
  [10-13]  Sender analysis
  [14-17]  Content patterns
  [18-20]  Structural signals
  [21-28]  NEW: Advanced content analysis
"""

import re
import math
import base64
from typing import Dict, Any, List
from collections import Counter


# -- Urgent / pressure keywords ------------------------------------------------
URGENT_PHRASES = [
    "urgent action required", "verify your account", "verify immediately",
    "confirm your identity", "update your information", "click here to update",
    "payment failed", "account suspended", "unauthorized access",
    "unusual activity", "security alert", "immediate action",
    "within 24 hours", "within 48 hours", "your account will be",
    "failure to verify", "risk of suspension", "action required",
    "verify your identity", "confirm your payment", "expire soon",
    "last warning", "final notice", "act now", "time sensitive",
    "respond immediately", "do not ignore", "limited time",
    # New urgency phrases
    "account will be closed", "must verify", "expires today",
    "hours remaining", "respond now", "take action immediately",
    "risk losing", "will be terminated", "will be permanently",
    "click below immediately", "requires your attention",
    "update required", "mandatory update", "confirm now",
    "verify within", "must be completed", "failure to respond",
    "your access will be", "will be disabled", "will be frozen",
]

THREAT_PHRASES = [
    "suspended", "locked", "unauthorized", "compromised", "breach",
    "terminated", "disabled", "restricted", "blocked", "frozen",
    "illegal activity", "legal action", "law enforcement",
    "permanent closure", "account closure", "identity theft",
    # New threat phrases
    "penalty", "fine", "prosecution", "court order", "arrest warrant",
    "federal investigation", "criminal charges", "tax fraud",
    "money laundering", "seized", "confiscated", "forfeited",
    "compliance violation", "regulatory action", "cease and desist",
    "your data has been", "security incident", "data breach notification",
]

REWARD_PHRASES = [
    "congratulations", "winner", "prize", "free gift", "claim your",
    "you have been selected", "lottery", "million dollars",
    "exclusive offer", "limited offer", "special promotion",
    "click to claim", "redeem now", "bonus", "reward",
    # New reward phrases
    "gift card", "cashback", "refund pending", "unclaimed funds",
    "inheritance", "beneficiary", "lottery winner", "sweepstakes",
    "guaranteed income", "work from home", "make money fast",
    "investment opportunity", "double your money", "risk free",
    "no obligation", "free trial", "free membership",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear account holder",
    "dear valued customer", "dear sir/madam", "dear member",
    "dear client", "dear subscriber", "hello user",
    "attention user", "dear recipient",
    # New generic greetings
    "dear valued member", "dear account owner", "dear patron",
    "dear cardholder", "dear taxpayer", "dear beneficiary",
    "dear winner", "dear friend", "to whom it may concern",
    "dear email user", "attention account holder",
]

# -- Sender analysis -----------------------------------------------------------
FREEMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "mail.com", "protonmail.com", "yandex.com",
    "zoho.com", "icloud.com", "live.com", "msn.com",
    # New freemail providers
    "mail.ru", "gmx.com", "gmx.net", "inbox.com",
    "rediffmail.com", "tutanota.com", "fastmail.com",
    "guerrillamail.com", "tempmail.com", "throwaway.email",
]

BRAND_NAMES = [
    "paypal", "amazon", "netflix", "google", "apple", "microsoft",
    "facebook", "instagram", "ebay", "dropbox", "chase", "wellsfargo",
    "citibank", "dhl", "fedex", "linkedin", "twitter", "steam",
    "whatsapp", "telegram", "coinbase", "binance", "bank of america",
    # New brands
    "uber", "venmo", "zelle", "usps", "ups", "spotify", "discord",
    "tiktok", "snapchat", "stripe", "shopify", "docusign", "adobe",
    "zoom", "slack", "metamask", "opensea", "robinhood", "schwab",
    "fidelity", "vanguard", "americanexpress", "capitalone", "discover",
    "irs", "social security", "medicare", "department of",
]

# -- Suspicious link patterns ---------------------------------------------------
SHORTENING_SERVICES = [
    "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "j.mp", "rb.gy", "cutt.ly",
    "shorturl.at", "tr.im",
    "v.gd", "clck.ru", "tny.im", "tiny.cc", "s.id",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".click", ".link",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".buzz",
    ".icu", ".cam", ".monster", ".rest", ".surf",
    ".loan", ".date", ".trade", ".gdn", ".men",
    ".space", ".host", ".site", ".website", ".online",
]

DANGEROUS_EXTENSIONS = [
    ".exe", ".zip", ".rar", ".scr", ".bat", ".cmd",
    ".js", ".vbs", ".msi", ".pif", ".jar",
    ".iso", ".img", ".dmg", ".apk", ".ps1", ".wsf",
    ".hta", ".cpl", ".inf", ".reg", ".lnk", ".docm", ".xlsm",
]


# -- Helper functions ----------------------------------------------------------

def _extract_urls(text: str) -> List[str]:
    """Extract all URLs from email text."""
    url_pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
    return re.findall(url_pattern, text, re.IGNORECASE)


def _extract_email_addresses(text: str) -> List[str]:
    """Extract email addresses from text."""
    return re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', text)


def _count_matches(text: str, phrases: List[str]) -> int:
    """Count how many phrases appear in the text."""
    text_lower = text.lower()
    return sum(1 for p in phrases if p in text_lower)


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _get_sender_domain(sender: str) -> str:
    """Extract domain from sender email."""
    match = re.search(r'@([\w.-]+)', sender)
    return match.group(1).lower() if match else ""


# -- Main extractor ------------------------------------------------------------

def extract_email_features(
    email_text: str,
    sender: str = "",
    subject: str = ""
) -> Dict[str, Any]:
    """
    Extract 28 features from email content for ML classification.

    Args:
        email_text: Full email body (plain text or HTML)
        sender:     Sender email address
        subject:    Email subject line

    Returns:
        Dict of 28 named features
    """
    features: Dict[str, Any] = {}

    # -- Strip HTML tags from email body if present ---
    # Gmail/Outlook scanner may send raw HTML which inflates features
    if '<html' in email_text.lower() or '<div' in email_text.lower() or '<table' in email_text.lower():
        # Extract URLs from HTML BEFORE stripping (preserves href targets)
        html_urls = re.findall(r'href\s*=\s*["\']?(https?://[^"\'>\s]+)', email_text, re.IGNORECASE)
        # Strip all HTML tags to get clean text
        email_text = re.sub(r'<[^>]+>', ' ', email_text)
        # Collapse whitespace
        email_text = re.sub(r'\s+', ' ', email_text).strip()
    else:
        html_urls = []

    text_lower = email_text.lower()
    combined = f"{subject} {email_text}".lower()
    sender_domain = _get_sender_domain(sender)

    try:
        # == 1-4: Urgency & threat indicators ==================================

        # [01] Has urgent language
        urgent_count = _count_matches(combined, URGENT_PHRASES)
        features["has_urgent_language"] = int(urgent_count > 0)

        # [02] Urgent keyword count
        features["urgent_keyword_count"] = min(urgent_count, 10)

        # [03] Has threat language
        threat_count = _count_matches(combined, THREAT_PHRASES)
        features["has_threat_language"] = int(threat_count > 0)

        # [04] Has reward/prize language
        features["has_reward_language"] = int(
            _count_matches(combined, REWARD_PHRASES) > 0
        )

        # == 5-9: Link analysis ================================================

        urls = _extract_urls(email_text)

        # [05] Total link count
        features["link_count"] = min(len(urls), 20)

        # [06] Has suspicious links (shortened / IP-based / suspicious TLD)
        suspicious_links = 0
        for url in urls:
            url_lower = url.lower()
            if any(s in url_lower for s in SHORTENING_SERVICES):
                suspicious_links += 1
            elif re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                suspicious_links += 1
            elif any(url_lower.endswith(t) or (t in url_lower) for t in SUSPICIOUS_TLDS):
                suspicious_links += 1
        features["has_suspicious_links"] = int(suspicious_links > 0)

        # [07] Suspicious link ratio
        features["suspicious_link_ratio"] = round(
            suspicious_links / max(len(urls), 1), 4
        )

        # [08] Has HTML forms (credential harvesting)
        features["has_html_form"] = int(
            bool(re.search(r'<form|<input|type=["\']password', text_lower))
        )

        # [09] Has mismatched URL text
        # e.g., <a href="evil.com">paypal.com</a>
        mismatched = re.findall(
            r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>',
            email_text, re.IGNORECASE
        )
        has_mismatch = 0
        for href, display_text in mismatched:
            display_clean = display_text.strip().lower()
            if re.match(r'https?://', display_clean) or '.' in display_clean:
                # Display text looks like a URL — check if it matches href
                if display_clean not in href.lower():
                    has_mismatch = 1
                    break
        features["has_mismatched_url"] = has_mismatch

        # == 10-13: Sender analysis ============================================

        # [10] Sender domain mismatch (brand in body but sender domain differs)
        brands_in_body = [b for b in BRAND_NAMES if b in text_lower]
        sender_has_brand = any(b in sender_domain for b in BRAND_NAMES)
        features["sender_domain_mismatch"] = int(
            len(brands_in_body) > 0 and not sender_has_brand and sender_domain != ""
        )

        # [11] Sender uses free email service
        features["sender_is_freemail"] = int(
            sender_domain in FREEMAIL_DOMAINS
        )

        # [12] Spoofed sender (display name has brand, domain doesn't match)
        sender_lower = sender.lower()
        has_brand_in_sender_name = any(b in sender_lower for b in BRAND_NAMES)
        brand_domain_match = any(
            b in sender_domain.split('.')[0] for b in BRAND_NAMES
        ) if sender_domain else False
        features["has_spoofed_sender"] = int(
            has_brand_in_sender_name and not brand_domain_match
        )

        # [13] Sender domain has suspicious TLD
        features["sender_suspicious_tld"] = int(
            any(sender_domain.endswith(t.lstrip('.')) for t in SUSPICIOUS_TLDS)
        ) if sender_domain else 0

        # == 14-17: Content patterns ===========================================

        # [14] Has generic greeting
        features["has_generic_greeting"] = int(
            _count_matches(combined, GENERIC_GREETINGS) > 0
        )

        # [15] Body length (normalized)
        features["body_length"] = min(len(email_text), 10000)

        # [16] Capitalization ratio (ALL CAPS = urgency trick)
        alpha_chars = [c for c in email_text if c.isalpha()]
        features["capitalization_ratio"] = round(
            sum(1 for c in alpha_chars if c.isupper()) / max(len(alpha_chars), 1), 4
        )

        # [17] Special character ratio
        features["special_char_ratio"] = round(
            sum(1 for c in email_text if not c.isalnum() and not c.isspace())
            / max(len(email_text), 1), 4
        )

        # == 18-20: Structural signals =========================================

        # [18] Mentions dangerous attachments
        # Use word-boundary matching to avoid false positives from URLs
        # e.g. "slack.com" should NOT trigger ".com" extension match
        has_dangerous = False
        for ext in DANGEROUS_EXTENSIONS:
            # Match patterns like "file.exe" or "document.zip" but not "google.com"
            pattern = r'\b\w+' + re.escape(ext) + r'(?:\s|$|[,;"\'\)])'
            if re.search(pattern, text_lower):
                has_dangerous = True
                break
        features["has_dangerous_attachment"] = int(has_dangerous)

        # [19] Spelling/grammar score (simple heuristic)
        # Count common phishing misspellings
        misspellings = [
            "paypa1", "arnazon", "micros0ft", "g00gle", "app1e",
            "netfl1x", "1nstagram", "faceb00k", "tw1tter",
            "acccount", "verifiy", "securty", "infomation",
            "updatte", "suspened", "unauthorised",
            # New misspellings
            "amaz0n", "netf1ix", "ch4se", "we11sfargo",
            "verfy", "confrm", "acction", "immedately",
            "suspeneded", "restrcted", "disab1ed", "acc0unt",
        ]
        features["spelling_error_score"] = min(
            _count_matches(combined, misspellings), 5
        )

        # [20] URL phishing score (average score from existing URL model)
        # This is computed externally and injected — default to 0
        features["url_phishing_score"] = 0.0

        # == 21-28: NEW Advanced content analysis ==============================

        # [21] Has base64 encoded content (obfuscation)
        has_b64 = bool(re.search(
            r'(?:data:[^;]+;base64,|Content-Transfer-Encoding:\s*base64)',
            email_text, re.IGNORECASE
        ))
        # Also check for long base64-like strings in the body
        if not has_b64:
            has_b64 = bool(re.search(r'[A-Za-z0-9+/]{50,}={0,2}', email_text))
        features["has_base64_content"] = int(has_b64)

        # [22] Has JavaScript (script injection in HTML emails)
        features["has_javascript"] = int(bool(re.search(
            r'<script|javascript:|on\w+\s*=\s*["\']|eval\s*\(|document\.(cookie|write|location)',
            text_lower
        )))

        # [23] Link to text ratio — phishing emails are link-heavy
        plain_text = re.sub(r'<[^>]+>', '', email_text)
        word_count = len(plain_text.split())
        link_count = len(urls)
        features["link_to_text_ratio"] = round(
            link_count / max(word_count, 1), 4
        )

        # [24] Has hidden text (CSS tricks: display:none, font-size:0, visibility:hidden)
        features["has_hidden_text"] = int(bool(re.search(
            r'display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|'
            r'color\s*:\s*(?:white|#fff|#ffffff|transparent)|'
            r'height\s*:\s*0|overflow\s*:\s*hidden',
            text_lower
        )))

        # [25] Reply-to mismatch (reply-to address differs from sender)
        reply_to_match = re.search(r'reply-to:\s*([^\s<>,]+@[^\s<>,]+)', text_lower)
        if reply_to_match:
            reply_to_domain = _get_sender_domain(reply_to_match.group(1))
            features["reply_to_mismatch"] = int(
                reply_to_domain != "" and sender_domain != "" and
                reply_to_domain != sender_domain
            )
        else:
            features["reply_to_mismatch"] = 0

        # [26] Has tracking pixel (tiny 1x1 images for tracking)
        features["has_tracking_pixel"] = int(bool(re.search(
            r'<img[^>]+(?:width\s*=\s*["\']?1["\']?\s+height\s*=\s*["\']?1|'
            r'height\s*=\s*["\']?1["\']?\s+width\s*=\s*["\']?1|'
            r'(?:1x1|pixel|track|beacon|open)[^>]*\.(?:gif|png|jpg))',
            text_lower
        )))

        # [27] Urgency in subject line — subject-level urgency is a strong signal
        subject_urgency = _count_matches(subject.lower(), [
            "urgent", "action required", "immediately", "alert", "warning",
            "final notice", "last chance", "expire", "suspended", "locked",
            "verify", "confirm", "update required", "act now", "important",
        ])
        features["urgency_in_subject"] = min(subject_urgency, 5)

        # [28] Body entropy — random-looking body text scores higher
        # Strip HTML tags for cleaner entropy calculation
        clean_body = re.sub(r'<[^>]+>', '', email_text)
        features["body_entropy"] = round(
            _shannon_entropy(clean_body[:500]), 4  # First 500 chars
        )

    except Exception:
        features = {k: 0 for k in email_feature_names()}

    return features


def email_feature_names() -> List[str]:
    """Ordered list of 28 email feature names."""
    return [
        # Urgency & threat (4)
        "has_urgent_language", "urgent_keyword_count",
        "has_threat_language", "has_reward_language",
        # Link analysis (5)
        "link_count", "has_suspicious_links", "suspicious_link_ratio",
        "has_html_form", "has_mismatched_url",
        # Sender analysis (4)
        "sender_domain_mismatch", "sender_is_freemail",
        "has_spoofed_sender", "sender_suspicious_tld",
        # Content patterns (4)
        "has_generic_greeting", "body_length",
        "capitalization_ratio", "special_char_ratio",
        # Structural signals (3)
        "has_dangerous_attachment", "spelling_error_score",
        "url_phishing_score",
        # NEW: Advanced content analysis (8)
        "has_base64_content", "has_javascript",
        "link_to_text_ratio", "has_hidden_text",
        "reply_to_mismatch", "has_tracking_pixel",
        "urgency_in_subject", "body_entropy",
    ]


def email_feature_vector(email_text: str, sender: str = "", subject: str = "") -> list:
    """Returns ordered list of feature values for ML input."""
    f = extract_email_features(email_text, sender, subject)
    return [f.get(k, 0) for k in email_feature_names()]
