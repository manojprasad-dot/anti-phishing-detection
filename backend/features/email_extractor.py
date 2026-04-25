"""
PhishGuard -- features/email_extractor.py
MODULE 5: Email Phishing Detection — Feature Extraction (v2.0)

Extracts 32 structured features from email content for ML classification.
Cross-references links found in emails with the existing URL phishing model.

Features (32):
  [01-04]  Header & authentication signals
  [05-07]  Domain reputation
  [08-11]  Urgency & threat indicators
  [12-17]  Link analysis
  [18-21]  Sender analysis
  [22-26]  Content patterns (NLP)
  [27-32]  Structural signals
"""

import re
import math
from typing import Dict, Any, List, Optional
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
    "must respond", "cannot be delayed", "urgent response needed",
    "take action immediately", "account will be closed",
]

THREAT_PHRASES = [
    "suspended", "locked", "unauthorized", "compromised", "breach",
    "terminated", "disabled", "restricted", "blocked", "frozen",
    "illegal activity", "legal action", "law enforcement",
    "permanent closure", "account closure", "identity theft",
    "will be deleted", "access revoked", "security violation",
]

REWARD_PHRASES = [
    "congratulations", "winner", "prize", "free gift", "claim your",
    "you have been selected", "lottery", "million dollars",
    "exclusive offer", "limited offer", "special promotion",
    "click to claim", "redeem now", "bonus", "reward",
    "gift card", "free money", "cash prize", "you won",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear account holder",
    "dear valued customer", "dear sir/madam", "dear member",
    "dear client", "dear subscriber", "hello user",
    "attention user", "dear recipient", "dear sir", "dear madam",
]

CREDENTIAL_REQUESTS = [
    "enter your password", "enter password", "type your password",
    "social security", "ssn", "bank account number",
    "credit card number", "routing number", "pin number",
    "enter your pin", "cvv", "card number", "account number",
    "login credentials", "username and password",
    "provide your details", "fill in your details",
]

# -- Sender analysis -----------------------------------------------------------
FREEMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "mail.com", "protonmail.com", "yandex.com",
    "zoho.com", "icloud.com", "live.com", "msn.com",
]

TRUSTED_SENDER_DOMAINS = [
    "gmail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "icloud.com", "google.com", "microsoft.com",
    "apple.com", "amazon.com", "netflix.com", "paypal.com",
    "github.com", "linkedin.com", "slack.com", "spotify.com",
    "zoom.us", "stripe.com", "trello.com", "notion.so",
    "dropbox.com", "adobe.com", "shopify.com", "twitter.com",
    "facebook.com", "instagram.com", "tiktok.com",
]

BRAND_NAMES = [
    "paypal", "amazon", "netflix", "google", "apple", "microsoft",
    "facebook", "instagram", "ebay", "dropbox", "chase", "wellsfargo",
    "citibank", "dhl", "fedex", "linkedin", "twitter", "steam",
    "whatsapp", "telegram", "coinbase", "binance", "bank of america",
]

# -- Suspicious link patterns ---------------------------------------------------
SHORTENING_SERVICES = [
    "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "j.mp", "rb.gy", "cutt.ly",
    "shorturl.at", "tr.im",
]

SUSPICIOUS_TLDS = {
    ".xyz": 0.8, ".top": 0.7, ".club": 0.6, ".work": 0.7,
    ".click": 0.8, ".link": 0.5, ".tk": 0.9, ".ml": 0.9,
    ".ga": 0.9, ".cf": 0.9, ".gq": 0.9, ".pw": 0.8,
    ".buzz": 0.7, ".icu": 0.7, ".cam": 0.7, ".monster": 0.7,
    ".rest": 0.6, ".surf": 0.6, ".top": 0.7, ".loan": 0.8,
    ".win": 0.7, ".bid": 0.7, ".stream": 0.6, ".racing": 0.6,
}

DANGEROUS_EXTENSIONS = [
    ".exe", ".zip", ".rar", ".scr", ".bat", ".cmd",
    ".js", ".vbs", ".msi", ".pif", ".com", ".jar",
]

# -- TF-IDF-like phishing vocabulary (weighted terms) --------------------------
PHISHING_VOCABULARY = {
    "verify": 2.5, "suspend": 3.0, "unauthorized": 3.0,
    "immediately": 2.0, "urgent": 2.5, "confirm": 1.5,
    "password": 2.0, "click here": 2.0, "update": 1.0,
    "secure": 1.5, "alert": 2.0, "warning": 2.0,
    "expire": 2.5, "locked": 3.0, "compromised": 3.0,
    "login": 1.5, "credentials": 2.5, "billing": 1.5,
    "payment": 1.5, "prize": 2.5, "winner": 3.0,
    "congratulations": 2.5, "lottery": 3.0, "claim": 2.0,
    "free": 1.5, "act now": 2.5, "limited time": 2.0,
    "bank account": 3.0, "ssn": 3.5, "social security": 3.5,
    "credit card": 2.5, "terminated": 3.0,
}


# -- Helper functions ----------------------------------------------------------

def _extract_urls(text: str) -> List[str]:
    """Extract all URLs from email text."""
    url_pattern = r"https?://[^\s<>\"'\)\]]+|www\.[^\s<>\"'\)\]]+"
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


def _get_display_name(sender: str) -> str:
    """Extract display name from 'Name <email>' format."""
    match = re.match(r'^([^<]+)\s*<', sender)
    if match:
        return match.group(1).strip().lower()
    return ""


def _compute_tfidf_score(text: str) -> float:
    """Compute a TF-IDF-like suspicion score using phishing vocabulary."""
    text_lower = text.lower()
    words = re.findall(r'\b\w+\b', text_lower)
    total_words = max(len(words), 1)

    score = 0.0
    for term, weight in PHISHING_VOCABULARY.items():
        # Term frequency (normalized)
        tf = text_lower.count(term) / total_words
        # Apply IDF-like weight
        score += tf * weight * 100  # Scale up

    # Normalize to 0-1 range
    return min(round(score, 4), 1.0)


def _compute_urgency_score(text: str) -> float:
    """Compute weighted urgency score (0.0 - 1.0)."""
    text_lower = text.lower()

    # High-weight urgency signals
    high_urgency = [
        "within 24 hours", "within 48 hours", "immediately",
        "act now", "last warning", "final notice", "respond now",
        "urgent", "do not ignore", "must respond",
    ]
    medium_urgency = [
        "action required", "verify", "confirm", "update",
        "expire", "suspended", "time sensitive", "limited time",
    ]
    low_urgency = [
        "please", "important", "attention", "notice", "reminder",
    ]

    score = 0.0
    score += sum(0.15 for p in high_urgency if p in text_lower)
    score += sum(0.08 for p in medium_urgency if p in text_lower)
    score += sum(0.03 for p in low_urgency if p in text_lower)

    return min(round(score, 4), 1.0)


# -- Main extractor ------------------------------------------------------------

def extract_email_features(
    email_text: str,
    sender: str = "",
    subject: str = "",
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Extract 32 features from email content for ML classification.

    Args:
        email_text: Full email body (plain text or HTML)
        sender:     Sender email address (or "Name <email>" format)
        subject:    Email subject line
        headers:    Optional dict with SPF/DKIM/DMARC results

    Returns:
        Dict of 32 named features
    """
    features: Dict[str, Any] = {}
    text_lower = email_text.lower()
    combined = f"{subject} {email_text}".lower()
    sender_domain = _get_sender_domain(sender)
    display_name = _get_display_name(sender)
    headers = headers or {}

    try:
        # == 1-4: Header & authentication signals ==============================

        # Real header data if available; otherwise, simulate from domain signals
        is_trusted_domain = sender_domain in TRUSTED_SENDER_DOMAINS

        # [01] SPF fail (simulated: suspicious domain → likely no SPF)
        if "spf" in headers:
            features["spf_fail"] = int(headers["spf"].lower() != "pass")
        else:
            features["spf_fail"] = int(
                not is_trusted_domain
                and sender_domain != ""
                and (
                    any(sender_domain.endswith(t) for t in SUSPICIOUS_TLDS)
                    or _shannon_entropy(sender_domain) > 3.5
                )
            )

        # [02] DKIM fail
        if "dkim" in headers:
            features["dkim_fail"] = int(headers["dkim"].lower() != "pass")
        else:
            features["dkim_fail"] = features["spf_fail"]  # correlates with SPF

        # [03] DMARC fail
        if "dmarc" in headers:
            features["dmarc_fail"] = int(headers["dmarc"].lower() != "pass")
        else:
            # DMARC fail = SPF fail or DKIM fail + non-trusted domain
            features["dmarc_fail"] = int(
                (features["spf_fail"] or features["dkim_fail"])
                and not is_trusted_domain
            )

        # [04] From vs Reply-To mismatch
        reply_to = headers.get("reply_to", "")
        if reply_to:
            reply_domain = _get_sender_domain(reply_to)
            features["from_reply_mismatch"] = int(
                reply_domain != "" and reply_domain != sender_domain
            )
        else:
            # Heuristic: check if email body contains a different reply address
            body_emails = _extract_email_addresses(email_text)
            body_domains = {_get_sender_domain(e) for e in body_emails}
            body_domains.discard(sender_domain)
            body_domains.discard("")
            features["from_reply_mismatch"] = int(len(body_domains) > 0)

        # == 5-7: Domain reputation ============================================

        # [05] Domain age suspicious (simulated: suspicious TLDs = new domains)
        features["domain_age_suspicious"] = int(
            any(sender_domain.endswith(t) for t in SUSPICIOUS_TLDS)
            or bool(re.search(r'\d{3,}', sender_domain))  # numbers in domain
            or (len(sender_domain.split('.')[0]) > 15)  # very long subdomain
        ) if sender_domain else 0

        # [06] TLD risk score (graduated 0.0 - 1.0)
        tld_risk = 0.0
        for tld, risk in SUSPICIOUS_TLDS.items():
            if sender_domain.endswith(tld.lstrip('.')):
                tld_risk = risk
                break
        features["tld_risk_score"] = tld_risk

        # [07] Display name spoofing
        # "PayPal Support <random@evil.xyz>" pattern
        has_brand_in_display = any(b in display_name for b in BRAND_NAMES)
        has_brand_in_sender = any(b in sender.lower() for b in BRAND_NAMES)
        brand_domain_match = any(
            b in sender_domain.split('.')[0] for b in BRAND_NAMES
        ) if sender_domain else False

        # Spoofing = brand in name but domain doesn't actually belong to brand
        features["display_name_spoof"] = int(
            (has_brand_in_display or has_brand_in_sender)
            and not brand_domain_match
            and not is_trusted_domain
            and sender_domain != ""
        )

        # == 8-11: Urgency & threat indicators =================================

        # [08] Has urgent language
        urgent_count = _count_matches(combined, URGENT_PHRASES)
        features["has_urgent_language"] = int(urgent_count > 0)

        # [09] Urgency score (weighted, 0.0-1.0)
        features["urgency_score"] = _compute_urgency_score(combined)

        # [10] Has threat language
        features["has_threat_language"] = int(
            _count_matches(combined, THREAT_PHRASES) > 0
        )

        # [11] Has reward/prize language
        features["has_reward_language"] = int(
            _count_matches(combined, REWARD_PHRASES) > 0
        )

        # == 12-17: Link analysis ==============================================

        urls = _extract_urls(email_text)

        # [12] Total link count
        features["link_count"] = min(len(urls), 20)

        # [13] Has suspicious links (shortened / IP-based / suspicious TLD)
        suspicious_links = 0
        for url in urls:
            url_lower = url.lower()
            if any(s in url_lower for s in SHORTENING_SERVICES):
                suspicious_links += 1
            elif re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                suspicious_links += 1
            elif any(t in url_lower for t in SUSPICIOUS_TLDS):
                suspicious_links += 1
        features["has_suspicious_links"] = int(suspicious_links > 0)

        # [14] Suspicious link ratio
        features["suspicious_link_ratio"] = round(
            suspicious_links / max(len(urls), 1), 4
        )

        # [15] Short URL present (binary)
        features["short_url_present"] = int(
            any(any(s in url.lower() for s in SHORTENING_SERVICES) for url in urls)
        )

        # [16] Any link flagged as phishing (set by caller, default 0)
        features["any_link_phishing"] = 0  # populated by app.py after URL model check

        # [17] Domain mismatch between link and brand text
        mismatched = re.findall(
            r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>',
            email_text, re.IGNORECASE
        )
        has_mismatch = 0
        for href, display_text in mismatched:
            display_clean = display_text.strip().lower()
            if re.match(r'https?://', display_clean) or '.' in display_clean:
                if display_clean not in href.lower():
                    has_mismatch = 1
                    break
        features["has_mismatched_url"] = has_mismatch

        # == 18-21: Sender analysis ============================================

        # [18] Sender domain mismatch (brand in body but sender domain differs)
        brands_in_body = [b for b in BRAND_NAMES if b in text_lower]
        sender_has_brand = any(b in sender_domain for b in BRAND_NAMES)
        features["sender_domain_mismatch"] = int(
            len(brands_in_body) > 0 and not sender_has_brand and sender_domain != ""
        )

        # [19] Sender uses free email service
        features["sender_is_freemail"] = int(
            sender_domain in FREEMAIL_DOMAINS
        )

        # [20] Sender domain has suspicious TLD
        features["sender_suspicious_tld"] = int(
            any(sender_domain.endswith(t.lstrip('.')) for t in SUSPICIOUS_TLDS)
        ) if sender_domain else 0

        # [21] Has spoofed sender (kept for backward compat, same as display_name_spoof)
        features["has_spoofed_sender"] = features["display_name_spoof"]

        # == 22-26: Content patterns (NLP) =====================================

        # [22] Has generic greeting
        features["has_generic_greeting"] = int(
            _count_matches(combined, GENERIC_GREETINGS) > 0
        )

        # [23] TF-IDF suspicion score
        features["tfidf_suspicion_score"] = _compute_tfidf_score(combined)

        # [24] Credential request (asks for password, SSN, bank info)
        features["credential_request"] = int(
            _count_matches(combined, CREDENTIAL_REQUESTS) > 0
        )

        # [25] Capitalization ratio (ALL CAPS = urgency trick)
        alpha_chars = [c for c in email_text if c.isalpha()]
        features["capitalization_ratio"] = round(
            sum(1 for c in alpha_chars if c.isupper()) / max(len(alpha_chars), 1), 4
        )

        # [26] Has HTML forms (credential harvesting)
        features["has_html_form"] = int(
            bool(re.search(r'<form|<input|type=["\']password', text_lower))
        )

        # == 27-32: Structural signals =========================================

        # [27] Body length (normalized)
        features["body_length"] = min(len(email_text), 10000)

        # [28] Special character ratio
        features["special_char_ratio"] = round(
            sum(1 for c in email_text if not c.isalnum() and not c.isspace())
            / max(len(email_text), 1), 4
        )

        # [29] Mentions dangerous attachments
        features["has_dangerous_attachment"] = int(
            any(ext in text_lower for ext in DANGEROUS_EXTENSIONS)
        )

        # [30] Spelling/grammar score (phishing misspellings)
        misspellings = [
            "paypa1", "arnazon", "micros0ft", "g00gle", "app1e",
            "netfl1x", "1nstagram", "faceb00k", "tw1tter",
            "acccount", "verifiy", "securty", "infomation",
            "updatte", "suspened", "unauthorised",
        ]
        features["spelling_error_score"] = min(
            _count_matches(combined, misspellings), 5
        )

        # [31] Urgent keyword count (raw count, capped)
        features["urgent_keyword_count"] = min(urgent_count, 10)

        # [32] URL phishing score (average from URL model — set by caller)
        features["url_phishing_score"] = 0.0

    except Exception:
        features = {k: 0 for k in email_feature_names()}

    return features


def email_feature_names() -> List[str]:
    """Ordered list of 32 email feature names."""
    return [
        # Header & auth (4)
        "spf_fail", "dkim_fail", "dmarc_fail", "from_reply_mismatch",
        # Domain reputation (3)
        "domain_age_suspicious", "tld_risk_score", "display_name_spoof",
        # Urgency & threat (4)
        "has_urgent_language", "urgency_score",
        "has_threat_language", "has_reward_language",
        # Link analysis (6)
        "link_count", "has_suspicious_links", "suspicious_link_ratio",
        "short_url_present", "any_link_phishing", "has_mismatched_url",
        # Sender analysis (4)
        "sender_domain_mismatch", "sender_is_freemail",
        "sender_suspicious_tld", "has_spoofed_sender",
        # Content patterns / NLP (5)
        "has_generic_greeting", "tfidf_suspicion_score",
        "credential_request", "capitalization_ratio", "has_html_form",
        # Structural signals (6)
        "body_length", "special_char_ratio",
        "has_dangerous_attachment", "spelling_error_score",
        "urgent_keyword_count", "url_phishing_score",
    ]


def email_feature_vector(email_text: str, sender: str = "", subject: str = "") -> list:
    """Returns ordered list of feature values for ML input."""
    f = extract_email_features(email_text, sender, subject)
    return [f.get(k, 0) for k in email_feature_names()]
