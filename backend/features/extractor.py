"""
PhishGuard -- features/extractor.py
MODULE 2: Backend API Processing Module -- Feature Extraction Step [06]
Extracts a structured numeric feature vector from a URL for ML classification.

30 engineered features for industrial-grade phishing detection.

Process Flow Reference:
  [06] Feature extraction module activated
  [07] Extracted features formatted for ML model input
"""

import re
import math
import string
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List
from collections import Counter


# -- Constants -----------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "paypa1", "paypal-", "bank-login", "secure-login", "account-verify",
    "signin-", "login-secure", "update-account", "verify-account",
    "banking-", "free-gift", "claim-prize", "winner-", "password-reset-",
    "apple-id", "microsoft-verify", "google-security", "amazon-secure",
    "ebay-support", "netflix-confirm", "instagram-verify", "facebook-login",
    "security-alert", "suspended", "unauthorized", "locked-account",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".link",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".buzz",
    ".bid", ".stream", ".download", ".racing", ".win",
    ".review", ".party", ".science", ".cricket", ".faith",
    ".icu", ".cam", ".monster", ".rest", ".surf",
}

BRAND_NAMES = [
    "paypal", "amazon", "netflix", "google", "apple",
    "microsoft", "facebook", "instagram", "ebay", "dropbox",
    "chase", "wellsfargo", "citibank", "dhl", "fedex",
    "linkedin", "twitter", "steam", "whatsapp", "telegram",
    "yahoo", "outlook", "icloud", "coinbase", "binance",
]

# Brand-owned TLDs (e.g., antigravity.google, store.apple)
# These are NOT phishing — they're owned by the brand itself.
BRAND_OWNED_TLDS = {
    ".google", ".apple", ".microsoft", ".amazon", ".youtube",
    ".netflix", ".facebook", ".instagram", ".linkedin",
    ".android", ".chrome", ".gmail", ".windows",
}

LEGITIMATE_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "x.com", "reddit.com", "linkedin.com", "github.com",
    "stackoverflow.com", "microsoft.com", "apple.com", "paypal.com",
    "netflix.com", "spotify.com", "instagram.com", "tiktok.com", "yahoo.com",
    "ebay.com", "adobe.com", "dropbox.com", "zoom.us", "slack.com",
    "notion.so", "figma.com", "medium.com", "quora.com", "pinterest.com",
    "wordpress.com", "cloudflare.com", "stripe.com", "twitch.tv",
    "discord.com", "whatsapp.com", "telegram.org", "bbc.com", "cnn.com",
    "nytimes.com", "walmart.com", "target.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "hulu.com", "disneyplus.com", "airbnb.com", "booking.com", "expedia.com",
    "coursera.org", "udemy.com", "aws.amazon.com", "azure.microsoft.com",
    "cloud.google.com", "salesforce.com", "shopify.com", "etsy.com",
    "onrender.com", "render.com", "vercel.app", "netlify.app",
    "herokuapp.com", "firebase.google.com", "web.app",
}

SENSITIVE_PATH_TERMS = [
    "login", "signin", "account", "secure", "verify",
    "banking", "update", "confirm", "password", "credential",
    "wallet", "payment", "billing", "auth", "token",
    "reset", "recover", "unlock", "validate", "checkout",
]

SHORTENING_SERVICES = [
    "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "j.mp", "tr.im",
    "rb.gy", "cutt.ly", "shorturl.at",
]


# -- Helper functions ----------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (higher = more random/suspicious)."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def _ratio_digits(text: str) -> float:
    """Ratio of digits to total characters."""
    if not text:
        return 0.0
    return sum(c.isdigit() for c in text) / len(text)


def _ratio_letters(text: str) -> float:
    """Ratio of letters to total characters."""
    if not text:
        return 0.0
    return sum(c.isalpha() for c in text) / len(text)


def _ratio_special(text: str) -> float:
    """Ratio of special characters to total characters."""
    if not text:
        return 0.0
    specials = set(string.punctuation)
    return sum(c in specials for c in text) / len(text)


# -- Main extractor ------------------------------------------------------------

def extract_features(url: str) -> Dict[str, Any]:
    """
    [06] Feature extraction module activated.
    Returns a flat dict of 30 named features extracted from the URL.
    """
    features: Dict[str, Any] = {}

    try:
        parsed   = urlparse(url.lower())
        hostname = parsed.hostname or ""
        path     = parsed.path or ""
        query    = parsed.query or ""
        full_url = url.lower()

        parts       = hostname.split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        # == 1. Length features (5) ============================================
        features["url_length"]          = len(url)
        features["hostname_length"]     = len(hostname)
        features["path_length"]         = len(path)
        features["query_length"]        = len(query)
        features["path_depth"]          = max(0, path.count("/") - 1)

        # == 2. Count features (7) =============================================
        features["num_dots"]            = full_url.count(".")
        features["num_hyphens"]         = full_url.count("-")
        features["num_underscores"]     = full_url.count("_")
        features["num_digits"]          = sum(c.isdigit() for c in hostname)
        features["num_subdomains"]      = max(0, len(parts) - 2)
        features["num_query_params"]    = len(parse_qs(query))
        features["num_special_chars"]   = sum(c in "@?=&%#~!" for c in url)

        # == 3. Ratio features (4) =============================================
        features["digit_ratio"]         = round(_ratio_digits(hostname), 4)
        features["letter_ratio"]        = round(_ratio_letters(hostname), 4)
        features["special_char_ratio"]  = round(_ratio_special(full_url), 4)
        features["hostname_entropy"]    = round(_shannon_entropy(hostname), 4)

        # == 4. Boolean / binary flags (11) ====================================
        features["uses_https"]          = int(parsed.scheme == "https")
        features["is_ip_address"]       = int(bool(
            re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)
        ))
        features["is_known_tld_suspicious"] = int(
            any(hostname.endswith(t) for t in SUSPICIOUS_TLDS)
        )
        features["has_suspicious_keyword"]  = int(
            any(kw in full_url for kw in SUSPICIOUS_KEYWORDS)
        )
        features["has_at_symbol"]       = int("@" in url)
        features["has_double_slash"]    = int("//" in path)
        features["has_redirect_param"]  = int(
            "redirect=" in full_url or "url=" in full_url or "next=" in full_url
        )
        features["has_encoded_chars"]   = int(
            "%2f" in full_url or "%40" in full_url or
            "%3a" in full_url or "%3d" in full_url
        )

        # Check if domain is a brand-owned TLD (e.g. antigravity.google)
        is_brand_tld = any(hostname.endswith(tld) for tld in BRAND_OWNED_TLDS)

        features["is_known_legitimate"] = int(
            root_domain in LEGITIMATE_DOMAINS or is_brand_tld
        )

        # Brand impersonation

        brand_in_host = any(
            b in hostname
            and root_domain not in LEGITIMATE_DOMAINS
            and not is_brand_tld
            for b in BRAND_NAMES
        )
        features["brand_in_hostname"]   = int(brand_in_host)

        brand_hyphen = any(
            (f"{b}-" in hostname or f"-{b}" in hostname)
            and root_domain not in LEGITIMATE_DOMAINS
            and not is_brand_tld
            for b in BRAND_NAMES
        )
        features["brand_hyphenated"]    = int(brand_hyphen)

        # == 5. Advanced features (3) ==========================================
        # Lookalike / homograph characters
        lookalike_chars = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "vv": "w"}
        has_lookalike = any(k in hostname for k in lookalike_chars)
        features["has_lookalike_chars"] = int(has_lookalike)

        # Sensitive path terms
        features["has_sensitive_path"]  = int(
            any(p in path for p in SENSITIVE_PATH_TERMS)
        )

        # URL shortening service
        features["is_shortened_url"]    = int(
            any(s in full_url for s in SHORTENING_SERVICES)
        )

    except Exception:
        features = {k: 0 for k in _feature_names()}

    return features


def feature_vector(url: str) -> list:
    """
    [07] Extracted features formatted for ML model input.
    Returns ordered list of feature values.
    """
    f = extract_features(url)
    return [f.get(k, 0) for k in _feature_names()]


def _feature_names() -> List[str]:
    """Ordered list of 30 feature names."""
    return [
        # Length (5)
        "url_length", "hostname_length", "path_length",
        "query_length", "path_depth",
        # Count (7)
        "num_dots", "num_hyphens", "num_underscores", "num_digits",
        "num_subdomains", "num_query_params", "num_special_chars",
        # Ratio (4)
        "digit_ratio", "letter_ratio", "special_char_ratio",
        "hostname_entropy",
        # Boolean (11)
        "uses_https", "is_ip_address", "is_known_tld_suspicious",
        "has_suspicious_keyword", "has_at_symbol", "has_double_slash",
        "has_redirect_param", "has_encoded_chars", "is_known_legitimate",
        "brand_in_hostname", "brand_hyphenated",
        # Advanced (3)
        "has_lookalike_chars", "has_sensitive_path", "is_shortened_url",
    ]
