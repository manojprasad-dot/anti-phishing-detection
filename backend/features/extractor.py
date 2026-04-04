"""
PhishGuard — features/extractor.py
MODULE 2: Backend API Processing Module — Feature Extraction Step [06]
Extracts a structured numeric feature vector from a URL for ML classification.

Process Flow Reference:
  [06] Feature extraction module activated
  [07] Extracted features formatted for ML model input
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any


# ── Constants ─────────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "paypa1", "paypal-", "bank-login", "secure-login", "account-verify",
    "signin-", "login-secure", "update-account", "verify-account",
    "banking-", "free-gift", "claim-prize", "winner-", "password-reset-",
    "apple-id", "microsoft-verify", "google-security", "amazon-secure",
    "ebay-support", "netflix-confirm", "instagram-verify", "facebook-login"
]

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".work", ".click", ".link",
                   ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".buzz"}

BRAND_NAMES = ["paypal", "amazon", "netflix", "google", "apple",
               "microsoft", "facebook", "instagram", "ebay", "dropbox",
               "chase", "wellsfargo", "citibank", "dhl", "fedex"]

LEGITIMATE_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "reddit.com", "linkedin.com", "github.com", "stackoverflow.com",
    "microsoft.com", "apple.com", "paypal.com", "netflix.com", "spotify.com",
    "instagram.com", "tiktok.com", "yahoo.com", "ebay.com", "adobe.com",
    "dropbox.com", "zoom.us", "slack.com", "notion.so", "figma.com"
}


# ── Main extractor ────────────────────────────────────────────────────────────

def extract_features(url: str) -> Dict[str, Any]:
    """
    [06] Feature extraction module activated.
    Returns a flat dict of named features extracted from the URL.
    """
    features: Dict[str, Any] = {}

    try:
        parsed   = urlparse(url.lower())
        hostname = parsed.hostname or ""
        path     = parsed.path or ""
        query    = parsed.query or ""
        full_url = url.lower()

        # ── Domain features ───────────────────────────────────────
        parts      = hostname.split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        features["url_length"]          = len(url)
        features["hostname_length"]     = len(hostname)
        features["path_length"]         = len(path)
        features["num_dots"]            = full_url.count(".")
        features["num_hyphens"]         = full_url.count("-")
        features["num_digits"]          = sum(c.isdigit() for c in hostname)
        features["num_subdomains"]      = max(0, len(parts) - 2)
        features["num_query_params"]    = len(parse_qs(query))
        features["num_special_chars"]   = sum(c in "@?=&%#~" for c in url)

        # ── Boolean flags ─────────────────────────────────────────
        features["uses_https"]          = int(parsed.scheme == "https")
        features["is_ip_address"]       = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)))
        features["is_known_tld_suspicious"] = int(any(hostname.endswith(t) for t in SUSPICIOUS_TLDS))
        features["has_suspicious_keyword"]  = int(any(kw in full_url for kw in SUSPICIOUS_KEYWORDS))
        features["has_at_symbol"]       = int("@" in url)
        features["has_double_slash"]    = int("//" in path)
        features["has_redirect_param"]  = int("redirect=" in full_url or "url=" in full_url)
        features["has_encoded_chars"]   = int("%2f" in full_url or "%40" in full_url or "%3a" in full_url)
        features["is_known_legitimate"] = int(root_domain in LEGITIMATE_DOMAINS)

        # ── Brand impersonation ───────────────────────────────────
        brand_in_host = any(b in hostname and root_domain not in LEGITIMATE_DOMAINS
                            for b in BRAND_NAMES)
        features["brand_in_hostname"]   = int(brand_in_host)

        brand_hyphen = any(
            (f"{b}-" in hostname or f"-{b}" in hostname)
            and root_domain not in LEGITIMATE_DOMAINS
            for b in BRAND_NAMES
        )
        features["brand_hyphenated"]    = int(brand_hyphen)

        # ── Lookalike / homograph ─────────────────────────────────
        lookalike_chars = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "vv": "w"}
        has_lookalike = any(k in hostname for k in lookalike_chars)
        features["has_lookalike_chars"] = int(has_lookalike)

        # ── Path features ─────────────────────────────────────────
        sensitive_paths = ["login", "signin", "account", "secure", "verify",
                           "banking", "update", "confirm", "password", "credential"]
        features["has_sensitive_path"]  = int(any(p in path for p in sensitive_paths))
        features["path_depth"]          = path.count("/") - 1

    except Exception:
        # Return zeroed features on parse error
        features = {k: 0 for k in _feature_names()}

    return features


def feature_vector(url: str):
    """
    [07] Extracted features formatted for ML model input.
    Returns ordered list of feature values.
    """
    f = extract_features(url)
    return [f.get(k, 0) for k in _feature_names()]


def _feature_names():
    return [
        "url_length", "hostname_length", "path_length",
        "num_dots", "num_hyphens", "num_digits",
        "num_subdomains", "num_query_params", "num_special_chars",
        "uses_https", "is_ip_address", "is_known_tld_suspicious",
        "has_suspicious_keyword", "has_at_symbol", "has_double_slash",
        "has_redirect_param", "has_encoded_chars", "is_known_legitimate",
        "brand_in_hostname", "brand_hyphenated", "has_lookalike_chars",
        "has_sensitive_path", "path_depth"
    ]
