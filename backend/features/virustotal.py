"""
PhishGuard -- features/virustotal.py
VirusTotal API integration for URL validation against 70+ security engines.

Uses the VirusTotal v3 API to scan URLs and get threat verdicts from
major security vendors (Google Safe Browsing, McAfee, Norton, etc.)
"""

import os
import time
import base64
import logging
import requests

logger = logging.getLogger(__name__)

# API key from environment variable (set in Render dashboard)
VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()
VT_BASE = "https://www.virustotal.com/api/v3"

# Cache results to avoid hitting rate limits (4 req/min on free tier)
_cache = {}
CACHE_TTL = 300  # 5 minutes


def _get_headers():
    return {"x-apikey": VT_API_KEY}


def _url_id(url: str) -> str:
    """Generate VirusTotal URL identifier."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def scan_url(url: str) -> dict:
    """
    Scan a URL with VirusTotal and return threat analysis.

    Returns:
        {
            "vt_available": True/False,
            "vt_malicious": 0,        # engines flagging as malicious
            "vt_suspicious": 0,       # engines flagging as suspicious
            "vt_harmless": 0,         # engines saying harmless
            "vt_undetected": 0,       # engines with no result
            "vt_total": 0,            # total engines scanned
            "vt_is_phishing": False,  # our verdict
            "vt_confidence": 0.0,     # confidence score
        }
    """
    default = {
        "vt_available": False,
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_harmless": 0,
        "vt_undetected": 0,
        "vt_total": 0,
        "vt_is_phishing": False,
        "vt_confidence": 0.0,
    }

    if not VT_API_KEY:
        return default

    # Check cache
    now = time.time()
    if url in _cache and (now - _cache[url]["time"]) < CACHE_TTL:
        return _cache[url]["data"]

    try:
        # Try to get existing analysis first
        url_id = _url_id(url)
        resp = requests.get(
            f"{VT_BASE}/urls/{url_id}",
            headers=_get_headers(),
            timeout=8,
        )

        if resp.status_code == 404:
            # URL not in VT database -- submit for scanning
            resp = requests.post(
                f"{VT_BASE}/urls",
                headers=_get_headers(),
                data={"url": url},
                timeout=8,
            )
            if resp.status_code != 200:
                return default

            # Wait briefly for analysis
            analysis_id = resp.json()["data"]["id"]
            time.sleep(2)

            # Get analysis result
            resp = requests.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=_get_headers(),
                timeout=8,
            )
            if resp.status_code != 200:
                return default

            data = resp.json()["data"]["attributes"]
            stats = data.get("stats", {})

        elif resp.status_code == 200:
            data = resp.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})

        else:
            return default

        malicious   = stats.get("malicious", 0)
        suspicious  = stats.get("suspicious", 0)
        harmless    = stats.get("harmless", 0)
        undetected  = stats.get("undetected", 0)
        total       = malicious + suspicious + harmless + undetected

        # Calculate confidence
        if total > 0:
            threat_ratio = (malicious + suspicious) / total
        else:
            threat_ratio = 0.0

        # Verdict: phishing if 2+ engines flagged it
        is_phishing = (malicious + suspicious) >= 2

        result = {
            "vt_available": True,
            "vt_malicious": malicious,
            "vt_suspicious": suspicious,
            "vt_harmless": harmless,
            "vt_undetected": undetected,
            "vt_total": total,
            "vt_is_phishing": is_phishing,
            "vt_confidence": round(threat_ratio, 4),
        }

        # Cache it
        _cache[url] = {"time": now, "data": result}

        logger.info(
            f"VT scan: {url[:50]}... -> "
            f"mal={malicious} sus={suspicious} harm={harmless} "
            f"(phishing={is_phishing})"
        )

        return result

    except requests.exceptions.Timeout:
        logger.warning(f"VT timeout for: {url[:50]}")
        return default

    except Exception as e:
        logger.warning(f"VT error: {e}")
        return default
