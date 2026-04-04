"""
PhishGuard — backend/app.py
MODULE 2: Backend API Processing Module
Central Flask API that coordinates feature extraction and ML classification.

Install: pip install flask flask-cors
Run:     python app.py
"""

import sys
import os
import logging
import datetime

# Allow imports from sibling packages
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify
from flask_cors import CORS

from features.extractor import extract_features
from ml.detector import detector

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# ── Request log (in-memory, last 500) ────────────────────────────────────────
request_log = []


# ── [02] API endpoint for URL analysis ───────────────────────────────────────
@app.route("/analyze", methods=["POST"])
def analyze():
    """
    [03] Browser extension sends URL analysis request.
    [04] API receives and validates request.
    [05-09] Feature extraction → ML prediction → response.
    [10] API sends classification response back to extension.
    """
    # [04] Validate
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field"}), 400

    url      = str(data["url"]).strip()
    tab_id   = data.get("tab_id", "?")
    ts       = datetime.datetime.utcnow().isoformat()

    logger.info(f"[tab={tab_id}] Analyzing → {url[:80]}")

    # [05] Preprocess / normalize
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # [06] Feature extraction
    features = extract_features(url)

    # [07-08] ML prediction
    result = detector.predict(features)

    # Enrich response
    result["url"]       = url
    result["timestamp"] = ts
    result["features"]  = features   # Useful for debugging / analytics

    # Log result
    log_entry = {
        "url": url, "tab_id": tab_id,
        "is_phishing": result["is_phishing"],
        "confidence":  result["confidence"],
        "risk_level":  result["risk_level"],
        "timestamp":   ts
    }
    request_log.insert(0, log_entry)
    if len(request_log) > 500:
        request_log.pop()

    # Console summary
    icon = "⚠️  PHISHING" if result["is_phishing"] else "✓  safe    "
    logger.info(f"  {icon}  confidence={result['confidence']*100:.0f}%  risk={result['risk_level']}")

    # [10] Return to extension
    return jsonify(result), 200


# ── Analytics endpoint ────────────────────────────────────────────────────────
@app.route("/analytics", methods=["GET"])
def analytics():
    """Returns aggregated stats from the request log."""
    total   = len(request_log)
    threats = sum(1 for r in request_log if r["is_phishing"])
    safe    = total - threats

    risk_dist = {"high": 0, "medium": 0, "low": 0, "safe": 0}
    for r in request_log:
        risk_dist[r.get("risk_level", "safe")] = risk_dist.get(r.get("risk_level", "safe"), 0) + 1

    recent_threats = [r for r in request_log if r["is_phishing"]][:10]

    return jsonify({
        "total_analyzed": total,
        "threats_detected": threats,
        "safe_count": safe,
        "threat_rate": round(threats / total * 100, 1) if total else 0,
        "risk_distribution": risk_dist,
        "recent_threats": recent_threats
    })


# ── Health check ──────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "PhishGuard API v1.0",
        "model": "sklearn" if detector.sklearn_model else "heuristic",
        "timestamp": datetime.datetime.utcnow().isoformat()
    })


# ── Test endpoint ─────────────────────────────────────────────────────────────
@app.route("/test", methods=["GET"])
def test():
    """Run a batch of sample URLs and return results."""
    samples = [
        ("https://www.google.com",                     False),
        ("https://github.com",                         False),
        ("https://paypal-secure-login.xyz/verify",     True),
        ("http://192.168.1.1/phishing-page",           True),
        ("https://amazon-account-update.club/login",   True),
        ("https://secure.paypa1.com/signin",           True),
        ("https://dropbox-file-share.tk/download",     True),
        ("https://netflix.com",                        False),
    ]

    results = []
    for url, expected in samples:
        feats  = extract_features(url)
        result = detector.predict(feats)
        correct = result["is_phishing"] == expected
        results.append({
            "url":         url,
            "expected":    "phishing" if expected else "safe",
            "predicted":   "phishing" if result["is_phishing"] else "safe",
            "confidence":  f"{result['confidence']*100:.0f}%",
            "risk_level":  result["risk_level"],
            "correct":     correct
        })

    accuracy = sum(1 for r in results if r["correct"]) / len(results) * 100
    return jsonify({"accuracy": f"{accuracy:.0f}%", "results": results})


# ── Feedback receiver (from Module 3 / content.js) ───────────────────────────
@app.route("/feedback", methods=["POST"])
def feedback():
    """Receive user-submitted feedback for model improvement."""
    data = request.get_json(silent=True) or {}
    logger.info(f"[Feedback] url={data.get('url','')} verdict={data.get('verdict','')}")
    # In production: save to database for retraining
    return jsonify({"ok": True})


# ── Start server ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "━"*54)
    print("  🛡️  PhishGuard API Server")
    print("  ▸  http://localhost:5000/analyze   — main endpoint")
    print("  ▸  http://localhost:5000/test       — run test batch")
    print("  ▸  http://localhost:5000/analytics  — stats dashboard")
    print("  ▸  http://localhost:5000/health     — service health")
    print("━"*54 + "\n")
    app.run(debug=True, port=5000, host="0.0.0.0")
