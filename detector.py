"""
PhishGuard — ml/detector.py
MODULE 2 (Analytics & ML): Phishing Detection Model
Heuristic rule engine + scikit-learn model stub for classification.

The heuristic engine works out-of-the-box.
The sklearn model can be trained on real datasets (see train() below).
"""

import os
import pickle
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# ── Feature weights for the heuristic engine ──────────────────────────────────
FEATURE_WEIGHTS = {
    "is_ip_address":           0.65,
    "brand_hyphenated":        0.55,
    "brand_in_hostname":       0.50,
    "has_suspicious_keyword":  0.40,
    "is_known_tld_suspicious": 0.35,
    "has_at_symbol":           0.35,
    "has_lookalike_chars":     0.30,
    "has_sensitive_path":      0.25,
    "num_subdomains":          0.08,   # per subdomain above 2
    "has_encoded_chars":       0.20,
    "has_redirect_param":      0.18,
    "has_double_slash":        0.18,
    "url_length_penalty":      0.10,   # applied if url_length > 100
    "no_https_penalty":        0.15,   # applied if uses_https == 0
    # Negatives (reduces score)
    "is_known_legitimate":    -1.00,   # hard override
}

PHISHING_THRESHOLD = 0.50


class PhishingDetector:
    """
    [08] Feature vector forwarded to the phishing detection model.
    [09] Prediction result generated.
    """

    def __init__(self):
        self.sklearn_model = None
        self._try_load_sklearn_model()

    # ── Primary predict method ────────────────────────────────────────────────
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Returns classification result dict:
          { is_phishing, confidence, risk_level, reasons }
        """
        # Hard override: known legitimate domain
        if features.get("is_known_legitimate"):
            return self._result(False, 0.01, [])

        # Try sklearn model first (if trained)
        if self.sklearn_model is not None:
            return self._sklearn_predict(features)

        # Fallback: heuristic engine
        return self._heuristic_predict(features)

    # ── Heuristic engine ──────────────────────────────────────────────────────
    def _heuristic_predict(self, f: Dict[str, Any]) -> Dict[str, Any]:
        score   = 0.0
        reasons: List[str] = []

        if f.get("is_ip_address"):
            score += FEATURE_WEIGHTS["is_ip_address"]
            reasons.append("Uses raw IP address instead of a domain name")

        if f.get("brand_hyphenated"):
            score += FEATURE_WEIGHTS["brand_hyphenated"]
            reasons.append("Domain uses a brand name with hyphens (brand spoofing)")

        if f.get("brand_in_hostname"):
            score += FEATURE_WEIGHTS["brand_in_hostname"]
            reasons.append("Hostname contains a major brand name on a non-official domain")

        if f.get("has_suspicious_keyword"):
            score += FEATURE_WEIGHTS["has_suspicious_keyword"]
            reasons.append("URL contains phishing-related keywords (e.g. 'verify', 'secure-login')")

        if f.get("is_known_tld_suspicious"):
            score += FEATURE_WEIGHTS["is_known_tld_suspicious"]
            reasons.append("Uses a high-risk top-level domain (.xyz, .tk, .ml, etc.)")

        if f.get("has_at_symbol"):
            score += FEATURE_WEIGHTS["has_at_symbol"]
            reasons.append("URL contains '@' symbol which can obscure the real destination")

        if f.get("has_lookalike_chars"):
            score += FEATURE_WEIGHTS["has_lookalike_chars"]
            reasons.append("Hostname uses lookalike characters (0→o, 1→l) to mimic real domains")

        if f.get("has_sensitive_path"):
            score += FEATURE_WEIGHTS["has_sensitive_path"]
            reasons.append("URL path contains sensitive terms like 'login', 'account', 'verify'")

        subdomains = max(0, int(f.get("num_subdomains", 0)) - 2)
        if subdomains > 0:
            score += FEATURE_WEIGHTS["num_subdomains"] * subdomains
            reasons.append(f"Excessive subdomain depth ({int(f.get('num_subdomains',0))} levels)")

        if f.get("has_encoded_chars"):
            score += FEATURE_WEIGHTS["has_encoded_chars"]
            reasons.append("URL contains encoded characters to obfuscate the path")

        if f.get("has_redirect_param"):
            score += FEATURE_WEIGHTS["has_redirect_param"]
            reasons.append("URL contains redirect parameters")

        if f.get("has_double_slash"):
            score += FEATURE_WEIGHTS["has_double_slash"]
            reasons.append("URL path contains a double slash redirect technique")

        if int(f.get("url_length", 0)) > 100:
            score += FEATURE_WEIGHTS["url_length_penalty"]
            reasons.append(f"Unusually long URL ({f.get('url_length')} characters)")

        if not f.get("uses_https"):
            score += FEATURE_WEIGHTS["no_https_penalty"]
            reasons.append("Page served over HTTP (not encrypted HTTPS)")

        confidence = min(score, 1.0)
        return self._result(confidence >= PHISHING_THRESHOLD, confidence, reasons[:5])

    # ── Sklearn model (stub — train with real data) ───────────────────────────
    def _sklearn_predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        from features.extractor import _feature_names
        try:
            vector = [[features.get(k, 0) for k in _feature_names()]]
            proba  = self.sklearn_model.predict_proba(vector)[0][1]  # P(phishing)
            return self._result(proba >= PHISHING_THRESHOLD, round(proba, 4), [])
        except Exception as e:
            logger.warning(f"sklearn predict failed, falling back: {e}")
            return self._heuristic_predict(features)

    def _try_load_sklearn_model(self):
        model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
        if os.path.exists(model_path):
            try:
                with open(model_path, "rb") as f:
                    self.sklearn_model = pickle.load(f)
                logger.info("Loaded sklearn model from model.pkl")
            except Exception as e:
                logger.warning(f"Could not load model.pkl: {e}")

    @staticmethod
    def _result(is_phishing: bool, confidence: float, reasons: List[str]) -> Dict[str, Any]:
        if confidence >= 0.7:   risk = "high"
        elif confidence >= 0.4: risk = "medium"
        else:                   risk = "low"
        return {
            "is_phishing": is_phishing,
            "confidence":  round(confidence, 4),
            "risk_level":  "safe" if not is_phishing and confidence < 0.15 else risk,
            "reasons":     reasons
        }


# ── Training stub ─────────────────────────────────────────────────────────────
def train(urls: list, labels: list, save_path: str = "ml/model.pkl"):
    """
    Train a RandomForestClassifier on labelled URL data.
    labels: list of 0 (safe) or 1 (phishing)

    Example:
        from ml.detector import train
        train(["https://google.com", "http://paypa1.xyz/login"], [0, 1])
    """
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
        from features.extractor import feature_vector
        import pickle

        X = [feature_vector(u) for u in urls]
        y = labels

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)

        preds = clf.predict(X_test)
        print(classification_report(y_test, preds, target_names=["Safe", "Phishing"]))

        with open(save_path, "wb") as f:
            pickle.dump(clf, f)
        print(f"Model saved to {save_path}")

    except ImportError:
        print("scikit-learn not installed. Run: pip install scikit-learn")


# Singleton detector instance
detector = PhishingDetector()
