"""
PhishGuard -- ml/email_detector.py
MODULE 6: Email Phishing Detection — XGBoost Ensemble Detector (v2.0)

High-accuracy email phishing detector:
  - XGBoost ML model — 70% weight
  - Heuristic rule engine — 30% weight
  - Hybrid decision engine (rules can override)
  - Calibrated risk scoring (0-100)
  - Trusted domain whitelist
  - Explainable reasons

Risk Score Thresholds:
  0-30   → Safe ✅
  30-60  → Suspicious ⚠️
  60-100 → Phishing 🔴
"""

import os
import pickle
import logging
import numpy as np
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# -- Feature weights for email heuristic engine --------------------------------
EMAIL_FEATURE_WEIGHTS = {
    # Header & auth (highest signal)
    "spf_fail":                 0.30,
    "dkim_fail":                0.25,
    "dmarc_fail":               0.35,
    "from_reply_mismatch":      0.20,
    # Domain reputation
    "domain_age_suspicious":    0.30,
    "tld_risk_score":           0.25,   # already 0-1
    "display_name_spoof":       0.45,
    # Urgency & threat
    "has_urgent_language":       0.20,
    "urgency_score":             0.30,   # already 0-1
    "has_threat_language":       0.30,
    "has_reward_language":       0.25,
    # Link analysis (biggest win)
    "has_suspicious_links":      0.35,
    "suspicious_link_ratio":     0.20,
    "short_url_present":         0.20,
    "any_link_phishing":         0.50,   # highest single signal
    "has_mismatched_url":        0.40,
    # Sender analysis
    "sender_domain_mismatch":    0.35,
    "sender_is_freemail":        0.10,
    "sender_suspicious_tld":     0.30,
    "has_spoofed_sender":        0.45,
    # Content / NLP
    "has_generic_greeting":      0.15,
    "tfidf_suspicion_score":     0.30,  # already 0-1
    "credential_request":        0.35,
    "capitalization_ratio":      0.10,  # applied if > 0.3
    "has_html_form":             0.25,
    # Structural
    "has_dangerous_attachment":   0.25,
    "spelling_error_score":      0.08,  # per error
    "urgent_keyword_count":      0.05,  # per keyword
    "url_phishing_score":        0.40,  # already 0-1
}

# Risk thresholds
PHISHING_THRESHOLD = 0.60   # 60+ = Phishing
SUSPICIOUS_THRESHOLD = 0.30  # 30-60 = Suspicious

# Trusted sender domains (reduce false positives)
TRUSTED_DOMAINS = {
    "gmail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "icloud.com", "google.com", "microsoft.com",
    "apple.com", "amazon.com", "netflix.com", "paypal.com",
    "github.com", "linkedin.com", "slack.com", "spotify.com",
    "zoom.us", "stripe.com", "trello.com", "notion.so",
    "dropbox.com", "adobe.com", "shopify.com", "twitter.com",
    "facebook.com", "instagram.com", "tiktok.com",
}


class EmailPhishingDetector:
    """
    XGBoost Ensemble email phishing detector.
    ML model (70%) + Heuristic rules (30%) + Hybrid override.
    Calibrated risk scoring: 0-100.
    """

    def __init__(self):
        self.ml_model = None
        self.model_meta = {}
        self._try_load_model()

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensemble detection for email content.
        Returns: {
            is_phishing, confidence, risk_score, risk_level,
            reasons, details
        }
        """
        sender_domain = str(features.get("_sender_domain", ""))

        # ── Step 1: Trusted domain whitelist ──────────────────────────
        if sender_domain in TRUSTED_DOMAINS:
            # Still run analysis but apply trust discount
            trust_discount = 0.5  # halve the score
        else:
            trust_discount = 1.0

        # ── Step 2: Heuristic analysis (always available) ────────────
        heuristic_result = self._heuristic_predict(features)
        h_conf = heuristic_result["confidence"]
        reasons = heuristic_result["reasons"]

        # ── Step 3: ML model prediction ──────────────────────────────
        if self.ml_model is not None:
            ml_result = self._ml_predict(features)
            ml_conf = ml_result["confidence"]

            # Weighted ensemble: 70% ML + 30% Heuristic
            combined = (ml_conf * 0.7) + (h_conf * 0.3)

            # If either engine is very confident, boost
            if h_conf >= 0.8 or ml_conf >= 0.8:
                combined = max(combined, max(h_conf, ml_conf))

            model_score = round(ml_conf, 4)
        else:
            combined = h_conf
            model_score = None

        # Apply trust discount
        combined = combined * trust_discount
        combined = min(combined, 1.0)

        # ── Step 4: Hybrid decision engine ───────────────────────────
        rule_triggers = []

        # Rule 1: Any link flagged phishing → strong signal
        if features.get("any_link_phishing"):
            combined = max(combined, 0.75)
            rule_triggers.append("phishing_link")
            if "Embedded link flagged as phishing by URL model" not in reasons:
                reasons.append("Embedded link flagged as phishing by URL model")

        # Rule 2: Auth fail + suspicious domain → very strong signal
        if (features.get("dmarc_fail") and features.get("domain_age_suspicious")):
            combined = max(combined, 0.70)
            rule_triggers.append("auth_fail_new_domain")
            if "Authentication failed on suspicious domain" not in reasons:
                reasons.append("Authentication failed on suspicious domain")

        # Rule 3: Display name spoofing → strong signal
        if features.get("display_name_spoof") and features.get("dmarc_fail"):
            combined = max(combined, 0.80)
            rule_triggers.append("spoofed_sender_auth_fail")
            if "Sender name spoofs a brand with failed authentication" not in reasons:
                reasons.append("Sender name spoofs a brand with failed authentication")

        # Rule 4: Credential harvesting form → strong signal
        if features.get("has_html_form") and features.get("credential_request"):
            combined = max(combined, 0.75)
            rule_triggers.append("credential_harvest")
            if "Email contains credential harvesting form" not in reasons:
                reasons.append("Email contains credential harvesting form")

        combined = min(combined, 1.0)

        # ── Step 5: Calibrated risk score (0-100) ────────────────────
        risk_score = int(round(combined * 100))

        # ── Step 6: 3-tier classification ────────────────────────────
        if risk_score >= 60:
            result = "phishing"
            risk_level = "high"
        elif risk_score >= 30:
            result = "suspicious"
            risk_level = "medium"
        else:
            result = "safe"
            risk_level = "safe" if risk_score < 15 else "low"

        # Build auth detail
        auth_detail = {
            "spf": "fail" if features.get("spf_fail") else "pass",
            "dkim": "fail" if features.get("dkim_fail") else "pass",
            "dmarc": "fail" if features.get("dmarc_fail") else "pass",
        }

        details = {
            "sender_analysis": auth_detail,
            "model_score": model_score,
            "heuristic_score": round(h_conf, 4),
            "rule_triggers": rule_triggers,
            "trust_applied": sender_domain in TRUSTED_DOMAINS,
        }

        return {
            "is_phishing": result == "phishing",
            "result": result,
            "confidence": round(combined, 4),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reasons": reasons[:8],
            "details": details,
        }

    def _heuristic_predict(self, f: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based email phishing detection with 32 features."""
        score = 0.0
        reasons: List[str] = []

        # Header & auth signals
        if f.get("spf_fail"):
            score += EMAIL_FEATURE_WEIGHTS["spf_fail"]
            reasons.append("SPF authentication failed")

        if f.get("dkim_fail"):
            score += EMAIL_FEATURE_WEIGHTS["dkim_fail"]
            reasons.append("DKIM authentication failed")

        if f.get("dmarc_fail"):
            score += EMAIL_FEATURE_WEIGHTS["dmarc_fail"]
            reasons.append("DMARC authentication failed")

        if f.get("from_reply_mismatch"):
            score += EMAIL_FEATURE_WEIGHTS["from_reply_mismatch"]
            reasons.append("From/Reply-To address mismatch")

        # Domain reputation
        if f.get("domain_age_suspicious"):
            score += EMAIL_FEATURE_WEIGHTS["domain_age_suspicious"]
            reasons.append("Sender domain appears new/suspicious")

        tld_risk = float(f.get("tld_risk_score", 0))
        if tld_risk > 0:
            score += EMAIL_FEATURE_WEIGHTS["tld_risk_score"] * tld_risk
            reasons.append(f"Sender uses high-risk TLD (risk: {tld_risk*100:.0f}%)")

        if f.get("display_name_spoof"):
            score += EMAIL_FEATURE_WEIGHTS["display_name_spoof"]
            reasons.append("Display name spoofs a known brand")

        # Urgency & threat
        if f.get("has_urgent_language"):
            score += EMAIL_FEATURE_WEIGHTS["has_urgent_language"]
            reasons.append("Contains urgent/pressure language")

        urgency = float(f.get("urgency_score", 0))
        if urgency > 0.2:
            score += EMAIL_FEATURE_WEIGHTS["urgency_score"] * urgency
            reasons.append(f"High urgency score ({urgency*100:.0f}%)")

        if f.get("has_threat_language"):
            score += EMAIL_FEATURE_WEIGHTS["has_threat_language"]
            reasons.append("Contains threatening language (suspension, legal action)")

        if f.get("has_reward_language"):
            score += EMAIL_FEATURE_WEIGHTS["has_reward_language"]
            reasons.append("Contains reward/prize language (common in scams)")

        # Link analysis
        if f.get("has_suspicious_links"):
            score += EMAIL_FEATURE_WEIGHTS["has_suspicious_links"]
            reasons.append("Contains suspicious links (shortened, IP-based, bad TLD)")

        susp_ratio = float(f.get("suspicious_link_ratio", 0))
        if susp_ratio > 0.5:
            score += EMAIL_FEATURE_WEIGHTS["suspicious_link_ratio"]

        if f.get("short_url_present"):
            score += EMAIL_FEATURE_WEIGHTS["short_url_present"]
            reasons.append("Contains shortened URL (hides real destination)")

        if f.get("any_link_phishing"):
            score += EMAIL_FEATURE_WEIGHTS["any_link_phishing"]
            reasons.append("Embedded link flagged as phishing by URL model")

        if f.get("has_mismatched_url"):
            score += EMAIL_FEATURE_WEIGHTS["has_mismatched_url"]
            reasons.append("Link text doesn't match actual URL (deceptive)")

        # Sender analysis
        if f.get("sender_domain_mismatch"):
            score += EMAIL_FEATURE_WEIGHTS["sender_domain_mismatch"]
            reasons.append("Sender domain doesn't match brand mentioned in email")

        if f.get("sender_is_freemail"):
            score += EMAIL_FEATURE_WEIGHTS["sender_is_freemail"]
            reasons.append("Sent from free email service (unusual for official emails)")

        if f.get("sender_suspicious_tld"):
            score += EMAIL_FEATURE_WEIGHTS["sender_suspicious_tld"]
            reasons.append("Sender uses a high-risk domain TLD")

        if f.get("has_spoofed_sender"):
            score += EMAIL_FEATURE_WEIGHTS["has_spoofed_sender"]
            reasons.append("Sender name contains brand but domain doesn't match")

        # Content / NLP
        if f.get("has_generic_greeting"):
            score += EMAIL_FEATURE_WEIGHTS["has_generic_greeting"]
            reasons.append("Uses generic greeting instead of your name")

        tfidf = float(f.get("tfidf_suspicion_score", 0))
        if tfidf > 0.15:
            score += EMAIL_FEATURE_WEIGHTS["tfidf_suspicion_score"] * tfidf
            reasons.append(f"Text matches phishing patterns (TF-IDF: {tfidf*100:.0f}%)")

        if f.get("credential_request"):
            score += EMAIL_FEATURE_WEIGHTS["credential_request"]
            reasons.append("Requests sensitive credentials (password, SSN, bank info)")

        cap_ratio = float(f.get("capitalization_ratio", 0))
        if cap_ratio > 0.3:
            score += EMAIL_FEATURE_WEIGHTS["capitalization_ratio"]
            reasons.append(f"Excessive capitalization ({cap_ratio*100:.0f}% uppercase)")

        if f.get("has_html_form"):
            score += EMAIL_FEATURE_WEIGHTS["has_html_form"]
            reasons.append("Email contains HTML login forms (credential harvesting)")

        # Structural
        if f.get("has_dangerous_attachment"):
            score += EMAIL_FEATURE_WEIGHTS["has_dangerous_attachment"]
            reasons.append("Mentions dangerous file attachments (.exe, .zip)")

        spelling = int(f.get("spelling_error_score", 0))
        if spelling > 0:
            score += EMAIL_FEATURE_WEIGHTS["spelling_error_score"] * spelling
            reasons.append(f"Contains suspicious misspellings ({spelling} found)")

        urgent_kw_count = int(f.get("urgent_keyword_count", 0))
        if urgent_kw_count > 1:
            score += EMAIL_FEATURE_WEIGHTS["urgent_keyword_count"] * min(urgent_kw_count, 5)

        url_score = float(f.get("url_phishing_score", 0))
        if url_score > 0.3:
            score += EMAIL_FEATURE_WEIGHTS["url_phishing_score"] * url_score
            reasons.append(f"Links scored as phishing by URL model ({url_score*100:.0f}%)")

        confidence = min(score, 1.0)
        return {
            "confidence": confidence,
            "reasons": reasons[:8],
        }

    def _ml_predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """XGBoost model prediction."""
        from features.email_extractor import email_feature_names
        try:
            vector = np.array(
                [[float(features.get(k, 0)) for k in email_feature_names()]],
                dtype=np.float32
            )
            vector = np.nan_to_num(vector, nan=0.0)
            proba = self.ml_model.predict_proba(vector)[0][1]  # P(phishing)
            return {
                "confidence": round(float(proba), 4),
            }
        except Exception as e:
            logger.warning(f"Email ML predict failed: {e}")
            return {"confidence": 0.0}

    def _try_load_model(self):
        """Load email_model.pkl if available."""
        model_path = os.path.join(os.path.dirname(__file__), "email_model.pkl")
        if os.path.exists(model_path):
            try:
                with open(model_path, "rb") as f:
                    data = pickle.load(f)

                if isinstance(data, dict) and "model" in data:
                    self.ml_model = data["model"]
                    self.model_meta = data
                    model_type = data.get("model_type", "unknown")
                    acc = data.get("accuracy", "?")
                    logger.info(
                        f"Loaded email model: {model_type} "
                        f"(accuracy: {acc}, trained: {data.get('trained_at', '?')})"
                    )
                else:
                    self.ml_model = data
                    logger.info("Loaded email ML model from email_model.pkl")
            except Exception as e:
                logger.warning(f"Could not load email_model.pkl: {e}")
        else:
            logger.info("No email_model.pkl found — using heuristic-only mode")

    def get_model_info(self) -> Dict[str, Any]:
        """Return model metadata for health endpoint."""
        if self.ml_model is not None:
            return {
                "type": self.model_meta.get("model_type", "xgboost"),
                "accuracy": self.model_meta.get("accuracy"),
                "f1": self.model_meta.get("f1"),
                "precision": self.model_meta.get("precision"),
                "recall": self.model_meta.get("recall"),
                "features": self.model_meta.get("n_features", 32),
                "trained_at": self.model_meta.get("trained_at"),
            }
        return {"type": "heuristic", "features": 32}

    @staticmethod
    def _result(is_phishing: bool, confidence: float, reasons: List[str]) -> Dict[str, Any]:
        risk_score = int(round(confidence * 100))
        if risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        else:
            risk_level = "safe" if risk_score < 15 else "low"
        return {
            "is_phishing": is_phishing,
            "confidence": round(confidence, 4),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reasons": reasons,
        }


# Singleton detector instance
email_detector = EmailPhishingDetector()
