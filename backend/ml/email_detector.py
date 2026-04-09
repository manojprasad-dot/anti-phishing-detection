"""
PhishGuard -- ml/email_detector.py
MODULE 6: Email Phishing Detection — ML Detector

Ensemble detector for email phishing:
  - ML model (RandomForest) — 70% weight
  - Heuristic rule engine — 30% weight

Same architecture as the URL detector (ml/detector.py).
"""

import os
import pickle
import logging
import numpy as np
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# -- Feature weights for email heuristic engine --------------------------------
EMAIL_FEATURE_WEIGHTS = {
    "has_urgent_language":      0.30,
    "urgent_keyword_count":     0.05,   # per keyword
    "has_threat_language":      0.30,
    "has_reward_language":      0.25,
    "has_suspicious_links":     0.35,
    "suspicious_link_ratio":    0.20,
    "has_html_form":            0.25,
    "has_mismatched_url":       0.40,
    "sender_domain_mismatch":   0.35,
    "sender_is_freemail":       0.10,
    "has_spoofed_sender":       0.45,
    "sender_suspicious_tld":    0.30,
    "has_generic_greeting":     0.15,
    "capitalization_ratio":     0.10,   # applied if > 0.3
    "has_dangerous_attachment":  0.25,
    "spelling_error_score":     0.08,   # per error
    "url_phishing_score":       0.40,
}

EMAIL_PHISHING_THRESHOLD = 0.50


class EmailPhishingDetector:
    """
    Ensemble email phishing detector.
    ML model (70%) + Heuristic rules (30%).
    """

    def __init__(self):
        self.ml_model = None
        self.model_meta = {}
        self._try_load_model()

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensemble detection for email content.
        Returns: { is_phishing, confidence, risk_level, reasons }
        """
        # Get heuristic result (always available)
        heuristic_result = self._heuristic_predict(features)
        h_conf = heuristic_result["confidence"]
        reasons = heuristic_result["reasons"]

        # If ML model is loaded, combine both scores
        if self.ml_model is not None:
            ml_result = self._ml_predict(features)
            ml_conf = ml_result["confidence"]

            # Weighted ensemble: 70% ML + 30% Heuristic
            combined = (ml_conf * 0.7) + (h_conf * 0.3)

            # If either engine is very confident, boost
            if h_conf >= 0.8 or ml_conf >= 0.8:
                combined = max(combined, max(h_conf, ml_conf))

            combined = min(combined, 1.0)
            is_phishing = combined >= EMAIL_PHISHING_THRESHOLD
            return self._result(is_phishing, round(combined, 4), reasons)

        # Fallback: heuristic only
        return heuristic_result

    def _heuristic_predict(self, f: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based email phishing detection."""
        score = 0.0
        reasons: List[str] = []

        if f.get("has_urgent_language"):
            score += EMAIL_FEATURE_WEIGHTS["has_urgent_language"]
            reasons.append("Contains urgent/pressure language")

        urgent_count = int(f.get("urgent_keyword_count", 0))
        if urgent_count > 1:
            score += EMAIL_FEATURE_WEIGHTS["urgent_keyword_count"] * min(urgent_count, 5)
            reasons.append(f"Multiple urgency keywords ({urgent_count} found)")

        if f.get("has_threat_language"):
            score += EMAIL_FEATURE_WEIGHTS["has_threat_language"]
            reasons.append("Contains threatening language (account suspension, etc.)")

        if f.get("has_reward_language"):
            score += EMAIL_FEATURE_WEIGHTS["has_reward_language"]
            reasons.append("Contains reward/prize language (common in scams)")

        if f.get("has_suspicious_links"):
            score += EMAIL_FEATURE_WEIGHTS["has_suspicious_links"]
            reasons.append("Contains suspicious links (shortened URLs, IP addresses)")

        susp_ratio = float(f.get("suspicious_link_ratio", 0))
        if susp_ratio > 0.5:
            score += EMAIL_FEATURE_WEIGHTS["suspicious_link_ratio"]
            reasons.append(f"High ratio of suspicious links ({susp_ratio*100:.0f}%)")

        if f.get("has_html_form"):
            score += EMAIL_FEATURE_WEIGHTS["has_html_form"]
            reasons.append("Email contains HTML login forms (credential harvesting)")

        if f.get("has_mismatched_url"):
            score += EMAIL_FEATURE_WEIGHTS["has_mismatched_url"]
            reasons.append("Link text doesn't match actual URL (deceptive link)")

        if f.get("sender_domain_mismatch"):
            score += EMAIL_FEATURE_WEIGHTS["sender_domain_mismatch"]
            reasons.append("Sender domain doesn't match brand mentioned in email")

        if f.get("sender_is_freemail"):
            score += EMAIL_FEATURE_WEIGHTS["sender_is_freemail"]
            reasons.append("Sent from a free email service (unusual for official emails)")

        if f.get("has_spoofed_sender"):
            score += EMAIL_FEATURE_WEIGHTS["has_spoofed_sender"]
            reasons.append("Sender name contains brand but domain is different (spoofed)")

        if f.get("sender_suspicious_tld"):
            score += EMAIL_FEATURE_WEIGHTS["sender_suspicious_tld"]
            reasons.append("Sender uses a high-risk domain (.xyz, .tk, etc.)")

        if f.get("has_generic_greeting"):
            score += EMAIL_FEATURE_WEIGHTS["has_generic_greeting"]
            reasons.append("Uses generic greeting instead of your name")

        cap_ratio = float(f.get("capitalization_ratio", 0))
        if cap_ratio > 0.3:
            score += EMAIL_FEATURE_WEIGHTS["capitalization_ratio"]
            reasons.append(f"Excessive capitalization ({cap_ratio*100:.0f}% uppercase)")

        if f.get("has_dangerous_attachment"):
            score += EMAIL_FEATURE_WEIGHTS["has_dangerous_attachment"]
            reasons.append("Mentions dangerous file attachments (.exe, .zip, etc.)")

        spelling = int(f.get("spelling_error_score", 0))
        if spelling > 0:
            score += EMAIL_FEATURE_WEIGHTS["spelling_error_score"] * spelling
            reasons.append(f"Contains suspicious misspellings ({spelling} found)")

        url_score = float(f.get("url_phishing_score", 0))
        if url_score > 0.3:
            score += EMAIL_FEATURE_WEIGHTS["url_phishing_score"] * url_score
            reasons.append(f"Links scored as phishing by URL model ({url_score*100:.0f}%)")

        confidence = min(score, 1.0)
        return self._result(
            confidence >= EMAIL_PHISHING_THRESHOLD,
            confidence,
            reasons[:6]
        )

    def _ml_predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """ML model prediction."""
        from features.email_extractor import email_feature_names
        try:
            vector = np.array(
                [[float(features.get(k, 0)) for k in email_feature_names()]],
                dtype=np.float32
            )
            vector = np.nan_to_num(vector, nan=0.0)
            proba = self.ml_model.predict_proba(vector)[0][1]  # P(phishing)
            return self._result(
                proba >= EMAIL_PHISHING_THRESHOLD,
                round(float(proba), 4),
                []
            )
        except Exception as e:
            logger.warning(f"Email ML predict failed: {e}")
            return self._heuristic_predict(features)

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
                    logger.info(
                        f"Loaded email model "
                        f"(accuracy: {data.get('accuracy', '?')}, "
                        f"trained: {data.get('trained_at', '?')})"
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
                "type": self.model_meta.get("model_type", "sklearn"),
                "accuracy": self.model_meta.get("accuracy"),
                "f1": self.model_meta.get("f1"),
                "features": self.model_meta.get("n_features", 20),
                "trained_at": self.model_meta.get("trained_at"),
            }
        return {"type": "heuristic"}

    @staticmethod
    def _result(is_phishing: bool, confidence: float, reasons: List[str]) -> Dict[str, Any]:
        if confidence >= 0.7:   risk = "high"
        elif confidence >= 0.4: risk = "medium"
        else:                   risk = "low"
        return {
            "is_phishing": is_phishing,
            "confidence":  round(confidence, 4),
            "risk_level":  "safe" if not is_phishing and confidence < 0.15 else risk,
            "reasons":     reasons,
        }


# Singleton detector instance
email_detector = EmailPhishingDetector()
