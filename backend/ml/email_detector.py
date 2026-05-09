"""
PhishGuard -- ml/email_detector.py
MODULE 6: Email Phishing Detection — ML Detector

Ensemble detector for email phishing:
  - ML model (RandomForest) — 75% weight
  - Heuristic rule engine — 25% weight

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
    # --- Original rules (retuned) ---
    "has_urgent_language":      0.30,
    "urgent_keyword_count":     0.06,   # per keyword
    "has_threat_language":      0.30,
    "has_reward_language":      0.25,
    "has_suspicious_links":     0.40,
    "suspicious_link_ratio":    0.22,
    "has_html_form":            0.30,
    "has_mismatched_url":       0.45,
    "sender_domain_mismatch":   0.38,
    "sender_is_freemail":       0.12,
    "has_spoofed_sender":       0.50,
    "sender_suspicious_tld":    0.35,
    "has_generic_greeting":     0.15,
    "capitalization_ratio":     0.12,   # applied if > 0.3
    "has_dangerous_attachment":  0.30,
    "spelling_error_score":     0.10,   # per error
    "url_phishing_score":       0.45,
    # --- NEW rules ---
    "has_base64_content":       0.20,
    "has_javascript":           0.50,
    "high_link_to_text_ratio":  0.25,
    "has_hidden_text":          0.40,
    "reply_to_mismatch":        0.35,
    "has_tracking_pixel":       0.10,
    "urgency_in_subject":       0.15,   # per keyword in subject
    "high_body_entropy":        0.10,
}

EMAIL_PHISHING_THRESHOLD = 0.50


class EmailPhishingDetector:
    """
    Ensemble email phishing detector.
    ML model (75%) + Heuristic rules (25%).
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

            # Weighted ensemble: 75% ML + 25% Heuristic
            combined = (ml_conf * 0.75) + (h_conf * 0.25)

            # If either engine is very confident, boost
            if h_conf >= 0.75 or ml_conf >= 0.85:
                combined = max(combined, max(h_conf, ml_conf))

            # If BOTH agree it's phishing, boost further
            if h_conf >= 0.5 and ml_conf >= 0.5:
                combined = max(combined, (h_conf + ml_conf) / 2 + 0.05)

            combined = min(combined, 1.0)
            is_phishing = combined >= EMAIL_PHISHING_THRESHOLD
            return self._result(is_phishing, round(combined, 4), reasons)

        # Fallback: heuristic only
        return heuristic_result

    def _heuristic_predict(self, f: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based email phishing detection."""
        score = 0.0
        reasons: List[str] = []
        flags_triggered = 0

        if f.get("has_urgent_language"):
            score += EMAIL_FEATURE_WEIGHTS["has_urgent_language"]
            reasons.append("Contains urgent/pressure language")
            flags_triggered += 1

        urgent_count = int(f.get("urgent_keyword_count", 0))
        if urgent_count > 1:
            score += EMAIL_FEATURE_WEIGHTS["urgent_keyword_count"] * min(urgent_count, 5)
            reasons.append(f"Multiple urgency keywords ({urgent_count} found)")
            flags_triggered += 1

        if f.get("has_threat_language"):
            score += EMAIL_FEATURE_WEIGHTS["has_threat_language"]
            reasons.append("Contains threatening language (account suspension, etc.)")
            flags_triggered += 1

        if f.get("has_reward_language"):
            score += EMAIL_FEATURE_WEIGHTS["has_reward_language"]
            reasons.append("Contains reward/prize language (common in scams)")
            flags_triggered += 1

        if f.get("has_suspicious_links"):
            score += EMAIL_FEATURE_WEIGHTS["has_suspicious_links"]
            reasons.append("Contains suspicious links (shortened URLs, IP addresses)")
            flags_triggered += 1

        susp_ratio = float(f.get("suspicious_link_ratio", 0))
        if susp_ratio > 0.5:
            score += EMAIL_FEATURE_WEIGHTS["suspicious_link_ratio"]
            reasons.append(f"High ratio of suspicious links ({susp_ratio*100:.0f}%)")
            flags_triggered += 1

        if f.get("has_html_form"):
            score += EMAIL_FEATURE_WEIGHTS["has_html_form"]
            reasons.append("Email contains HTML login forms (credential harvesting)")
            flags_triggered += 1

        if f.get("has_mismatched_url"):
            score += EMAIL_FEATURE_WEIGHTS["has_mismatched_url"]
            reasons.append("Link text doesn't match actual URL (deceptive link)")
            flags_triggered += 1

        if f.get("sender_domain_mismatch"):
            score += EMAIL_FEATURE_WEIGHTS["sender_domain_mismatch"]
            reasons.append("Sender domain doesn't match brand mentioned in email")
            flags_triggered += 1

        if f.get("sender_is_freemail"):
            score += EMAIL_FEATURE_WEIGHTS["sender_is_freemail"]
            reasons.append("Sent from a free email service (unusual for official emails)")
            flags_triggered += 1

        if f.get("has_spoofed_sender"):
            score += EMAIL_FEATURE_WEIGHTS["has_spoofed_sender"]
            reasons.append("Sender name contains brand but domain is different (spoofed)")
            flags_triggered += 1

        if f.get("sender_suspicious_tld"):
            score += EMAIL_FEATURE_WEIGHTS["sender_suspicious_tld"]
            reasons.append("Sender uses a high-risk domain (.xyz, .tk, etc.)")
            flags_triggered += 1

        if f.get("has_generic_greeting"):
            score += EMAIL_FEATURE_WEIGHTS["has_generic_greeting"]
            reasons.append("Uses generic greeting instead of your name")
            flags_triggered += 1

        cap_ratio = float(f.get("capitalization_ratio", 0))
        if cap_ratio > 0.3:
            score += EMAIL_FEATURE_WEIGHTS["capitalization_ratio"]
            reasons.append(f"Excessive capitalization ({cap_ratio*100:.0f}% uppercase)")
            flags_triggered += 1

        if f.get("has_dangerous_attachment"):
            score += EMAIL_FEATURE_WEIGHTS["has_dangerous_attachment"]
            reasons.append("Mentions dangerous file attachments (.exe, .zip, etc.)")
            flags_triggered += 1

        spelling = int(f.get("spelling_error_score", 0))
        if spelling > 0:
            score += EMAIL_FEATURE_WEIGHTS["spelling_error_score"] * spelling
            reasons.append(f"Contains suspicious misspellings ({spelling} found)")
            flags_triggered += 1

        url_score = float(f.get("url_phishing_score", 0))
        if url_score > 0.3:
            score += EMAIL_FEATURE_WEIGHTS["url_phishing_score"] * url_score
            reasons.append(f"Links scored as phishing by URL model ({url_score*100:.0f}%)")
            flags_triggered += 1

        # ── NEW heuristic rules ───────────────────────────────────────────

        if f.get("has_base64_content"):
            score += EMAIL_FEATURE_WEIGHTS["has_base64_content"]
            reasons.append("Contains base64 encoded content (possible obfuscation)")
            flags_triggered += 1

        if f.get("has_javascript"):
            score += EMAIL_FEATURE_WEIGHTS["has_javascript"]
            reasons.append("Contains JavaScript code (script injection attempt)")
            flags_triggered += 1

        link_text_ratio = float(f.get("link_to_text_ratio", 0))
        if link_text_ratio > 0.1:
            score += EMAIL_FEATURE_WEIGHTS["high_link_to_text_ratio"]
            reasons.append("Unusually high link-to-text ratio")
            flags_triggered += 1

        if f.get("has_hidden_text"):
            score += EMAIL_FEATURE_WEIGHTS["has_hidden_text"]
            reasons.append("Contains hidden text using CSS tricks")
            flags_triggered += 1

        if f.get("reply_to_mismatch"):
            score += EMAIL_FEATURE_WEIGHTS["reply_to_mismatch"]
            reasons.append("Reply-to address differs from sender (potential spoofing)")
            flags_triggered += 1

        if f.get("has_tracking_pixel"):
            score += EMAIL_FEATURE_WEIGHTS["has_tracking_pixel"]
            reasons.append("Contains tracking pixel (1x1 image)")
            flags_triggered += 1

        subj_urgency = int(f.get("urgency_in_subject", 0))
        if subj_urgency > 0:
            score += EMAIL_FEATURE_WEIGHTS["urgency_in_subject"] * min(subj_urgency, 3)
            reasons.append(f"Subject line contains {subj_urgency} urgency indicator(s)")
            flags_triggered += 1

        body_entropy = float(f.get("body_entropy", 0))
        if body_entropy > 5.0:
            score += EMAIL_FEATURE_WEIGHTS["high_body_entropy"]
            reasons.append("Unusually high entropy in email body (obfuscated content)")
            flags_triggered += 1

        # ── Combo boosting: multiple flags = exponentially more suspicious ──
        if flags_triggered >= 6:
            combo_boost = 0.20
            score += combo_boost
            reasons.append(f"Multi-signal alert: {flags_triggered} suspicious indicators")
        elif flags_triggered >= 4:
            combo_boost = 0.12
            score += combo_boost
        elif flags_triggered >= 3:
            combo_boost = 0.05
            score += combo_boost

        # ── Contextual combo: specific dangerous combinations ──
        # Freemail + Urgent + Generic Greeting = very likely phishing
        if (f.get("sender_is_freemail") and f.get("has_urgent_language")
                and f.get("has_generic_greeting")):
            score += 0.15
            if "Contextual combo: freemail + urgency + generic greeting" not in reasons:
                reasons.append("Contextual combo: freemail + urgency + generic greeting")

        # Spoofed sender + Suspicious links = very likely phishing
        if f.get("has_spoofed_sender") and f.get("has_suspicious_links"):
            score += 0.12

        # Mismatched URL + Threat language = credential phishing
        if f.get("has_mismatched_url") and f.get("has_threat_language"):
            score += 0.10

        confidence = min(score, 1.0)
        return self._result(
            confidence >= EMAIL_PHISHING_THRESHOLD,
            confidence,
            reasons[:7]
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

            # Handle feature count mismatch (old model with 20 features vs new 28)
            expected = self.ml_model.n_features_in_
            if vector.shape[1] > expected:
                vector = vector[:, :expected]
            elif vector.shape[1] < expected:
                padding = np.zeros((1, expected - vector.shape[1]), dtype=np.float32)
                vector = np.concatenate([vector, padding], axis=1)

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
                "features": self.model_meta.get("n_features", 28),
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
