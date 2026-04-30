# PhishGuard: Detection Thresholds & Rule Engine Logic

This document details the logic used to determine whether a URL or Email is flagged as phishing. It explains the core threshold (0.50), how it was determined, and the ruleset governing the heuristic engine.

## 1. Determining the Threshold (0.50)
The detection system uses a probability-based threshold of **0.50**. This means if the combined confidence score from our ML and Heuristic models is ≥ 50%, the item is flagged as phishing.

### Why 0.50?
The threshold is the "Point of Equilibrium" between sensitivity and accuracy.
- **Precise Calculation:** We utilize a weighted ensemble: `(ML Score * 0.7) + (Heuristic Score * 0.3)`.
- **Confidence Boost:** If either engine reaches a confidence of ≥ 0.8, the system automatically "boosts" the final score to that higher value, ensuring high-confidence threats aren't diluted by the average.
- **Goal:** To minimize "False Positives" (blocking safe sites) while maintaining a "High Recall" for actual phishing attacks.

---

## 2. Threshold Impact: Right vs. Wrong (Decision Matrix)

The following table explains the implications of the 0.50 threshold in real-world scenarios.

| Outcome | Technical Term | What Happened | Impact |
| :--- | :--- | :--- | :--- |
| **Right (Positive)** | True Positive | Score ≥ 0.50; Item is actually phishing. | **Success:** User is protected, attack blocked. |
| **Right (Negative)** | True Negative | Score < 0.50; Item is legitimate. | **Success:** User navigates freely, no interruption. |
| **Wrong (Type I)** | False Positive | Score ≥ 0.50; Item is actually **safe**. | **Bad UX:** User is annoyed by a false warning. |
| **Wrong (Type II)** | False Negative | Score < 0.50; Item is actually **phishing**. | **Critical Failure:** User is exposed to the threat. |

> **Strategy:** We maintain a 0.50 threshold to balance these risks. If we moved it to 0.90, we would have fewer False Positives but many more False Negatives (dangerous). If we moved it to 0.10, everything would be flagged (useless).

---

## 3. The Ruleset (Heuristic Weights)

The heuristic engine acts as the "human-like" logic layer. Each rule adds a weight to the confidence score.

### URL Detection Ruleset
| Feature | Weight | Description |
| :--- | :--- | :--- |
| **IP Address Usage** | 0.65 | Using numbers instead of names (e.g., `192.168.1.1`) is a high-risk indicator. |
| **Brand Spoofing** | 0.55 | Adding hyphens to brands (e.g., `secure-paypal-login.com`). |
| **Suspicious TLD** | 0.35 | Use of `.xyz`, `.tk`, `.ml`, or `.top` domains. |
| **Obfuscation (@)** | 0.35 | Using the `@` symbol to hide the real destination domain. |
| **No HTTPS** | 0.15 | Serving a login page over an unencrypted connection. |

### Email Detection Ruleset
| Feature | Weight | Description |
| :--- | :--- | :--- |
| **Spoofed Sender** | 0.45 | Name says "Bank" but email is `random@gmail.com`. |
| **Mismatched URL** | 0.40 | Link text says "Click Here" but points to a different site. |
| **Urgent Language** | 0.30 | Phrases like "Immediate action required" or "Account suspended". |
| **Threat Language** | 0.30 | Mentioning legal action or financial loss. |
| **Generic Greeting** | 0.15 | "Dear Customer" instead of your actual name. |

---

## 4. Final Decision Rules
1. **Low Risk (< 0.40):** Green status. Content is likely safe.
2. **Medium Risk (0.40 - 0.69):** Yellow status. Caution advised; some suspicious elements found.
3. **High Risk (≥ 0.70):** Red status. Blocked. Strong indicators of phishing detected.
4. **Legitimate Override:** If a domain is on our "Safe List," the score is force-set to **0.01**, bypassing all ML logic.
