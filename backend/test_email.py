"""
PhishGuard — Email Detection Test Suite (v2.0)
Tests the enhanced /check_email endpoint with calibrated risk scoring.

Usage:
    1. Start backend: python app.py
    2. Run tests:     python test_email.py
"""
import sys
import io
import requests
import json

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

BASE = "http://localhost:5000/check_email"

tests = [
    {
        "name": "PHISHING — PayPal Scam",
        "expected": "phishing",
        "data": {
            "sender": "security@paypal-verification.xyz",
            "subject": "Urgent: Your account has been suspended",
            "email_text": (
                "Dear Customer,\n\n"
                "We have detected unauthorized access to your PayPal account. "
                "Your account has been temporarily suspended.\n\n"
                "Click here to verify your identity immediately: "
                "http://paypal-secure-login.tk/verify\n\n"
                "Failure to verify within 24 hours will result in permanent closure.\n\n"
                "Download the attached form: verify_form.exe\n\n"
                "PayPal Security Team"
            ),
        },
    },
    {
        "name": "PHISHING — Lottery Prize Scam",
        "expected": "phishing",
        "data": {
            "sender": "winner@lottery-prize.buzz",
            "subject": "CONGRATULATIONS! You Won $1,000,000!!!",
            "email_text": (
                "CONGRATULATIONS!!!\n\n"
                "Dear Sir/Madam,\n\n"
                "You have been selected as the WINNER of the International Lottery! "
                "You have won ONE MILLION DOLLARS!\n\n"
                "Claim your prize NOW: http://bit.ly/claim-prize-now\n\n"
                "Provide your Bank Account and SSN to claim.\n\n"
                "This is LIMITED TIME. Act NOW or lose your prize forever!"
            ),
        },
    },
    {
        "name": "PHISHING — Fake Microsoft Alert",
        "expected": "phishing",
        "data": {
            "sender": "admin@microsoft-security.top",
            "subject": "Security Alert: Unusual sign-in activity",
            "email_text": (
                "Dear Account Holder,\n\n"
                "We detected unusual activity on your Microsoft account. "
                "Someone tried to sign in from an unknown location.\n\n"
                "Verify your identity: http://micros0ft-verify.work/auth\n\n"
                "If this was not you, click the link immediately.\n\n"
                "Microsoft Security"
            ),
        },
    },
    {
        "name": "SAFE — GitHub Notification",
        "expected": "safe",
        "data": {
            "sender": "noreply@github.com",
            "subject": "New login to your GitHub account",
            "email_text": (
                "Hi John,\n\n"
                "We noticed a new sign-in to your GitHub account.\n\n"
                "Device: Chrome on Windows 11\n"
                "Location: San Francisco, CA\n\n"
                "If this was you, no action is needed.\n\n"
                "Review settings: https://github.com/settings/security\n\n"
                "Thanks,\nThe GitHub Team"
            ),
        },
    },
    {
        "name": "SAFE — Slack Weekly Digest",
        "expected": "safe",
        "data": {
            "sender": "notifications@slack.com",
            "subject": "Weekly digest from Engineering workspace",
            "email_text": (
                "Hi Sarah,\n\n"
                "Here's what happened in your Slack workspace this week:\n\n"
                "#general - 45 new messages\n"
                "#engineering - 23 new messages\n\n"
                "Open Slack: https://app.slack.com/\n\n"
                "Slack Notifications"
            ),
        },
    },
    {
        "name": "PHISHING — Credential Harvesting Form",
        "expected": "phishing",
        "data": {
            "sender": "billing@disney-plus.work",
            "subject": "Disney+ Payment Issue: Update Required",
            "email_text": (
                "Dear Subscriber,\n\n"
                "We couldn't process your Disney+ subscription payment.\n\n"
                "<form action='http://disneyplus-billing.work/pay'>"
                "<input type='text' placeholder='Card Number'>"
                "<input type='password' placeholder='CVV'></form>\n\n"
                "Action required within 24 hours.\n\n"
                "Disney+ Billing"
            ),
        },
    },
    {
        "name": "SAFE — Netflix Receipt",
        "expected": "safe",
        "data": {
            "sender": "billing@netflix.com",
            "subject": "Your Netflix receipt",
            "email_text": (
                "Hi David,\n\n"
                "Thank you for your payment.\n\n"
                "Plan: Standard\n"
                "Amount: $15.49\n"
                "Next billing date: May 21, 2026\n\n"
                "Manage your subscription: https://www.netflix.com/YourAccount\n\n"
                "Netflix"
            ),
        },
    },
]

print("\n" + "=" * 65)
print("  PhishGuard — Email Detection Test Suite v2.0")
print("  XGBoost + 32 Features + Calibrated Risk Scoring")
print("=" * 65)

passed = 0
correct = 0
total = len(tests)

for t in tests:
    try:
        r = requests.post(
            BASE, 
            json=t["data"], 
            headers={"x-api-key": "PG-API-KEY-2026"},
            timeout=15
        )
        result = r.json()

        risk_score = result.get("risk_score", 0)
        result_label = result.get("result", "unknown")
        confidence = round(result.get("confidence", 0) * 100)
        risk_level = result.get("risk_level", "?")

        # Determine icon
        if result_label == "phishing":
            emoji = "🔴"
        elif result_label == "suspicious":
            emoji = "⚠️ "
        else:
            emoji = "🟢"

        # Check if correct
        is_correct = result_label == t["expected"]
        # Also accept "suspicious" for expected phishing (conservative is OK)
        if t["expected"] == "phishing" and result_label == "suspicious":
            is_correct = True  # acceptable
        if is_correct:
            correct += 1

        check = "✅" if is_correct else "❌"

        print(f"\n{emoji}  {t['name']}  {check}")
        print(f"   Result:     {result_label.upper()}")
        print(f"   Risk Score: {risk_score}%")
        print(f"   Risk Level: {risk_level}")
        print(f"   Confidence: {confidence}%")

        # Show auth details
        details = result.get("details", {})
        auth = details.get("sender_analysis", {})
        if auth:
            spf = auth.get("spf", "?").upper()
            dkim = auth.get("dkim", "?").upper()
            dmarc = auth.get("dmarc", "?").upper()
            print(f"   Auth:       SPF={spf} | DKIM={dkim} | DMARC={dmarc}")

        # Show rule triggers
        triggers = details.get("rule_triggers", [])
        if triggers:
            print(f"   Rules:      {', '.join(triggers)}")

        # Show reasons
        reasons = result.get("reasons", [])
        if reasons:
            print(f"   Reasons:")
            for reason in reasons[:4]:
                print(f"     • {reason}")

        # Show link analysis
        links = details.get("links_analyzed", result.get("links_analyzed", 0))
        flagged = details.get("links_flagged", 0)
        if links:
            print(f"   Links:      {links} analyzed, {flagged} flagged")

        passed += 1
    except Exception as e:
        print(f"\n❌  {t['name']} — FAILED: {e}")

print(f"\n{'=' * 65}")
print(f"  Results: {passed}/{total} tests completed, {correct}/{total} correct")
print(f"{'=' * 65}\n")
