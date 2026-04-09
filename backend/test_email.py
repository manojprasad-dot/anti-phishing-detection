"""Quick test for /check_email endpoint."""
import requests, json

BASE = "http://localhost:5000/check_email"

tests = [
    {
        "name": "PHISHING — PayPal Scam",
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
]

print("\n" + "=" * 60)
print("  PhishGuard — Email Detection Test Suite")
print("=" * 60)

passed = 0
for t in tests:
    try:
        r = requests.post(BASE, json=t["data"], timeout=15)
        result = r.json()
        emoji = "🔴" if result["result"] == "phishing" else "🟢"
        conf = round(result["confidence"] * 100)

        print(f"\n{emoji}  {t['name']}")
        print(f"   Result:     {result['result'].upper()}")
        print(f"   Confidence: {conf}%")
        print(f"   Risk Level: {result['risk_level']}")
        if result.get("reasons"):
            print(f"   Reasons:")
            for r in result["reasons"][:3]:
                print(f"     • {r}")
        if result.get("links_analyzed"):
            print(f"   Links:      {result['links_analyzed']} analyzed (avg score: {round((result.get('avg_link_score') or 0)*100)}%)")
        passed += 1
    except Exception as e:
        print(f"\n❌  {t['name']} — FAILED: {e}")

print(f"\n{'=' * 60}")
print(f"  Results: {passed}/{len(tests)} tests passed")
print(f"{'=' * 60}\n")
