"""Verify that HTML stripping fixes the false positive issue."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from features.email_extractor import extract_email_features
from ml.email_detector import email_detector

def test(label, body, sender, subject):
    features = extract_email_features(body, sender, subject)
    result = email_detector.predict(features)
    status = "PHISHING" if result["is_phishing"] else "SAFE"
    print(f"  {label:50s} -> {status:8s} ({result['confidence']*100:.0f}%)")
    if result.get("reasons"):
        for r in result["reasons"][:3]:
            print(f"    - {r}")
    return result

print("=" * 70)
print("  Testing HTML stripping fix")
print("=" * 70)

# Test 1: Plain text safe email
print("\n[1] Plain text emails:")
test("GitHub notification (plain text)",
     "Hi John, We noticed a new login to your GitHub account from Chrome. If this was you, no action needed. Thanks, GitHub Team",
     "noreply@github.com", "New login to your account")

# Test 2: HTML-wrapped safe email (simulating Gmail's DOM output)
print("\n[2] HTML-wrapped emails (Gmail scenario):")
gmail_html = '''<div class="a3s aiL"><div dir="ltr"><div style="display:none;font-size:0;height:0;overflow:hidden">Preview text</div><table width="100%"><tr><td><div style="font-family:Arial,sans-serif;font-size:14px"><p>Hi John,</p><p>We noticed a new login to your GitHub account from Chrome on Windows.</p><p>If this was you, you can ignore this email.</p><p>Thanks,<br>The GitHub Team</p></div></td></tr></table><img src="https://github.com/notifications/beacon/abc123.gif" width="1" height="1" alt=""></div></div>'''

test("GitHub notification (HTML wrapped)",
     gmail_html,
     "noreply@github.com", "New login to your account")

# Test 3: HTML-wrapped phishing should still be caught
phishing_html = '''<div><p>Dear Customer,</p><p>Your account has been <b>SUSPENDED</b>. Unauthorized access detected!</p><p>Click here to verify: <a href="http://paypal-secure.tk/verify">https://www.paypal.com/verify</a></p><p>Failure to verify within 24 hours will result in permanent account closure.</p></div>'''

test("PayPal phishing (HTML wrapped)",
     phishing_html,
     "security@paypal-verify.xyz", "URGENT: Account suspended")

# Test 4: Safe Amazon order (plain text)
test("Amazon order (plain text)",
     "Hi David, Your Amazon order #112-3456 has shipped! Track it at https://www.amazon.com/gp/your-orders. Estimated delivery: March 15.",
     "orders@amazon.com", "Your order has shipped")

# Test 5: Safe Slack digest
test("Slack digest (plain text)",
     "Hi Sarah, Here is your Slack workspace summary: 45 messages in general, 12 in engineering. View at https://app.slack.com",
     "team@slack.com", "Your weekly Slack digest")

print("\n" + "=" * 70)
print("  Expected: Tests 1,2,4,5 = SAFE | Test 3 = PHISHING")
print("=" * 70)
