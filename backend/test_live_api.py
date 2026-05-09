import urllib.request, json

url = "https://phishguard-api-6dmc.onrender.com/check_email"
safe = {
    "email_text": "Hi John, We noticed a new login to your GitHub account. If this was you, no action needed. Thanks, GitHub Team",
    "sender": "noreply@github.com",
    "subject": "New login to your account"
}
phish = {
    "email_text": "Dear Customer, Your account has been suspended. Click here to verify: http://paypal-secure.tk/verify. Failure to verify within 24 hours will result in closure. PayPal Security",
    "sender": "security@paypal-verify.xyz",
    "subject": "Urgent: Account suspended"
}

for label, data in [("SAFE", safe), ("PHISHING", phish)]:
    req = urllib.request.Request(url, json.dumps(data).encode(), {"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read())
        print(f"{label}: result={result.get('result')} confidence={result.get('confidence')} risk={result.get('risk_level')}")
        if result.get("reasons"):
            for r in result["reasons"][:3]:
                print(f"  - {r}")
    except Exception as e:
        print(f"{label}: ERROR - {e}")
