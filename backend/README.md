# PhishGuard Backend

AI-powered phishing URL detection API.

## Deploy to Render.com

1. Fork/clone this repo
2. Create a new **Web Service** on Render
3. Set build command: `pip install -r requirements.txt`
4. Set start command: `gunicorn app:app`
5. Deploy

## API Endpoint

```
POST /check_url
Body: { "url": "https://example.com" }
Response: { "result": "safe" | "phishing", "confidence": 0.95 }
```
