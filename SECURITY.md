# Security Policy

## Supported Versions

Currently, only the latest version of PhishGuard (v2.0+) is supported with security updates. 

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Security Architecture ("Bank-Grade" Protection)

As of version 2.0, PhishGuard implements strong security mechanisms to protect both users and the backend API from abuse:

1. **API Key Authentication**: 
   The PhishGuard backend API (`/check_url` and `/check_email`) is restricted. All requests require a valid `X-API-Key` injected securely by the authorized Chrome extension. 
2. **Rate Limiting**: 
   The API is protected by `Flask-Limiter` to enforce strict rate limits (60 requests per minute) per IP, preventing DDOS and automated spam.
3. **Strict Content Security Policies (CSP)**:
   - **Extension**: `manifest.json` imposes a strict CSP that disallows inline scripts (`unsafe-eval`) and only permits API connections to the official backend server.
   - **Website**: `index.html` is locked down with a CSP meta tag preventing XSS, clickjacking, and unauthorized resource loading.
4. **Talisman Security Headers**: 
   The Flask API utilizes `Flask-Talisman` to enforce HTTPS everywhere, HSTS, X-Content-Type-Options, X-Frame-Options, and X-XSS-Protection.

## Reporting a Vulnerability

If you discover a security vulnerability in PhishGuard, please do **NOT** open a public issue. Protect our users by reporting vulnerabilities privately.

1. Email your findings to: `security@phishguard.example.com` (replace with actual security contact).
2. Include a detailed description of the vulnerability and steps to reproduce it.

We aim to acknowledge receipt of vulnerability reports within 48 hours and provide regular updates until a fix is deployed.

## User Privacy
PhishGuard processes URLs and Emails in real time but operates with a strict **Privacy-First** approach:
- We do not store personally identifiable information (PII).
- Backend logs are ephemeral and do not persist email bodies permanently.
