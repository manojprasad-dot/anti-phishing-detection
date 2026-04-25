import os
import re
import json
import logging
from datetime import datetime
from functools import wraps
from flask import request, jsonify, abort

# Configure absolute path for the threat log file
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security.log")

# Setup custom logger for Intrusion Detection
attack_logger = logging.getLogger("phishguard_ids")
attack_logger.setLevel(logging.WARNING)

# File handler
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.WARNING)
attack_logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)
attack_logger.addHandler(console_handler)

def log_attack(reason, details=""):
    """
    Format and log an intrusion attempt (Invalid API, Origin, Rate Limit, etc).
    """
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # Handle comma-separated lists for Proxies/Render
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()
        
    log_entry = {
        "event": "blocked_request",
        "ip": client_ip,
        "origin": request.headers.get("Origin", "unknown"),
        "endpoint": request.path,
        "reason": reason,
        "details": details,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    # Log the JSON string
    attack_logger.warning(json.dumps(log_entry))

def secure_endpoint(f):
    """
    Decorator to enforce strictly validated API requests.
    Validates:
      1. X-API-Key existence and exact match.
      2. Origin header against the environment whitelist.
      3. Strict JSON structure logic (must parse cleanly).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. API Key Validation
        expected_key = os.environ.get("PG_API_KEY", "PG-API-KEY-2026")
        client_key = request.headers.get("X-API-Key")
        
        if not client_key or client_key != expected_key:
            safe_key = client_key[:5] if client_key else "None"
            log_attack("invalid_api_key", f"Key provided: {safe_key}... (truncated)")
            return jsonify({"error": "Unauthorized: Invalid or missing API Key"}), 401
            
        # 2. Origin Header Validation
        mode = os.environ.get("MODE", "development")
        origin = request.headers.get("Origin")
        
        # We enforce origin strictly. Requests from non-browser clients (like curl) often omit origin.
        # But this is a browser extension API, origin MUST be present in production.
        if mode == "production":
            ext_id = os.environ.get("EXTENSION_ID", "")
            netlify = os.environ.get("NETLIFY_SITE", "")
            
            allowed_origins = []
            if ext_id and ext_id != "your_extension_id_here":
                allowed_origins.append(f"chrome-extension://{ext_id}")
            if netlify and netlify != "your_netlify_site_here":
                allowed_origins.append(netlify)
                
            if not origin or origin not in allowed_origins:
                log_attack("invalid_origin", f"Production origin rejected: {origin}")
                return jsonify({"error": "Forbidden: Untrusted Origin"}), 403
                
        else: # Development Mode
            # Allow localhost, any netlify, any chrome-extension
            if origin:
                is_safe = (
                    re.match(r'^https?://localhost:\d+$', origin) or 
                    re.match(r'^https://[a-zA-Z0-9-]+\.netlify\.app$', origin) or 
                    origin.startswith("chrome-extension://") or
                    origin == "null" # Some local HTML file testing
                )
                if not is_safe:
                    log_attack("invalid_origin", f"Development origin rejected: {origin}")
                    return jsonify({"error": "Forbidden: Untrusted Origin"}), 403

        # 3. Request Payload Integrity Validation
        if request.method in ["POST", "PUT", "PATCH"]:
            if not request.is_json:
                log_attack("bad_request", "Missing or malformed JSON payload")
                return jsonify({"error": "Bad Request: JSON expected"}), 400
            
            # Flask handles the actual silent parsing error if invalid JSON, 
            # we just ensure it parses without hard exceptions here
            try:
                data = request.get_json()
                if data is None:
                    raise ValueError("Empty data")
            except Exception as e:
                log_attack("malformed_payload", str(e))
                return jsonify({"error": "Bad Request: Invalid JSON payload"}), 400

        return f(*args, **kwargs)
        
    return decorated_function
