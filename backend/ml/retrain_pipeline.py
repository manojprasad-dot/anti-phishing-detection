"""
PhishGuard -- ml/retrain_pipeline.py
MLOps Retraining Pipeline

This script fetches real user feedback from the SQLite database, 
combines it with the base templates, and retrains the XGBoost model.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import database
from ml.train_email_xgboost import build_dataset, extract_all_features, train_model, save_model

def get_feedback_samples():
    """Fetch user feedback from DB and convert to training samples."""
    conn = database.get_db()
    cursor = conn.execute("SELECT * FROM feedback")
    rows = cursor.fetchall()
    conn.close()

    samples = []
    for row in rows:
        url = row["url"]
        verdict = row["verdict"]  # "phishing", "safe", "user_proceeded"
        
        # Simple heuristic: If it was a URL feedback, we convert it to an email body format
        # If it was an email feedback (logged as 'email: sender@domain.com' in requests, but feedback is just url)
        # We'll treat the reported string as the body/url.
        
        label = 1 if verdict in ["phishing", "user_proceeded"] else 0
        
        samples.append({
            "sender": "user-feedback@phishguard.local",
            "subject": "User Reported Content",
            "body": f"Reported content: {url}",
            "label": label
        })
        
    return samples

def main():
    # Support Render persistent disk via environment variable
    DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__))))
    model_path = os.path.join(DATA_DIR, "email_model.pkl")

    print("\n" + "="*60)
    print("  PhishGuard MLOps — Retraining Pipeline")
    print("="*60)

    # 1. Base dataset
    base_samples = build_dataset()
    
    # 2. Add real feedback
    feedback_samples = get_feedback_samples()
    print(f"\n[+] Added {len(feedback_samples)} real user feedback samples from database.")
    
    all_samples = base_samples + feedback_samples
    
    # 3. Train
    X, y = extract_all_features(all_samples)
    model, metrics = train_model(X, y)
    
    # 4. Save
    save_model(model, metrics, model_path)
    
    # 5. Clear feedback to prevent unbounded growth? (Optional, skipping for safety)
    print("\n[+] Retraining complete. Model is ready for hot-reload.")

if __name__ == "__main__":
    main()
