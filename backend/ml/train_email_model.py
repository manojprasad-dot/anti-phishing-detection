"""
PhishGuard -- ml/train_email_model.py
Email Phishing ML Training Pipeline

Trains a RandomForest classifier on email features.
Includes a built-in synthetic dataset (500 phishing + 500 safe) for
immediate functionality without external downloads.

Usage:
    cd backend
    python ml/train_email_model.py
"""

import os
import sys
import pickle
import time
import random
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from features.email_extractor import extract_email_features, email_feature_names


# ==============================================================================
# Built-in Synthetic Training Dataset
# ==============================================================================

# Phishing email templates with realistic variations
PHISHING_TEMPLATES = [
    {
        "sender": "security@paypal-verification.xyz",
        "subject": "Urgent: Your account has been suspended",
        "body": "Dear Customer,\n\nWe have detected unauthorized access to your account. Your account has been temporarily suspended.\n\nClick here to verify your identity immediately: http://paypal-secure.tk/verify\n\nFailure to verify within 24 hours will result in permanent account closure.\n\nPayPal Security Team"
    },
    {
        "sender": "support@amazon-orders.club",
        "subject": "Action Required: Payment Failed",
        "body": "Dear Valued Customer,\n\nYour recent payment has failed. Please update your billing information to avoid account suspension.\n\nUpdate now: http://bit.ly/amzn-update\n\nIf you do not respond within 48 hours, your account will be locked.\n\nAmazon Support"
    },
    {
        "sender": "noreply@netflix-billing.xyz",
        "subject": "Your Netflix subscription is about to expire",
        "body": "Dear User,\n\nWe were unable to process your last payment. To continue enjoying Netflix, please verify your payment details.\n\n<a href='http://192.168.1.5/netflix-login'>Click here to update</a>\n\nAct now or your account will be terminated.\n\nNetflix Team"
    },
    {
        "sender": "admin@microsoft-security.top",
        "subject": "Security Alert: Unusual sign-in activity",
        "body": "Dear Account Holder,\n\nWe detected unusual activity on your Microsoft account. Someone tried to sign in from an unknown location.\n\nVerify your identity: http://micros0ft-verify.work/auth\n\nIf this was not you, click the link above immediately to secure your account.\n\nMicrosoft Security"
    },
    {
        "sender": "info@apple-id-verify.ml",
        "subject": "Your Apple ID has been locked",
        "body": "Dear Customer,\n\nYour Apple ID has been locked due to security reasons. Please verify your identity to unlock your account.\n\n<form action='http://app1e-id.ga/login'><input type='password' placeholder='Enter password'></form>\n\nThis is your final notice.\n\nApple Support"
    },
    {
        "sender": "winner@lottery-prize.buzz",
        "subject": "Congratulations! You've Won $1,000,000",
        "body": "CONGRATULATIONS!!!\n\nYou have been selected as the winner of our international lottery. You've won ONE MILLION DOLLARS!\n\nClaim your prize now: http://lottery-claim.pw/winner\n\nPlease download the attached claim form: prize_form.exe\n\nRespond immediately to claim your reward!"
    },
    {
        "sender": "support@chase-banking.work",
        "subject": "Immediate action required - Account compromised",
        "body": "Dear Sir/Madam,\n\nYour Chase bank account has been compromised. Unauthorized transactions have been detected.\n\nSecure your acccount now: http://chase-secure.click/login\n\nDo not ignore this message. Legal action may be taken.\n\nChase Security Department"
    },
    {
        "sender": "help@dropbox-share.tk",
        "subject": "Someone shared a file with you",
        "body": "Dear User,\n\nSomeone has shared an important document with you on Dropbox.\n\nView document: http://dropbox-file.gq/download\n\nPlease download it immediately: shared_doc.zip\n\nDropbox Team"
    },
    {
        "sender": "no-reply@instagram-verify.cam",
        "subject": "Verify your Instagram account now",
        "body": "Dear Member,\n\nYour 1nstagram account needs verification. Failure to verifiy will result in account suspension.\n\nVerify now: http://is.gd/insta_verify\n\nThis is time sensitive. Act now.\n\nInstagram Security"
    },
    {
        "sender": "billing@google-security.monster",
        "subject": "Your Google account will be terminated",
        "body": "Dear Subscriber,\n\nYour G00gle account is scheduled for termination due to suspicious activity.\n\nConfirm your identity: http://g00gle-securty.rest/confirm\n\nYou must respond within 24 hours or your account will be permanently closed.\n\nGoogle Security Team"
    },
]

SAFE_TEMPLATES = [
    {
        "sender": "noreply@github.com",
        "subject": "New login to your GitHub account",
        "body": "Hi John,\n\nWe noticed a new login to your GitHub account from Chrome on Windows.\n\nIf this was you, you can ignore this email. If not, please review your security settings at https://github.com/settings/security\n\nThanks,\nThe GitHub Team"
    },
    {
        "sender": "notifications@linkedin.com",
        "subject": "You have 5 new connection requests",
        "body": "Hi Sarah,\n\nYou have 5 new connection requests on LinkedIn.\n\nView your connections: https://www.linkedin.com/mynetwork/\n\nBest regards,\nLinkedIn Notifications"
    },
    {
        "sender": "no-reply@accounts.google.com",
        "subject": "Your Google Account: Monthly security report",
        "body": "Hi Mike,\n\nHere's your monthly security summary for your Google Account.\n\nNo issues found. Your account is secure.\n\nReview your settings: https://myaccount.google.com/security\n\nGoogle Account Team"
    },
    {
        "sender": "team@slack.com",
        "subject": "Weekly digest from your Slack workspace",
        "body": "Hi Emma,\n\nHere's what happened in your Slack workspace this week:\n- 45 messages in #general\n- 12 messages in #engineering\n- 3 new channels created\n\nOpen Slack: https://app.slack.com/\n\nSlack"
    },
    {
        "sender": "orders@amazon.com",
        "subject": "Your order has been shipped",
        "body": "Hi David,\n\nGreat news! Your order #112-4567890 has been shipped.\n\nEstimated delivery: March 15-17\nTracking: https://www.amazon.com/gp/your-orders\n\nThank you for shopping with us.\nAmazon.com"
    },
    {
        "sender": "hello@newsletter.medium.com",
        "subject": "Daily Digest: Top stories for you",
        "body": "Good morning Alex,\n\nHere are today's top stories on Medium:\n\n1. How AI is Changing Software Development\n2. The Future of Remote Work\n3. Understanding Machine Learning\n\nRead more: https://medium.com/\n\nMedium Daily Digest"
    },
    {
        "sender": "noreply@spotify.com",
        "subject": "Your Spotify Wrapped 2025 is here",
        "body": "Hi Jessica,\n\nYour 2025 Wrapped is ready! See your top songs, artists, and listening stats.\n\nView your Wrapped: https://open.spotify.com/wrapped\n\nHappy listening!\nSpotify"
    },
    {
        "sender": "do-not-reply@zoom.us",
        "subject": "Meeting reminder: Team standup at 10:00 AM",
        "body": "Hi team,\n\nReminder: Team standup meeting starts in 30 minutes.\n\nJoin: https://zoom.us/j/1234567890\nPassword: 123456\n\nSee you there!\nZoom"
    },
    {
        "sender": "support@stripe.com",
        "subject": "Your monthly invoice is ready",
        "body": "Hi Rachel,\n\nYour Stripe invoice for February 2025 is ready.\n\nAmount: $49.00\nView invoice: https://dashboard.stripe.com/invoices\n\nThank you for using Stripe.\nStripe Billing"
    },
    {
        "sender": "notifications@trello.com",
        "subject": "Card assigned to you: Fix landing page",
        "body": "Hi Tom,\n\nYou've been assigned a new card on the Development board:\n\nCard: Fix landing page responsiveness\nDue: March 20\nBoard: https://trello.com/b/abc123\n\nTrello Notifications"
    },
]


def generate_variations(templates, count, is_phishing=True):
    """Generate variations from templates to create a larger dataset."""
    rng = random.Random(42)
    samples = []

    # Subject variations for phishing
    phishing_subjects = [
        "URGENT: {}", "WARNING: {}", "Action Required: {}", "FINAL NOTICE: {}",
        "Security Alert: {}", "Important: {}", "Verify now: {}", "Alert: {}",
    ]
    safe_subjects = [
        "Re: {}", "{}", "Update: {}", "FYI: {}",
    ]

    # Name variations
    names = ["Customer", "User", "Account Holder", "Valued Customer",
             "Member", "Sir/Madam", "Subscriber", "Client"]
    real_names = ["John", "Sarah", "Mike", "Emma", "David", "Alex",
                  "Jessica", "Tom", "Rachel", "Chris", "Lisa", "James"]

    for i in range(count):
        template = rng.choice(templates)

        # Vary the content slightly
        body = template["body"]
        subject = template["subject"]
        sender = template["sender"]

        if is_phishing:
            # Randomize greeting
            greeting = rng.choice(names)
            body = body.replace("Dear Customer", f"Dear {greeting}")
            body = body.replace("Dear User", f"Dear {greeting}")

            # Randomize subject format
            fmt = rng.choice(phishing_subjects)
            if rng.random() > 0.5:
                subject = fmt.format(subject)

            # Add random urgency
            if rng.random() > 0.6:
                body += "\n\nThis is your last warning. Respond immediately."
        else:
            # Randomize name
            name = rng.choice(real_names)
            for n in real_names:
                body = body.replace(f"Hi {n}", f"Hi {name}")

            if rng.random() > 0.5:
                fmt = rng.choice(safe_subjects)
                subject = fmt.format(subject)

        samples.append({
            "sender": sender,
            "subject": subject,
            "body": body,
            "label": 1 if is_phishing else 0,
        })

    return samples


def build_dataset():
    """Build training dataset from templates."""
    print("\n[1/6] Building synthetic email dataset...")

    phishing_samples = generate_variations(PHISHING_TEMPLATES, 500, is_phishing=True)
    safe_samples = generate_variations(SAFE_TEMPLATES, 500, is_phishing=False)

    all_samples = phishing_samples + safe_samples
    random.Random(42).shuffle(all_samples)

    print(f"      Total: {len(all_samples)} emails "
          f"(Phishing: {len(phishing_samples)}, Safe: {len(safe_samples)})")

    return all_samples


def extract_all_features(samples):
    """Extract features from all emails."""
    print(f"\n[2/6] Extracting features from {len(samples)} emails...")

    feature_names = email_feature_names()
    feature_list = []
    labels = []
    start = time.time()

    for i, sample in enumerate(samples):
        features = extract_email_features(
            email_text=sample["body"],
            sender=sample["sender"],
            subject=sample["subject"],
        )
        feature_list.append([features.get(k, 0) for k in feature_names])
        labels.append(sample["label"])

        if (i + 1) % 200 == 0 or (i + 1) == len(samples):
            elapsed = time.time() - start
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"      [{(i+1)/len(samples)*100:5.1f}%] {i+1}/{len(samples)} ({rate:.0f}/sec)")

    X = np.array(feature_list, dtype=np.float32)
    y = np.array(labels)
    print(f"      Shape: {X.shape} | Phishing: {sum(y==1)} | Safe: {sum(y==0)}")
    return X, y


def train_model(X, y):
    """Train RandomForest classifier for email phishing detection."""
    X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)

    print(f"\n[3/6] Splitting 80/20...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n[4/6] Training RandomForest (200 trees)...")
    start = time.time()
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    print(f"      Done in {time.time()-start:.1f}s")

    # Evaluate
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall    = recall_score(y_test, y_pred)
    f1        = f1_score(y_test, y_pred)
    auc       = roc_auc_score(y_test, y_proba)

    print(f"\n{'='*60}")
    print(f"  EMAIL MODEL RESULTS (RandomForest)")
    print(f"{'='*60}")
    print(f"  Accuracy:  {accuracy*100:.2f}%")
    print(f"  Precision: {precision*100:.2f}%")
    print(f"  Recall:    {recall*100:.2f}%")
    print(f"  F1 Score:  {f1*100:.2f}%")
    print(f"  AUC-ROC:   {auc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    cm = confusion_matrix(y_test, y_pred)
    print(f"  Confusion Matrix:")
    print(f"  {'':20s} Pred Safe  Pred Phish")
    print(f"  {'Actual Safe':20s}  {cm[0][0]:>7}     {cm[0][1]:>7}")
    print(f"  {'Actual Phishing':20s}  {cm[1][0]:>7}     {cm[1][1]:>7}")

    # Feature importance
    names = email_feature_names()
    if len(names) == X.shape[1]:
        imp = sorted(zip(names, model.feature_importances_),
                     key=lambda x: x[1], reverse=True)
        print(f"\n  Top Features:")
        for n, v in imp[:10]:
            print(f"    {n:30s} {v:.4f}  {'#'*int(v*50)}")

    # Cross-validation
    print(f"\n[5/6] 5-Fold Cross Validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy", n_jobs=-1)
    print(f"      CV: {cv_scores.mean()*100:.2f}% +/- {cv_scores.std()*100:.2f}%")

    return model, {
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1, "auc_roc": auc,
        "cv_mean": cv_scores.mean(), "cv_std": cv_scores.std(),
    }


def save_model(model, metrics, path):
    """Save trained model to disk."""
    print(f"\n[6/6] Saving to {path}")
    data = {
        "model": model,
        "model_type": "RandomForestClassifier",
        "n_features": 20,
        "feature_names": email_feature_names(),
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": "Synthetic (1000 samples)",
        **metrics,
    }
    with open(path, "wb") as f:
        pickle.dump(data, f)
    print(f"      Size: {os.path.getsize(path)/1024:.1f} KB")
    print(f"      Accuracy: {metrics['accuracy']*100:.2f}%")
    print(f"\n  Email model saved successfully!\n")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "email_model.pkl")

    print("\n" + "="*60)
    print("  PhishGuard — Email Phishing ML Training")
    print("  RandomForest + 20 Features + 1000 Emails")
    print("="*60)

    samples = build_dataset()
    X, y = extract_all_features(samples)
    model, metrics = train_model(X, y)
    save_model(model, metrics, model_path)


if __name__ == "__main__":
    main()
