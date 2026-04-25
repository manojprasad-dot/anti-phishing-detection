"""
PhishGuard -- ml/train_email_xgboost.py
Email Phishing XGBoost Training Pipeline (v2.0)

Trains an XGBoost classifier on 32 email features.
Includes a built-in synthetic dataset (5,000 samples) with diverse
templates for immediate high-accuracy performance.

Usage:
    cd backend
    python ml/train_email_xgboost.py

Outputs:
    - email_model.pkl (XGBoost model + metadata)
    - Console report: accuracy, precision, recall, F1, AUC-ROC, confusion matrix
"""

import os
import sys
import io
import pickle
import time
import random
import numpy as np

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ML imports
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from features.email_extractor import extract_email_features, email_feature_names


# ==============================================================================
# Built-in Synthetic Training Dataset (25 phishing + 25 safe templates)
# ==============================================================================

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
    {
        "sender": "accounts@wellsfargo-alert.xyz",
        "subject": "Unusual Transaction Detected on Your Account",
        "body": "Dear Account Holder,\n\nWe have detected an unusual transaction on your Wells Fargo account amounting to $4,789.00.\n\nIf you did not authorize this transaction, please verify your identity immediately: http://wf-secure.tk/verify\n\nProvide your account number and PIN to confirm: http://wellsfargo-verify.xyz/auth\n\nThis is urgent. Failure to respond will result in your account being frozen.\n\nWells Fargo Security Team"
    },
    {
        "sender": "security@dhl-tracking.pw",
        "subject": "Your DHL Package Could Not Be Delivered",
        "body": "Dear Customer,\n\nYour package could not be delivered because the shipping address was incorrect.\n\nPlease update your shipping details within 24 hours: http://dhl-redelivery.pw/update\n\nDownload the attached shipping label: shipping_label.exe\n\nDHL Express"
    },
    {
        "sender": "admin@coinbase-verify.buzz",
        "subject": "Suspicious Login to Your Coinbase Account",
        "body": "Dear User,\n\nSomeone attempted to access your Coinbase account from an unrecognized device in Moscow, Russia.\n\nSecure your account now: http://coinbase-secure.xyz/auth\n\nEnter your password and 2FA code to confirm it was you.\n\nIf you do not take action within 2 hours, your cryptocurrency wallet will be locked.\n\nCoinbase Security"
    },
    {
        "sender": "support@ebay-refund.click",
        "subject": "Refund Notification: $349.99 Pending",
        "body": "Dear Valued Customer,\n\nYou are entitled to a refund of $349.99 for a recent eBay purchase. To claim your refund, please verify your bank details.\n\nClaim refund: http://ebay-refund.click/claim\n\n<form action='http://ebay-refund.click/process'><input type='text' placeholder='Bank Account Number'><input type='password' placeholder='Bank PIN'></form>\n\nActon required within 48 hours.\n\neBay Customer Service"
    },
    {
        "sender": "alert@fedex-delivery.monster",
        "subject": "Failed Delivery Attempt - Action Needed",
        "body": "Dear Recipient,\n\nWe attempted to deliver your FedEx package but nobody was available to receive it.\n\nReschedule delivery: http://fedex-redelivery.monster/schedule\n\nPlease download the shipping receipt: receipt.scr\n\nIf you do not respond, the package will be returned to sender.\n\nFedEx Ground"
    },
    {
        "sender": "noreply@steam-community.icu",
        "subject": "Your Steam Account Has Been Reported",
        "body": "Dear Steam User,\n\nYour account has been reported for trading violations. To avoid permanent ban, verify your account.\n\nVerify: http://steam-community.icu/verify\n\nYou must complete verification within 12 hours or your account and all games will be permanently deleted.\n\nSteam Support"
    },
    {
        "sender": "hr@company-benefits.gq",
        "subject": "Important: Update Your Direct Deposit Information",
        "body": "Dear Employee,\n\nDue to a system update, all employees must re-enter their direct deposit information.\n\nUpdate your information here: http://bit.ly/hr-deposit-update\n\nPlease have your bank routing number and Social Security Number ready.\n\nHuman Resources Department"
    },
    {
        "sender": "security@whatsapp-verify.surf",
        "subject": "WhatsApp Account Verification Required",
        "body": "Dear User,\n\nYour WhatsApp account needs re-verification. Failure to verify will result in deactivation.\n\nVerify now: http://whatsapp-verify.surf/auth\n\nEnter your phone number and verification code. This is your last warning.\n\nWhatsApp Support"
    },
    {
        "sender": "crypto@bitcoin-investment.rest",
        "subject": "Exclusive: 500% Return on Bitcoin Investment",
        "body": "Dear Investor,\n\nCONGRATULATIONS! You have been selected for an exclusive Bitcoin investment opportunity.\n\nInvest just $200 and earn $1,000 in 24 hours! This is a LIMITED TIME exclusive offer.\n\nStart now: http://bitcoin-invest.rest/signup\n\nProvide your cryptocurrency wallet address and banking details to get started.\n\nThis offer expires in 12 hours. Act now!\n\nBitcoin Investment Group"
    },
    {
        "sender": "tax@irs-refund.cf",
        "subject": "IRS Tax Refund: $3,247.00 Available",
        "body": "Dear Taxpayer,\n\nThe Internal Revenue Service has determined that you are eligible for a tax refund of $3,247.00.\n\nTo claim your refund, please verify your identity: http://irs-refund.cf/claim\n\nYou must provide your Social Security Number and bank account details.\n\nThis is a time sensitive matter. Respond within 3 business days.\n\nInternal Revenue Service"
    },
    {
        "sender": "service@paypa1-support.tk",
        "subject": "Your PayPal Account: Unauthorized Transaction Alert",
        "body": "Dear Customer,\n\nWe noticed a login from an unfamiliar device to your PayPal account.\n\nDevice: Unknown (IP: 185.123.xx.xx)\nLocation: Lagos, Nigeria\n\nIf this wasn't you, secure your account immediately: http://paypa1-secure.tk/lockdown\n\nFailure to verify within 24 hours will result in permanent account closure.\n\nPayPal Security"
    },
    {
        "sender": "noreply@linkedin-premium.xyz",
        "subject": "Your LinkedIn Premium Trial is Ending",
        "body": "Dear Member,\n\nYour LinkedIn Premium trial expires today. Act now to keep your premium features.\n\nRenew at special rate: http://linkedin-premium.xyz/renew\n\nEnter your credit card number to continue your subscription at 50% off.\n\nThis is a limited time offer. Do not ignore.\n\nLinkedIn"
    },
    {
        "sender": "alerts@telegram-security.ga",
        "subject": "Telegram: Someone Tried to Log Into Your Account",
        "body": "Dear User,\n\nSomeone attempted to access your Telegram account from an unknown device.\n\nIf this wasn't you, secure your account: http://tinyurl.com/telegram-secure\n\nYou must respond immediately to prevent unauthorized access.\n\nTelegram Security Team"
    },
    {
        "sender": "billing@disney-plus.work",
        "subject": "Disney+ Payment Issue: Update Required",
        "body": "Dear Subscriber,\n\nWe couldn't process your Disney+ subscription payment. Your account will be suspended unless you update your payment method.\n\nUpdate now: http://disneyplus-billing.work/update\n\n<form action='http://disneyplus-billing.work/pay'><input type='text' placeholder='Card Number'><input type='password' placeholder='CVV'></form>\n\nAction required within 24 hours.\n\nDisney+ Billing"
    },
    {
        "sender": "compliance@bank-notice.bid",
        "subject": "FINAL NOTICE: Account Compliance Review",
        "body": "Dear Sir/Madam,\n\nThis is a FINAL NOTICE regarding your bank account compliance review. Your account has been flagged for irregular activity.\n\nComplete the compliance form immediately: http://bank-compliance.bid/form\n\nProvide your full legal name, SSN, and bank account details.\n\nFailure to comply within 72 hours may result in legal action and account termination.\n\nBank Compliance Department"
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
    {
        "sender": "noreply@twitter.com",
        "subject": "Your weekly Twitter highlights",
        "body": "Hi Mike,\n\nHere are your top moments from this week on Twitter:\n\n- 15 new followers\n- Your tweet about AI got 234 likes\n- Trending topics in your area\n\nSee more: https://twitter.com/home\n\nTwitter"
    },
    {
        "sender": "no-reply@apple.com",
        "subject": "Your Apple ID was used to sign in to iCloud",
        "body": "Hi Sarah,\n\nYour Apple ID was used to sign in to iCloud on a MacBook Pro.\n\nDate: April 20, 2026\nLocation: New York, NY\n\nIf this was you, no action is needed.\nIf you didn't sign in, visit https://appleid.apple.com\n\nApple Support"
    },
    {
        "sender": "noreply@paypal.com",
        "subject": "You sent $25.00 to John Smith",
        "body": "Hi Alex,\n\nYou sent a payment of $25.00 USD to John Smith.\n\nTransaction ID: 8RF123456789\nDate: April 21, 2026\n\nView details: https://www.paypal.com/activity\n\nPayPal"
    },
    {
        "sender": "hello@notion.so",
        "subject": "Welcome to Notion!",
        "body": "Hi there,\n\nWelcome to Notion! We're excited to have you.\n\nHere are some resources to get started:\n- Quick start guide: https://www.notion.so/getting-started\n- Templates: https://www.notion.so/templates\n\nHappy writing!\nThe Notion Team"
    },
    {
        "sender": "billing@netflix.com",
        "subject": "Your Netflix receipt",
        "body": "Hi David,\n\nThank you for your payment.\n\nPlan: Standard\nAmount: $15.49\nNext billing date: May 21, 2026\n\nManage your subscription: https://www.netflix.com/YourAccount\n\nNetflix"
    },
    {
        "sender": "noreply@figma.com",
        "subject": "Someone mentioned you in a comment",
        "body": "Hi Emma,\n\nAlex mentioned you in a comment on the Landing Page Design file:\n\n\"@Emma can you review the hero section?\"\n\nView comment: https://www.figma.com/file/abc123\n\nFigma"
    },
    {
        "sender": "digest@producthunt.com",
        "subject": "Top 5 Products of the Day",
        "body": "Good morning!\n\nHere are today's top products:\n\n1. AI Code Assistant - Smart coding companion\n2. DesignFlow - UI design automation\n3. DataSync - Real-time data sync tool\n\nExplore all: https://www.producthunt.com/\n\nProduct Hunt Daily Digest"
    },
    {
        "sender": "support@digitalocean.com",
        "subject": "Your droplet is running low on disk space",
        "body": "Hi there,\n\nYour droplet 'web-server-01' is using 85% of its disk space.\n\nConsider upgrading or cleaning up unused files.\n\nManage droplet: https://cloud.digitalocean.com/droplets\n\nDigitalOcean Support"
    },
    {
        "sender": "no-reply@coursera.org",
        "subject": "You earned a new certificate!",
        "body": "Congratulations Sarah!\n\nYou've successfully completed 'Machine Learning' by Stanford University.\n\nView your certificate: https://www.coursera.org/account/accomplishments\n\nKeep learning!\nCoursera"
    },
    {
        "sender": "team@vercel.com",
        "subject": "Deployment successful: my-app",
        "body": "Hi Tom,\n\nYour deployment for 'my-app' was successful.\n\nURL: https://my-app.vercel.app\nBranch: main\nCommit: abc1234\n\nView deployment: https://vercel.com/dashboard\n\nVercel"
    },
    {
        "sender": "noreply@dropbox.com",
        "subject": "Alex shared a folder with you",
        "body": "Hi Jessica,\n\nAlex shared the folder 'Project Assets' with you.\n\nView folder: https://www.dropbox.com/sh/abc123\n\nYou can access this folder anytime from your Dropbox.\n\nDropbox"
    },
    {
        "sender": "updates@canva.com",
        "subject": "New templates available for you",
        "body": "Hi there,\n\nWe've added new templates you might like:\n\n- Social media post templates\n- Presentation designs\n- Resume templates\n\nExplore templates: https://www.canva.com/templates\n\nCanva Team"
    },
    {
        "sender": "support@shopify.com",
        "subject": "Your store had 45 new orders this week",
        "body": "Hi Rachel,\n\nGreat week! Your store had 45 new orders totaling $3,245.00.\n\nTop product: Wireless Earbuds (18 sold)\n\nView analytics: https://admin.shopify.com/store/analytics\n\nShopify"
    },
    {
        "sender": "noreply@airbnb.com",
        "subject": "Booking confirmed: Paris apartment",
        "body": "Hi David,\n\nYour booking is confirmed!\n\nDestination: Paris, France\nCheck-in: June 15, 2026\nCheck-out: June 20, 2026\nHost: Marie\n\nView booking: https://www.airbnb.com/trips\n\nAirbnb"
    },
    {
        "sender": "hello@mailchimp.com",
        "subject": "Your campaign was sent successfully",
        "body": "Hi Tom,\n\nYour email campaign 'April Newsletter' was sent successfully.\n\nRecipients: 1,245\nOpen rate: 32%\nClick rate: 8%\n\nView report: https://mailchimp.com/reports\n\nMailchimp"
    },
]


def generate_variations(templates, count, is_phishing=True):
    """Generate variations from templates to create a larger dataset."""
    rng = random.Random(42)
    samples = []

    # Subject variations
    phishing_subjects = [
        "URGENT: {}", "WARNING: {}", "Action Required: {}", "FINAL NOTICE: {}",
        "Security Alert: {}", "Important: {}", "Verify now: {}", "Alert: {}",
        "[WARNING] {}", "IMMEDIATE ACTION: {}", "Critical: {}", "Last Warning: {}",
    ]
    safe_subjects = [
        "Re: {}", "{}", "Update: {}", "FYI: {}",
        "Reminder: {}", "Weekly: {}", "Monthly: {}",
    ]

    # Greeting variations
    phishing_greetings = [
        "Dear Customer", "Dear User", "Dear Account Holder",
        "Dear Valued Customer", "Dear Sir/Madam", "Dear Member",
        "Dear Client", "Dear Subscriber", "Attention User",
        "Dear Recipient", "Dear Sir", "Dear Madam",
    ]
    safe_names = [
        "John", "Sarah", "Mike", "Emma", "David", "Alex",
        "Jessica", "Tom", "Rachel", "Chris", "Lisa", "James",
        "Maria", "Robert", "Jennifer", "Michael", "Amanda", "Brian",
    ]

    # Extra urgency lines for phishing
    urgency_additions = [
        "\n\nThis is your last warning. Respond immediately.",
        "\n\nYour account will be permanently deleted if you don't act NOW.",
        "\n\nDo not ignore this email. Time is running out.",
        "\n\nIMPORTANT: You must respond within 12 hours.",
        "\n\nFailure to comply will result in legal consequences.",
        "\n\nACT NOW before it's too late!",
    ]

    for i in range(count):
        template = rng.choice(templates)

        body = template["body"]
        subject = template["subject"]
        sender = template["sender"]

        if is_phishing:
            # Randomize greeting
            greeting = rng.choice(phishing_greetings)
            body = body.replace("Dear Customer", f"Dear {greeting.split(' ', 1)[-1]}")
            body = body.replace("Dear User", f"Dear {greeting.split(' ', 1)[-1]}")

            # Randomize subject format
            if rng.random() > 0.4:
                fmt = rng.choice(phishing_subjects)
                subject = fmt.format(subject)

            # Add random urgency
            if rng.random() > 0.5:
                body += rng.choice(urgency_additions)

            # Randomly add credential requests
            if rng.random() > 0.7:
                body += "\n\nPlease have your Social Security Number and bank account ready."

        else:
            # Randomize safe email name
            name = rng.choice(safe_names)
            for n in safe_names:
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
    print("\n[1/7] Building synthetic email dataset...")

    phishing_samples = generate_variations(PHISHING_TEMPLATES, 2500, is_phishing=True)
    safe_samples = generate_variations(SAFE_TEMPLATES, 2500, is_phishing=False)

    all_samples = phishing_samples + safe_samples
    random.Random(42).shuffle(all_samples)

    print(f"      Total: {len(all_samples)} emails "
          f"(Phishing: {len(phishing_samples)}, Safe: {len(safe_samples)})")

    return all_samples


def extract_all_features(samples):
    """Extract 32 features from all emails."""
    print(f"\n[2/7] Extracting 32 features from {len(samples)} emails...")

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

        if (i + 1) % 500 == 0 or (i + 1) == len(samples):
            elapsed = time.time() - start
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"      [{(i+1)/len(samples)*100:5.1f}%] {i+1}/{len(samples)} ({rate:.0f}/sec)")

    X = np.array(feature_list, dtype=np.float32)
    y = np.array(labels)
    print(f"      Shape: {X.shape} | Phishing: {sum(y==1)} | Safe: {sum(y==0)}")
    return X, y


def train_model(X, y):
    """Train XGBoost classifier for email phishing detection."""
    X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)

    print(f"\n[3/7] Splitting 80/20...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Train: {len(X_train)} | Test: {len(X_test)}")

    print(f"\n[4/7] Training XGBoost classifier...")
    start = time.time()
    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        scale_pos_weight=1.0,  # balanced dataset
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )
    train_time = time.time() - start
    print(f"      Done in {train_time:.1f}s")

    # Evaluate
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall    = recall_score(y_test, y_pred)
    f1        = f1_score(y_test, y_pred)
    auc       = roc_auc_score(y_test, y_proba)

    print(f"\n{'='*60}")
    print(f"  EMAIL MODEL RESULTS (XGBoost)")
    print(f"{'='*60}")
    print(f"  Accuracy:  {accuracy*100:.2f}%")
    print(f"  Precision: {precision*100:.2f}%")
    print(f"  Recall:    {recall*100:.2f}%")
    print(f"  F1 Score:  {f1*100:.2f}%")
    print(f"  AUC-ROC:   {auc:.4f}")

    print(f"\n{classification_report(y_test, y_pred, target_names=['Safe', 'Phishing'])}")

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
        print(f"\n  Top 15 Features:")
        for n, v in imp[:15]:
            bar = '#' * int(v * 80)
            print(f"    {n:30s} {v:.4f}  {bar}")

    # Cross-validation
    print(f"\n[5/7] 5-Fold Cross Validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy", n_jobs=-1)
    print(f"      CV: {cv_scores.mean()*100:.2f}% +/- {cv_scores.std()*100:.2f}%")

    cv_f1 = cross_val_score(model, X, y, cv=cv, scoring="f1", n_jobs=-1)
    print(f"      CV F1: {cv_f1.mean()*100:.2f}% +/- {cv_f1.std()*100:.2f}%")

    cv_precision = cross_val_score(model, X, y, cv=cv, scoring="precision", n_jobs=-1)
    print(f"      CV Precision: {cv_precision.mean()*100:.2f}% +/- {cv_precision.std()*100:.2f}%")

    return model, {
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1, "auc_roc": auc,
        "cv_mean": cv_scores.mean(), "cv_std": cv_scores.std(),
        "cv_f1_mean": cv_f1.mean(),
        "train_time": round(train_time, 2),
    }


def save_model(model, metrics, path):
    """Save trained model to disk."""
    print(f"\n[6/7] Saving to {path}")
    data = {
        "model": model,
        "model_type": "XGBClassifier",
        "n_features": 32,
        "feature_names": email_feature_names(),
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": "Synthetic (5000 samples, 25 templates/class)",
        "risk_thresholds": {
            "safe": "0-30",
            "suspicious": "30-60",
            "phishing": "60-100",
        },
        **metrics,
    }
    with open(path, "wb") as f:
        pickle.dump(data, f)
    print(f"      Size: {os.path.getsize(path)/1024:.1f} KB")
    print(f"      Accuracy: {metrics['accuracy']*100:.2f}%")
    print(f"      F1 Score: {metrics['f1']*100:.2f}%")
    print(f"      Precision: {metrics['precision']*100:.2f}%")


def run_demo_predictions(model):
    """Run sample predictions to show output format."""
    print(f"\n[7/7] Demo predictions...\n")

    demo_emails = [
        {
            "name": "PHISHING — PayPal Scam",
            "sender": "security@paypal-verification.xyz",
            "subject": "Urgent: Your account has been suspended",
            "body": "Dear Customer,\n\nWe have detected unauthorized access to your PayPal account.\nVerify immediately: http://paypal-secure.tk/verify\n\nFailure to verify within 24 hours will result in permanent closure.\nDownload: verify_form.exe\n\nPayPal Security Team",
        },
        {
            "name": "SAFE — GitHub Notification",
            "sender": "noreply@github.com",
            "subject": "New login to your GitHub account",
            "body": "Hi John,\n\nWe noticed a new sign-in to your GitHub account.\n\nDevice: Chrome on Windows 11\nLocation: San Francisco, CA\n\nIf this was you, no action is needed.\nhttps://github.com/settings/security\n\nThe GitHub Team",
        },
    ]

    feature_names = email_feature_names()
    for demo in demo_emails:
        features = extract_email_features(demo["body"], demo["sender"], demo["subject"])
        vector = np.array([[float(features.get(k, 0)) for k in feature_names]], dtype=np.float32)
        vector = np.nan_to_num(vector, nan=0.0)
        proba = model.predict_proba(vector)[0][1]
        risk_score = int(round(proba * 100))

        if risk_score >= 60:
            label = "PHISHING 🔴"
        elif risk_score >= 30:
            label = "SUSPICIOUS ⚠️"
        else:
            label = "SAFE ✅"

        print(f"  {demo['name']}")
        print(f"  Sender: {demo['sender']}")
        print(f"  SPF: {'Fail' if features.get('spf_fail') else 'Pass'} | "
              f"DKIM: {'Fail' if features.get('dkim_fail') else 'Pass'} | "
              f"DMARC: {'Fail' if features.get('dmarc_fail') else 'Pass'}")
        print(f"  Risk Score: {risk_score}%")
        print(f"  Result: {label}")
        print()


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "email_model.pkl")

    print("\n" + "="*60)
    print("  PhishGuard — Email Phishing XGBoost Training v2.0")
    print("  XGBoost + 32 Features + 5000 Emails")
    print("="*60)

    samples = build_dataset()
    X, y = extract_all_features(samples)
    model, metrics = train_model(X, y)
    save_model(model, metrics, model_path)
    run_demo_predictions(model)

    print("="*60)
    print("  Training complete! Model saved to email_model.pkl")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
