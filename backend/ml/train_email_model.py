"""
PhishGuard -- ml/train_email_model.py
Email Phishing ML Training Pipeline

Trains a RandomForest classifier on email features.
Includes a built-in synthetic dataset (2500 phishing + 2500 safe) for
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
    {"sender": "alert@usps-delivery.xyz", "subject": "Package Delivery Failed - Action Required",
     "body": "Dear Customer,\n\nWe were unable to deliver your package. Please confirm your shipping address to reschedule delivery.\n\nReschedule here: http://usps-redeliver.tk/confirm\n\nA fee of $3.99 is required for redelivery. Failure to respond within 48 hours will result in return to sender.\n\nUSPS Delivery Services"},
    {"sender": "noreply@fedex-tracking.work", "subject": "FedEx: Your shipment is on hold",
     "body": "Dear Sir/Madam,\n\nYour FedEx shipment #FX8834921 is on hold due to unpaid customs fees.\n\nPay customs fee ($4.95): http://fedx-customs.buzz/pay\n\nPackage will be destroyed after 5 business days.\n\nFedEx Customer Service"},
    {"sender": "support@dhl-express.cam", "subject": "DHL Express: Delivery Exception",
     "body": "Dear Customer,\n\nYour DHL package requires address verification before delivery.\n\nVerify address: http://192.168.1.100/dhl-verify\n\nPlease complete verification within 24 hours.\n\nDHL Express"},
    {"sender": "refund@irs-gov.monster", "subject": "IRS Tax Refund Notification",
     "body": "Dear Taxpayer,\n\nYou are eligible for a tax refund of $4,287.00. To claim your refund, verify your identity.\n\nClaim refund: http://irs-refund.top/claim\n\nYou must respond within 3 business days or your refund will be forfeited.\n\nInternal Revenue Service"},
    {"sender": "notice@social-security.xyz", "subject": "Social Security: Suspicious Activity Detected",
     "body": "Dear Beneficiary,\n\nSuspicious activity has been detected on your Social Security number. Your benefits have been temporarily suspended.\n\nVerify identity: http://ssa-verify.work/confirm\n\nFailure to verify will result in permanent suspension of benefits.\n\nSocial Security Administration"},
    {"sender": "wallet@metamask-verify.tk", "subject": "MetaMask: Wallet Security Alert",
     "body": "Dear User,\n\nYour MetaMask wallet requires immediate verification due to suspicious login attempts.\n\nVerify wallet: http://metamask-secure.ga/verify\n\nEnter your seed phrase to confirm ownership. Failure to verify within 12 hours will result in wallet freeze.\n\nMetaMask Security"},
    {"sender": "alert@coinbase-security.ml", "subject": "Coinbase: Unauthorized Transaction Detected",
     "body": "Dear Account Holder,\n\nAn unauthorized transaction of 0.5 BTC was detected on your Coinbase account.\n\nReview transaction: http://c0inbase-review.cf/auth\n\nIf this was not you, click above immediately to reverse the transaction.\n\nCoinbase Security Team"},
    {"sender": "hr@global-careers.buzz", "subject": "Job Offer: Remote Position - $85/hour",
     "body": "Dear Candidate,\n\nCongratulations! You have been selected for a remote data entry position paying $85/hour.\n\nAccept offer: http://job-offer-apply.pw/accept\n\nPlease provide your banking details for direct deposit setup. This offer expires in 24 hours.\n\nGlobal Careers HR"},
    {"sender": "recruit@amazon-jobs.top", "subject": "Amazon Work From Home Opportunity",
     "body": "Dear Applicant,\n\nAmazon is hiring work-from-home employees. Earn $500/day with no experience required.\n\nApply now: http://amaz0n-careers.click/apply\n\nA small registration fee of $49.99 is required. Limited positions available.\n\nAmazon Recruitment"},
    {"sender": "security@wells-fargo-alert.xyz", "subject": "Wells Fargo: Account Access Restricted",
     "body": "Dear Valued Customer,\n\nYour Wells Fargo account has been restricted due to multiple failed login attempts.\n\nRestore access: http://wellsfarg0-secure.monster/restore\n\nPlease verify your identity within 24 hours to avoid permanent account closure.\n\nWells Fargo Online Banking"},
    {"sender": "alert@bank-of-america.work", "subject": "BofA: Wire Transfer Pending Approval",
     "body": "Dear Account Holder,\n\nA wire transfer of $12,500.00 is pending from your account. If you did not authorize this transaction, take action immediately.\n\nCancel transfer: http://bofa-secure.click/cancel\n\nBank of America Fraud Prevention"},
    {"sender": "billing@uber-receipt.tk", "subject": "Uber: Payment Method Declined",
     "body": "Dear Rider,\n\nYour payment method on file has been declined. Please update your billing information.\n\nUpdate payment: http://uber-billing.ga/update\n\nYour account will be suspended if not updated within 48 hours.\n\nUber Support"},
    {"sender": "noreply@venmo-alert.xyz", "subject": "Venmo: Suspicious Payment Activity",
     "body": "Dear User,\n\nWe detected suspicious payment activity on your Venmo account. Your account has been limited.\n\nVerify identity: http://venm0-verify.ml/auth\n\nPlease respond immediately to restore full access.\n\nVenmo Security"},
    {"sender": "support@discord-verify.cam", "subject": "Discord: Account Will Be Disabled",
     "body": "Dear Member,\n\nYour Discord account has been flagged for Terms of Service violations. Verify your identity to prevent permanent ban.\n\nVerify: http://disc0rd-verify.rest/confirm\n\nYou have 24 hours to respond.\n\nDiscord Trust & Safety"},
    {"sender": "team@spotify-billing.buzz", "subject": "Spotify: Payment Failed - Premium Cancellation",
     "body": "Dear Subscriber,\n\nWe were unable to process your Spotify Premium payment. Your subscription will be cancelled.\n\nUpdate payment: http://sp0tify-billing.top/update\n\nAct within 24 hours to keep your playlists and downloads.\n\nSpotify Billing"},
    {"sender": "verify@tiktok-support.work", "subject": "TikTok: Account Verification Required",
     "body": "Dear Creator,\n\nYour TikTok account requires verification. Unverified accounts will be removed.\n\nVerify now: http://t1ktok-verify.click/auth\n\nThis is your final notice.\n\nTikTok Support"},
    {"sender": "admin@docusign-alert.xyz", "subject": "DocuSign: Document Requires Your Signature",
     "body": "Dear Recipient,\n\nYou have a document waiting for your signature. This document is time-sensitive.\n\nReview & Sign: http://d0cusign-sign.monster/review\n\nPlease download the attached document: contract.exe\n\nDocuSign eSignature"},
    {"sender": "it-support@microsoft365.tk", "subject": "IT Alert: Email Storage Full - Action Required",
     "body": "Dear Employee,\n\nYour Microsoft 365 mailbox has reached its storage limit. Emails will bounce back if not resolved.\n\nExpand storage: http://ms365-storage.ga/expand\n\nEnter your credentials to verify your account.\n\nIT Support Department"},
    {"sender": "shipping@amazon-delivery.club", "subject": "Amazon: Your Order Cannot Be Delivered",
     "body": "Dear Customer,\n\nWe were unable to deliver your Amazon order #AMZ-9912834. Please update your shipping address.\n\nUpdate address: http://amzn-deliver.pw/update\n\nOrder will be cancelled in 72 hours if not resolved.\n\nAmazon Logistics"},
    {"sender": "alert@zelle-payment.xyz", "subject": "Zelle: Payment Pending - Verify Now",
     "body": "Dear User,\n\nA Zelle payment of $850.00 is pending your verification. If you did not request this, take action.\n\nVerify: http://ze11e-verify.top/confirm\n\nUnauthorized transactions must be reported immediately.\n\nZelle Pay"},
    {"sender": "security@steam-guard.work", "subject": "Steam Guard: New Login From Unknown Device",
     "body": "Dear Gamer,\n\nA new login was detected on your Steam account from Russia. If this wasn't you, secure your account.\n\nSecure account: http://stearn-guard.buzz/secure\n\nYour account may be compromised. Act now.\n\nSteam Support"},
    {"sender": "claims@insurance-refund.monster", "subject": "Health Insurance Refund Available",
     "body": "Dear Policyholder,\n\nYou are eligible for a health insurance refund of $2,150.00 due to overpayment.\n\nClaim refund: http://insurance-claim.rest/refund\n\nProvide your banking details to receive your refund. Expires in 5 days.\n\nHealth Insurance Claims"},
    {"sender": "admin@adobe-renew.tk", "subject": "Adobe: Subscription Renewal Failed",
     "body": "Dear User,\n\nYour Adobe Creative Cloud subscription renewal has failed. Your access will be terminated.\n\nRenew now: http://ad0be-renew.ga/billing\n\nAll your cloud files will be deleted after 7 days.\n\nAdobe Billing"},
    {"sender": "verify@snapchat-team.xyz", "subject": "Snapchat: Verify Your Identity",
     "body": "Dear Snapchatter,\n\nYour account has been flagged for unusual activity. Please verify your identity.\n\nVerify: http://snapchat-verify.ml/auth\n\nFailure to verify will result in permanent account deletion.\n\nSnapchat Team"},
    {"sender": "noreply@robinhood-alert.cam", "subject": "Robinhood: Unusual Trading Activity",
     "body": "Dear Investor,\n\nUnusual trading activity was detected on your Robinhood account. Your account has been restricted.\n\nReview activity: http://r0binhood-review.work/auth\n\nVerify your identity to restore trading access.\n\nRobinhood Security"},
    {"sender": "alert@capitalone-fraud.buzz", "subject": "Capital One: Fraud Alert - Card Compromised",
     "body": "Dear Cardholder,\n\nYour Capital One credit card may have been compromised. Unauthorized charges detected.\n\nReview charges: http://capita1one-review.top/fraud\n\nClick above immediately to freeze your card and dispute charges.\n\nCapital One Fraud Department"},
    {"sender": "lottery@mega-prize.pw", "subject": "You've Won €5,000,000 - European Lottery",
     "body": "CONGRATULATIONS!!!\n\nYour email was selected in the European Grand Lottery! You have won FIVE MILLION EUROS!\n\nClaim prize: http://euro-lottery.gq/claim\n\nA processing fee of $99 is required. Download claim form: prize_claim.exe\n\nEuropean Lottery Commission"},
    {"sender": "prince@royal-funds.xyz", "subject": "Urgent Business Proposal - $15M Transfer",
     "body": "Dear Friend,\n\nI am Prince Abubakar from Nigeria. I need your assistance to transfer $15,000,000 from my late father's estate.\n\nYou will receive 30% as commission. Reply with your bank details immediately.\n\nThis is strictly confidential. Time is of the essence.\n\nPrince Abubakar"},
    {"sender": "helpdesk@outlook-verify.club", "subject": "Outlook: Mailbox Deactivation Notice",
     "body": "Dear User,\n\nYour Outlook mailbox will be deactivated due to inactivity. Verify your account to prevent deletion.\n\nKeep my account: http://0utlook-verify.link/keep\n\nAll emails and contacts will be permanently deleted.\n\nMicrosoft Outlook Team"},
    {"sender": "billing@netflix-renewal.surf", "subject": "Netflix: Membership On Hold",
     "body": "Dear Member,\n\nYour Netflix membership is on hold because we're having trouble with your current billing information.\n\nUpdate billing: http://netfl1x-billing.icu/update\n\nUpdate within 48 hours or your account will be cancelled and all viewing history lost.\n\nNetflix Billing Support"},
    {"sender": "support@whatsapp-verify.top", "subject": "WhatsApp: Account Expiring Soon",
     "body": "Dear User,\n\nYour WhatsApp account is about to expire. Please verify to continue using the service.\n\nVerify: http://whatsapp-renew.click/verify\n\nPay the annual subscription fee of $0.99. All messages will be deleted if not renewed.\n\nWhatsApp Support"},
    {"sender": "security@linkedin-alert.work", "subject": "LinkedIn: Someone Is Using Your Identity",
     "body": "Dear Professional,\n\nWe detected someone creating fake profiles using your LinkedIn identity. Verify your account immediately.\n\nVerify: http://l1nkedin-secure.monster/verify\n\nYour professional reputation is at risk.\n\nLinkedIn Security Team"},
    {"sender": "payment@stripe-billing.xyz", "subject": "Stripe: Payment Dispute - Funds Held",
     "body": "Dear Merchant,\n\nA payment dispute has been filed against your Stripe account. $5,200.00 has been held pending review.\n\nRespond to dispute: http://str1pe-disputes.rest/respond\n\nFailure to respond within 7 days will result in funds being returned to the customer.\n\nStripe Disputes Team"},
    {"sender": "alert@shopify-security.buzz", "subject": "Shopify: Store Suspended - Policy Violation",
     "body": "Dear Store Owner,\n\nYour Shopify store has been suspended due to a policy violation. Revenue payouts are frozen.\n\nAppeal suspension: http://sh0pify-appeal.cam/verify\n\nProvide your credentials to begin the appeal process. You have 48 hours.\n\nShopify Trust & Safety"},
    {"sender": "support@zoom-security.tk", "subject": "Zoom: Account Compromised - Immediate Action",
     "body": "Dear User,\n\nYour Zoom account credentials may have been exposed in a data breach. Reset your password immediately.\n\nReset now: http://zo0m-reset.ga/password\n\nAll scheduled meetings have been cancelled as a precaution.\n\nZoom Security Team"},
    {"sender": "verify@twitter-blue.ml", "subject": "X/Twitter: Verification Badge Revoked",
     "body": "Dear User,\n\nYour Twitter/X verification badge has been revoked. Complete re-verification to restore it.\n\nRe-verify: http://tw1tter-verify.cf/badge\n\nYour followers and engagement will drop significantly without verification.\n\nX Platform Support"},
    {"sender": "alert@medicare-refund.work", "subject": "Medicare: Overpayment Refund Available",
     "body": "Dear Beneficiary,\n\nMedicare has determined you are owed a refund of $1,840.00 due to billing overpayment.\n\nClaim refund: http://medicare-refund.click/claim\n\nProvide your Medicare ID and banking information to process refund. Expires in 10 days.\n\nMedicare Services"},
    {"sender": "support@ebay-resolution.xyz", "subject": "eBay: Item Not Received - Case Opened",
     "body": "Dear Seller,\n\nA buyer has opened a case against you for an item not received. Your PayPal funds have been held.\n\nRespond to case: http://ebay-res0lve.top/respond\n\nProvide shipping proof within 48 hours or funds will be refunded to buyer.\n\neBay Resolution Center"},
    {"sender": "noreply@binance-kyc.monster", "subject": "Binance: Complete KYC or Account Will Be Frozen",
     "body": "Dear Trader,\n\nDue to new regulations, all Binance accounts must complete KYC verification. Non-compliant accounts will be frozen.\n\nComplete KYC: http://b1nance-kyc.rest/verify\n\nUpload your ID and proof of address. Deadline: 72 hours.\n\nBinance Compliance"},
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
    {"sender": "noreply@figma.com", "subject": "New comment on your design",
     "body": "Hi Sarah,\n\nMark left a comment on 'Dashboard Redesign v3':\n\n'Love the new color palette! Can we adjust the spacing on the sidebar?'\n\nView in Figma: https://www.figma.com/file/abc123\n\nFigma Notifications"},
    {"sender": "receipts@uber.com", "subject": "Your Uber ride receipt",
     "body": "Hi Alex,\n\nThanks for riding with Uber!\n\nTrip: Downtown to Airport\nDate: March 12, 2025\nTotal: $24.50\n\nView receipt: https://riders.uber.com/trips\n\nRate your driver to help improve the experience.\n\nUber"},
    {"sender": "noreply@venmo.com", "subject": "You paid Sarah $25.00",
     "body": "Hi Mike,\n\nYou paid Sarah Johnson $25.00 for 'Lunch split'.\n\nView transaction: https://venmo.com/account/statement\n\nVenmo"},
    {"sender": "donotreply@chase.com", "subject": "Your Chase statement is ready",
     "body": "Hi David,\n\nYour Chase checking account statement for February 2025 is now available.\n\nView statement: https://secure.chase.com/web/auth/\n\nThank you for being a Chase customer.\n\nChase Online Banking"},
    {"sender": "alerts@bankofamerica.com", "subject": "Direct deposit received",
     "body": "Hi Rachel,\n\nA direct deposit of $3,450.00 has been credited to your checking account ending in 4521.\n\nDate: March 15, 2025\nFrom: ABC Corporation\n\nView account: https://www.bankofamerica.com/\n\nBank of America"},
    {"sender": "noreply@capitalone.com", "subject": "Your payment was received",
     "body": "Hi Tom,\n\nWe received your payment of $156.78 for your Capital One credit card ending in 9876.\n\nNew balance: $0.00\nPayment date: March 14, 2025\n\nManage account: https://www.capitalone.com/\n\nCapital One"},
    {"sender": "news@producthunt.com", "subject": "Top 5 products launching today",
     "body": "Good morning Emma,\n\nHere are today's top product launches:\n\n1. AIWriter - AI-powered content creation\n2. DesignFlow - Automated design system\n3. CodeReview Pro - Smart code review tool\n\nExplore: https://www.producthunt.com/\n\nProduct Hunt Daily"},
    {"sender": "noreply@calendar.google.com", "subject": "Reminder: Team retrospective tomorrow at 2 PM",
     "body": "Hi Jessica,\n\nReminder: Team retrospective is scheduled for tomorrow.\n\nWhen: March 16, 2025 at 2:00 PM EST\nWhere: Conference Room B\nMeet link: https://meet.google.com/abc-defg-hij\n\nGoogle Calendar"},
    {"sender": "notifications@discord.com", "subject": "You have new messages",
     "body": "Hi Chris,\n\nYou have 12 unread messages in your Discord servers:\n\n- #general in Dev Community: 5 messages\n- #help in Python Discord: 7 messages\n\nOpen Discord: https://discord.com/channels/\n\nDiscord"},
    {"sender": "noreply@coursera.org", "subject": "Congratulations on completing your course!",
     "body": "Hi Alex,\n\nCongratulations! You've completed 'Machine Learning Specialization' by Andrew Ng.\n\nYour certificate is ready: https://www.coursera.org/account/accomplishments\n\nKeep learning!\nCoursera"},
    {"sender": "team@notion.so", "subject": "Your weekly Notion digest",
     "body": "Hi Sarah,\n\nHere's what happened in your Notion workspace this week:\n\n- 15 pages updated\n- 3 new databases created\n- 8 comments added\n\nOpen Notion: https://www.notion.so/\n\nNotion Team"},
    {"sender": "support@shopify.com", "subject": "Your store had 45 sales today",
     "body": "Hi David,\n\nGreat day for your store! Here's your daily summary:\n\nOrders: 45\nRevenue: $2,340.00\nTop product: Premium T-Shirt\n\nView dashboard: https://admin.shopify.com/\n\nShopify"},
    {"sender": "noreply@airbnb.com", "subject": "Booking confirmed in Barcelona",
     "body": "Hi Emma,\n\nYour reservation is confirmed!\n\nProperty: Cozy apartment in Gothic Quarter\nCheck-in: April 5, 2025\nCheck-out: April 10, 2025\nTotal: $625.00\n\nView booking: https://www.airbnb.com/trips\n\nAirbnb"},
    {"sender": "orders@target.com", "subject": "Order shipped - arriving Thursday",
     "body": "Hi Lisa,\n\nYour Target order #T-5567891 has shipped!\n\nEstimated delivery: Thursday, March 20\nItems: 3 items\n\nTrack package: https://www.target.com/orders\n\nThank you for shopping at Target."},
    {"sender": "noreply@walmart.com", "subject": "Your pickup order is ready",
     "body": "Hi James,\n\nYour Walmart pickup order #WM-4489012 is ready!\n\nPickup location: Walmart Supercenter - Main St\nPickup hours: 8 AM - 8 PM\n\nView order: https://www.walmart.com/orders\n\nWalmart"},
    {"sender": "security@github.com", "subject": "New SSH key added to your account",
     "body": "Hi Mike,\n\nA new SSH key was added to your GitHub account:\n\nKey: SHA256:abc123def456\nAdded: March 15, 2025\n\nIf this was you, no action is needed. If not, review your SSH keys: https://github.com/settings/keys\n\nGitHub"},
    {"sender": "noreply@npmjs.com", "subject": "Package published: my-awesome-lib@2.1.0",
     "body": "Hi Tom,\n\nYour package my-awesome-lib version 2.1.0 has been published to npm.\n\nView package: https://www.npmjs.com/package/my-awesome-lib\n\nnpm"},
    {"sender": "no-reply@atlassian.com", "subject": "JIRA: Sprint 14 completed",
     "body": "Hi Rachel,\n\nSprint 14 has been completed.\n\nCompleted: 18 stories (42 points)\nCarried over: 3 stories (8 points)\nVelocity: 42 points\n\nView sprint report: https://your-team.atlassian.net/\n\nJira by Atlassian"},
    {"sender": "newsletter@techcrunch.com", "subject": "TechCrunch Daily: AI funding hits record high",
     "body": "Good morning Chris,\n\nToday's top stories:\n\n1. AI startup funding reaches $50B in Q1 2025\n2. Apple announces new developer tools\n3. Google Cloud expands to 5 new regions\n\nRead more: https://techcrunch.com/\n\nTechCrunch Daily"},
    {"sender": "noreply@canva.com", "subject": "Your design has been shared",
     "body": "Hi Jessica,\n\nSarah shared a design with you: 'Marketing Campaign Q2'\n\nView design: https://www.canva.com/design/abc123\n\nCanva"},
    {"sender": "team@vercel.com", "subject": "Deployment successful: my-app",
     "body": "Hi David,\n\nYour project 'my-app' was deployed successfully.\n\nURL: https://my-app.vercel.app\nBranch: main\nCommit: Fix responsive layout\n\nView deployment: https://vercel.com/dashboard\n\nVercel"},
    {"sender": "noreply@grammarly.com", "subject": "Your weekly writing stats",
     "body": "Hi Alex,\n\nHere's your writing summary for this week:\n\nWords checked: 12,450\nUnique words: 2,100\nProductivity score: 89/100\nTone: Confident and professional\n\nView insights: https://app.grammarly.com/\n\nGrammarly"},
    {"sender": "noreply@dropbox.com", "subject": "Someone shared a folder with you",
     "body": "Hi Emma,\n\nSarah shared the folder 'Project Assets' with you.\n\n3 files, 245 MB total\n\nView folder: https://www.dropbox.com/sh/abc123\n\nDropbox"},
    {"sender": "receipts@lyft.com", "subject": "Your Lyft ride receipt",
     "body": "Hi Tom,\n\nThanks for riding with Lyft!\n\nTrip: Home to Office\nDate: March 15, 2025\nTotal: $18.75\nDriver: Maria (4.9 stars)\n\nView receipt: https://www.lyft.com/ride-history\n\nLyft"},
    {"sender": "noreply@duolingo.com", "subject": "Don't break your streak! Practice Spanish today",
     "body": "Hi Lisa,\n\nYou're on a 45-day streak! Don't let it end.\n\nToday's lesson: Past tense verbs\nEstimated time: 5 minutes\n\nStart lesson: https://www.duolingo.com/learn\n\nDuolingo"},
    {"sender": "updates@gitlab.com", "subject": "Merge request approved: feature/auth-v2",
     "body": "Hi Mike,\n\nYour merge request 'Add OAuth2 authentication' has been approved by 2 reviewers.\n\nApproved by: Sarah, James\nPipeline: Passed\n\nView MR: https://gitlab.com/project/-/merge_requests/42\n\nGitLab"},
    {"sender": "hello@substack.com", "subject": "New post from Tech Insights",
     "body": "Hi Rachel,\n\nNew post from Tech Insights: 'The Future of Web Development in 2025'\n\nRead now: https://techinsights.substack.com/p/future-web-dev\n\nYou're receiving this because you subscribed to Tech Insights.\n\nSubstack"},
    {"sender": "noreply@paypal.com", "subject": "You received a payment of $150.00",
     "body": "Hi Chris,\n\nYou received a payment of $150.00 from John Smith.\n\nTransaction ID: 7AB12345CD\nDate: March 15, 2025\n\nView transaction: https://www.paypal.com/activity\n\nPayPal"},
    {"sender": "noreply@twitch.tv", "subject": "StreamerPro is live now!",
     "body": "Hi Alex,\n\nStreamerPro is streaming: 'Competitive Ranked Gameplay'\n\nCategory: Gaming\nViewers: 2,450\n\nWatch now: https://www.twitch.tv/streamerpro\n\nTwitch"},
    {"sender": "support@digitalocean.com", "subject": "Your monthly invoice for March 2025",
     "body": "Hi Tom,\n\nYour DigitalOcean invoice for March 2025 is ready.\n\nAmount due: $24.00\nDue date: April 1, 2025\n\nView invoice: https://cloud.digitalocean.com/account/billing\n\nDigitalOcean"},
    {"sender": "noreply@reddit.com", "subject": "Trending on r/programming",
     "body": "Hi David,\n\nTrending posts in communities you follow:\n\n1. r/programming: 'Why Rust is winning' (2.5k upvotes)\n2. r/webdev: 'CSS has come so far' (1.8k upvotes)\n3. r/python: 'FastAPI best practices' (1.2k upvotes)\n\nView: https://www.reddit.com/\n\nReddit"},
    {"sender": "noreply@apple.com", "subject": "Your Apple ID was used to sign in",
     "body": "Hi Sarah,\n\nYour Apple ID was used to sign in to iCloud on a MacBook Pro.\n\nDate: March 15, 2025\nLocation: San Francisco, CA\n\nIf this was you, no action is needed. If not, go to https://appleid.apple.com\n\nApple"},
    {"sender": "noreply@microsoft.com", "subject": "Your Microsoft 365 subscription was renewed",
     "body": "Hi Emma,\n\nYour Microsoft 365 Personal subscription has been renewed.\n\nPlan: Microsoft 365 Personal\nNext billing: March 15, 2026\nAmount: $69.99/year\n\nManage subscription: https://account.microsoft.com/services\n\nMicrosoft"},
    {"sender": "team@asana.com", "subject": "Weekly status report for Project Phoenix",
     "body": "Hi James,\n\nWeekly update for Project Phoenix:\n\nCompleted: 12 tasks\nIn Progress: 8 tasks\nOverdue: 2 tasks\n\nView project: https://app.asana.com/0/project/board\n\nAsana"},
    {"sender": "hello@mailchimp.com", "subject": "Your campaign 'Spring Sale' was sent",
     "body": "Hi Lisa,\n\nYour email campaign 'Spring Sale' has been sent to 5,420 subscribers.\n\nOpen rate: Tracking...\nClick rate: Tracking...\n\nView report: https://mailchimp.com/reports/\n\nMailchimp"},
    {"sender": "security@amazon.com", "subject": "Your password was changed",
     "body": "Hi Chris,\n\nThe password for your Amazon account was changed on March 15, 2025.\n\nIf you made this change, no further action is needed.\n\nIf you didn't change your password, visit: https://www.amazon.com/security\n\nAmazon"},
    {"sender": "noreply@etsy.com", "subject": "You made a sale!",
     "body": "Hi Rachel,\n\nCongratulations! You made a sale on Etsy.\n\nItem: Handmade ceramic mug\nPrice: $35.00\nBuyer: JohnD\n\nView order: https://www.etsy.com/your/orders/sold\n\nEtsy"},
    {"sender": "noreply@hulu.com", "subject": "New episodes available for you",
     "body": "Hi David,\n\nNew episodes are available:\n\n- The Bear: Season 4, Episode 3\n- Only Murders: Season 5, Episode 1\n\nWatch now: https://www.hulu.com/\n\nHulu"},
    {"sender": "newsletter@wired.com", "subject": "WIRED Daily: The tech stories you need to read",
     "body": "Good morning Tom,\n\nToday's essential reads:\n\n1. Inside the AI chip race\n2. The privacy debate continues\n3. How quantum computing will change everything\n\nRead more: https://www.wired.com/\n\nWIRED"},
]



def generate_variations(templates, count, is_phishing=True):
    """Generate variations from templates to create a larger dataset."""
    rng = random.Random(42)
    samples = []

    # Subject variations for phishing
    phishing_subjects = [
        "URGENT: {}", "WARNING: {}", "Action Required: {}", "FINAL NOTICE: {}",
        "Security Alert: {}", "Important: {}", "Verify now: {}", "Alert: {}",
        "IMMEDIATE ACTION: {}", "ATTENTION: {}", "CRITICAL: {}", "Response Required: {}",
    ]
    safe_subjects = [
        "Re: {}", "{}", "Update: {}", "FYI: {}",
        "Notification: {}", "Reminder: {}", "Weekly: {}", "Your {}",
    ]

    # Name variations
    names = ["Customer", "User", "Account Holder", "Valued Customer",
             "Member", "Sir/Madam", "Subscriber", "Client",
             "Valued Member", "Account Owner", "Dear Friend", "Recipient"]
    real_names = ["John", "Sarah", "Mike", "Emma", "David", "Alex",
                  "Jessica", "Tom", "Rachel", "Chris", "Lisa", "James",
                  "Daniel", "Sophia", "Olivia", "Liam", "Noah", "Ava"]

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
            urgency_additions = [
                "\n\nThis is your last warning. Respond immediately.",
                "\n\nDo not ignore this message. Your account is at risk.",
                "\n\nTime is running out. Act now or face consequences.",
                "\n\nThis is an automated final notice. No further warnings will be sent.",
            ]
            if rng.random() > 0.5:
                body += rng.choice(urgency_additions)
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

    phishing_samples = generate_variations(PHISHING_TEMPLATES, 2500, is_phishing=True)
    safe_samples = generate_variations(SAFE_TEMPLATES, 2500, is_phishing=False)

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

    print(f"\n[4/6] Training RandomForest (300 trees)...")
    start = time.time()
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
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
        "n_features": 28,
        "feature_names": email_feature_names(),
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": "Synthetic (5000 samples, 50+50 templates)",
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
    print("  RandomForest + 28 Features + 5000 Emails")
    print("="*60)

    samples = build_dataset()
    X, y = extract_all_features(samples)
    model, metrics = train_model(X, y)
    save_model(model, metrics, model_path)


if __name__ == "__main__":
    main()
