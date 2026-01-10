# scorer.py - Full scoring logic using utils.py and logger.py for TrustChain AI

import os
from dotenv import load_dotenv
from datetime import datetime

from utils import (
    check_domain_age,
    check_blacklist_status,
    has_known_payment_gateway,
    extract_legal_pages,
    check_social_sentiment
)
from logger import log_evaluation_entry, log_debug

load_dotenv()


def evaluate(domain, content):
    trust_score = 0
    criteria_log = {}

    domain_score, domain_failures = score_domain_reputation(domain)
    sentiment_score, sentiment_failures = score_user_sentiment(domain)
    payment_score, payment_failures = score_payment_security(domain)
    technical_score, technical_failures = score_technical_behavior(content)
    business_score, business_failures = score_business_legitimacy(content)

    trust_score = domain_score + sentiment_score + payment_score + technical_score + business_score

    if trust_score >= 80:
        risk = "safe"
    elif trust_score >= 50:
        risk = "suspicious"
    else:
        risk = "high risk"

    criteria_log = {
        "domain_reputation": domain_failures or "passed",
        "user_sentiment": sentiment_failures or "passed",
        "payment_security": payment_failures or "passed",
        "technical_behavior": technical_failures or "passed",
        "business_legitimacy": business_failures or "passed"
    }

    log_evaluation_entry(domain, trust_score, risk, criteria_log)
    return trust_score, risk, criteria_log


def score_domain_reputation(domain):
    score = 20
    failures = []
    domain_age = check_domain_age(domain)
    if domain_age == "new":
        score -= 5
        failures.append("new_domain")
    elif domain_age == "error":
        score -= 3
        failures.append("whois_lookup_failed")
        log_debug(f"WHOIS lookup failed for {domain}")

    blacklist_status = check_blacklist_status(domain)
    if blacklist_status == "blacklisted":
        score -= 5
        failures.append("blacklisted")
    elif blacklist_status == "error":
        score -= 3
        failures.append("blacklist_check_failed")
        log_debug(f"VirusTotal check failed for {domain}")

    if domain.endswith(".xyz"):
        score -= 2
        failures.append("tld_flag")

    return max(0, score), failures


def score_user_sentiment(domain):
    score = 20
    failures = []
    try:
        flagged_posts = check_social_sentiment(domain)
        if flagged_posts:
            score -= 8
            failures.extend(flagged_posts)
        if domain.startswith("secure-"):
            score -= 4
            failures.append("fake_review_pattern")
    except Exception as e:
        log_debug(f"Sentiment scoring error for {domain}: {str(e)}")
        failures.append("sentiment_error")
        score -= 5

    return max(0, score), failures


def score_payment_security(domain):
    score = 20
    failures = []

    try:
        from utils import analyze_payment_security

        intel = analyze_payment_security(domain)
        baseline_trust = intel.get("baseline_trust", False)
        
        # ---- A. Payment Methods (8 points) ----
        safe_methods = ["stripe", "paypal", "razorpay", "upi", "apple pay", "google pay"]
        risky_methods = ["crypto", "bitcoin", "bank transfer", "gift card"]

        methods_score = 0
        detected_methods = [m.lower() for m in intel.get("payment_methods", [])]

        for m in detected_methods:
            if m in safe_methods:
                methods_score += 2
            if m in risky_methods:
                methods_score -= 2
                failures.append(f"risky_payment_method:{m}")

        methods_score = max(0, min(8, methods_score))
        score -= (8 - methods_score)

        if not detected_methods:
            failures.append("payment_methods_not_detected")

        # ---- B. Gateway Reputation (6 points) ----
        reputation = intel.get("gateway_reputation", "unknown")

        if reputation == "trusted":
            pass
        elif reputation == "mixed":
            score -= 3
            failures.append("gateway_reputation_mixed")
        elif reputation == "bad":
            score -= 6
            failures.append("gateway_reputation_bad")
        elif reputation == "unknown" and not baseline_trust:
            score -= 2
            failures.append("gateway_reputation_unknown")

        # ---- C. Scam Reports (4 points) ----
        scam_reports = intel.get("scam_reports", "unknown")

        if scam_reports == "none":
            pass
        elif scam_reports == "isolated":
            score -= 2
            failures.append("isolated_payment_scam_reports")
        elif scam_reports == "multiple":
            score -= 4
            failures.append("multiple_payment_scam_reports")
        elif scam_reports == "unknown" and not baseline_trust:
            score -= 2
            failures.append("payment_scam_status_unknown")

        # ---- D. Checkout Security (2 points) ----
        checkout = intel.get("checkout_security", "unknown")

        if checkout == "secure":
            pass
        elif checkout == "unclear":
            score -= 1
            failures.append("checkout_security_unclear")
        elif checkout == "unsafe":
            score -= 2
            failures.append("checkout_not_secure")
        elif checkout == "unknown" and not baseline_trust:
            score -= 1
            failures.append("checkout_security_unknown")

    except Exception as e:
        log_debug(f"Payment security scoring failed: {str(e)}")
        failures.append("payment_security_analysis_failed")
        score -= 8  # conservative fallback

    return max(0, score), failures

def score_technical_behavior(content):
    score = 20
    failures = []
    red_flags = ["redirect", "popup", "malware", "you won", "error", "ai-generated"]
    for flag in red_flags:
        if flag in content:
            failures.append(flag)
    penalty = len(failures) * 3
    return max(0, score - penalty), failures


def score_business_legitimacy(content):
    score = 0
    failures = []
    matched = extract_legal_pages(content)
    score += len(matched) * 3
    for kw in ["refund", "return", "terms", "privacy", "contact", "email"]:
        if kw not in matched:
            failures.append(f"missing_{kw}")
    return min(20, score), failures