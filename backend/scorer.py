# scorer.py - Full scoring logic using utils.py and logger.py for TrustChain AI

import os
import time
from dotenv import load_dotenv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils import (
    fetch_website_text,
    check_domain_age,
    check_blacklist_status,
    check_social_sentiment,
    analyze_payment_security,
    analyze_technical_behavior,
    analyze_onsite_legitimacy, 
    analyze_offsite_legitimacy
    
)
from logger import log_evaluation_entry, log_debug

load_dotenv()


def evaluate(domain, content):
    trust_score = 0
    criteria_log = {}

    #page_text = fetch_website_text(domain)

    # Execute scoring functions in parallel for better performance
    scoring_functions = [
        ("domain", score_domain_reputation),
        ("sentiment", score_user_sentiment),
        ("payment", score_payment_security),
        ("technical", score_technical_behavior),
        ("business", score_business_legitimacy)
    ]
    
    results = {}
    start_time = time.perf_counter()
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Submit all tasks
        future_to_key = {
            executor.submit(func, domain): key 
            for key, func in scoring_functions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result()
            except Exception as e:
                log_debug(f"Error in {key} scoring: {str(e)}")
                # Set default values on error
                results[key] = (0, [f"{key}_scoring_error"])
    execution_time = time.perf_counter() - start_time
    
    domain_score, domain_failures = results["domain"]
    sentiment_score, sentiment_failures = results["sentiment"]
    payment_score, payment_failures = results["payment"]
    technical_score, technical_failures = results["technical"]
    business_score, business_failures = results["business"]

    trust_score = domain_score + sentiment_score + payment_score + technical_score + business_score
    
    print(f"Parallel scoring execution completed in {execution_time:.2f} seconds")
    log_debug(f"Parallel scoring execution completed in {execution_time:.2f} seconds")

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

def score_technical_behavior(domain):
    score = 20
    failures = []

    try:
        intel = analyze_technical_behavior(domain)

        # ---- A. HTTPS (5 pts) ----
        if not intel.get("https"):
            score -= 5
            failures.append("no_https")

        # ---- B. Redirects (4 pts) ----
        redirects = intel.get("redirects")
        if redirects == "acceptable":
            score -= 1
        elif redirects == "excessive":
            score -= 4
            failures.append("excessive_redirects")

        # ---- C. Script Risk (5 pts) ----
        script_risk = intel.get("script_risk")
        if script_risk == "medium":
            score -= 2
        elif script_risk == "high":
            score -= 5
            failures.append("high_risk_scripts")

        # ---- D. Popups / Cloaking (4 pts) ----
        popup = intel.get("popup_behavior")
        if popup == "mild":
            score -= 2
        elif popup == "aggressive":
            score -= 4
            failures.append("forced_interruption_behavior")

        # ---- E. Page Errors (2 pts) ----
        errors = intel.get("page_errors")
        if errors == "minor":
            score -= 1
        elif errors == "severe":
            score -= 2
            failures.append("server_errors")

    except Exception as e:
        log_debug(f"Technical behavior scoring failed: {str(e)}")
        failures.append("technical_behavior_analysis_failed")
        score -= 8

    return max(0, score), failures


def score_business_legitimacy(domain):

    score = 0
    failures = []

    # ---------- ON-SITE LEGITIMACY (8 pts) ----------
    try:
        onsite_intel = analyze_onsite_legitimacy(domain)

        # A. Legal pages (4 pts)
        legal_count = sum(onsite_intel["legal_pages"].values())
        score += min(4, legal_count)
        for page, exists in onsite_intel["legal_pages"].items():
            if not exists:
                failures.append(f"missing_{page}_page")

        # B. Contact credibility (2 pts)
        contact = onsite_intel["contact_info"]
        if contact["email"]:
            if contact.get("free_email", False):
                score += 1
                failures.append("generic_email_provider")
            else:
                score += 2
        else:
            failures.append("no_email_found")

        # C. Address presence (2 pts)
        if contact.get("address"):
            score += 2
        else:
            failures.append("no_address_found")

        # D. Policy depth & site effort bonus (0–2 pts)
        if onsite_intel.get("policy_depth") == "clear":
            score += 1
        elif onsite_intel.get("policy_depth") == "missing":
            failures.append("no_refund_policy")

        if onsite_intel.get("site_effort") in ["medium", "high"]:
            score += 1
        else:
            failures.append("low_site_effort")

    except Exception as e:
        failures.append("onsite_legitimacy_check_failed")
        score -= 3

    # ---------- OFF-SITE LEGITIMACY (12 pts) ----------

    try:
        off_intel = analyze_offsite_legitimacy(domain)

        if off_intel["company_existence"] == "confirmed":
            score += 3
        elif off_intel["company_existence"] == "weak":
            score += 1
        else:
            failures.append("company_not_verified")

        brand_map = {"high": 3, "medium": 2, "low": 1}
        score += brand_map.get(off_intel["brand_recognition"], 0)

        media_map = {"strong": 2, "limited": 1}
        score += media_map.get(off_intel["media_presence"], 0)

        if off_intel["consistency"] == "consistent":
            score += 2
        else:
            failures.append("offsite_inconsistency")

        if off_intel["scam_reports"] == "none":
            score += 2
        elif off_intel["scam_reports"] == "isolated":
            score += 1
        else:
            score -= 4
            failures.append("multiple_scam_reports")

    except Exception as e:
        failures.append("offsite_legitimacy_check_failed")
        score -= 3

    return max(0, min(20, score)), failures