# utils.py – TrustChain AI (fix Trustpilot URL check + flexible summary selector)

import os
import requests
from backend.logger import log_debug
import praw
import json
from bs4 import BeautifulSoup
from urllib.parse import quote
from dotenv import load_dotenv

load_dotenv()

WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID")
REDDIT_CLIENT_SECRET = os.getenv("REDDIT_CLIENT_SECRET")
REDDIT_USER_AGENT = os.getenv("REDDIT_USER_AGENT")
PERPLEXITY_API = os.getenv("PERPLEXITY_API")


def check_domain_age(domain):
    if not WHOIS_API_KEY:
        return 'error'
    try:
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            "apiKey": WHOIS_API_KEY,
            "domainName": domain,
            "outputFormat": "JSON"
        }
        res = requests.get(url, params=params)
        data = res.json()
        created = data["WhoisRecord"].get("createdDate", "")
        if any(year in created for year in ["2024", "2025"]):
            return "new"
        return "old"
    except Exception as e:
        print(f"[WHOIS] Error: {e}")
        return "error"


def check_blacklist_status(domain):
    if not VIRUSTOTAL_API_KEY:
        return 'error'
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        res = requests.get(url, headers=headers)
        data = res.json()
        malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        return "blacklisted" if malicious > 0 else "safe"
    except Exception as e:
        print(f"[VirusTotal] Error: {e}")
        return "error"


def has_known_payment_gateway(content):
    known_gateways = ["stripe", "paypal", "razorpay", "amazon pay", "apple pay"]
    return any(gw in content.lower() for gw in known_gateways)


def extract_legal_pages(content):
    terms = ["refund", "return", "terms", "privacy", "contact", "email"]
    return [t for t in terms if t in content.lower()]


def google_search_trustpilot_profile(domain):
    try:
        domain = domain.replace("www.", "")
        query = f"site:trustpilot.com/review/{domain}"
        headers = {"User-Agent": "Mozilla/5.0"}
        url = f"https://www.google.com/search?q={quote(query)}"
        res = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        for link in soup.select("a"):
            href = link.get("href", "")
            if "trustpilot.com/review" in href:
                raw_url = href.split("&")[0].replace("/url?q=", "")
                if raw_url.startswith("http"):
                    print("[Trustpilot] Found profile via Google:", raw_url)
                    return raw_url
    except Exception as e:
        print("[Google Trustpilot Search] Error:", e)
    return None


def check_social_sentiment(domain):
    findings = []
    flagged_keywords = ["scam", "fraud", "ripoff", "fake", "non delivery", "chargeback", "never arrived", "cheated", "doesn't work"]
    trustpilot_negative_phrases = [
        "let down", "dissatisfaction", "incorrect items", "missing products", "defective goods",
        "poor quality", "delivery issues", "delays", "cancellations", "poor handling",
        "unhelpful", "unresponsive", "refund difficulties", "difficulty obtaining refund",
        "customer service is another sore point", "not meet expectations"
    ]
    base_terms = [domain, domain.replace("www.", "").split(".")[0]]

    print("[Social Sentiment] Domain being checked:", domain)

    # Reddit check
    if REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET and REDDIT_USER_AGENT:
        try:
            reddit = praw.Reddit(
                client_id=REDDIT_CLIENT_ID,
                client_secret=REDDIT_CLIENT_SECRET,
                user_agent=REDDIT_USER_AGENT
            )
            for query in base_terms:
                for post in reddit.subreddit("all").search(query, sort="new", limit=15):
                    text = (post.title + " " + post.selftext).lower()
                    if any(flag in text for flag in flagged_keywords):
                        findings.append(f"reddit: {post.title[:60]}{'...' if len(post.title) > 60 else ''}")
                        break
        except Exception as e:
            print(f"[Reddit API] Error: {e}")

    # Trustpilot via summary
    try:
        profile_url = google_search_trustpilot_profile(domain)
        if profile_url:
            headers = {"User-Agent": "Mozilla/5.0"}
            review_page = requests.get(profile_url, headers=headers, timeout=10)
            soup = BeautifulSoup(review_page.text, "html.parser")
            summary = soup.find("p", class_=lambda c: c and "typography_body" in c)
            if summary:
                text = summary.get_text().lower()
                print("[Trustpilot] Summary:", text)
                if any(phrase in text for phrase in trustpilot_negative_phrases):
                    findings.append("trustpilot: " + text[:80] + ("..." if len(text) > 80 else ""))
            else:
                print("[Trustpilot] Summary paragraph not found.")
    except Exception as e:
        print("[Trustpilot Scraping Error]", e)

    # Simulate Quora & App store
    if "scam" in domain or domain.startswith("fraud"):
        findings.append("quora: flagged as suspicious by users")

    return findings

def has_baseline_trust(domain):
    """
    Determines baseline trust using deterministic signals.
    This should override LLM uncertainty.
    """

    # VirusTotal check (strongest signal)
    blacklist = check_blacklist_status(domain)
    if blacklist == "safe":
        return True

    return False

def analyze_payment_security(domain):
    """
    Uses Perplexity API to analyze payment security signals
    Returns structured intelligence for scorer.py
    """

    log_debug(f"[PaymentSecurity] Starting analysis for: {domain}")
    # ---- HARD SANITY GUARD ----
    if " " in domain or len(domain) > 80:
        log_debug(f"[PaymentSecurity] ❌ Invalid domain input detected: {domain[:120]}")
        raise ValueError("analyze_payment_security received page content instead of domain")
    
    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        baseline_trust = has_baseline_trust(domain)
        log_debug(f"[PaymentSecurity] Baseline trust: {baseline_trust}")
    except Exception as e:
        log_debug(f"[PaymentSecurity] ❌ Baseline trust check failed: {e}")
        baseline_trust = False

    if not PERPLEXITY_API:
        log_debug("[PaymentSecurity] ❌ PERPLEXITY_API key missing")
        return {
            "payment_methods": [],
            "gateway_reputation": "unknown",
            "scam_reports": "unknown",
            "checkout_security": "unknown",
            "confidence": "low",
            "baseline_trust": baseline_trust
        }

    url = "https://api.perplexity.ai/chat/completions"

    prompt = f"""
Analyze the payment security of the e-commerce website {domain}.

Return ONLY valid JSON in the following format:

{{
  "payment_methods": [list of payment methods or gateways used],
  "gateway_reputation": "trusted | mixed | bad | unknown",
  "scam_reports": "none | isolated | multiple | unknown",
  "checkout_security": "secure | unclear | unsafe",
  "confidence": "high | medium | low"
}}

Guidelines:
- Mention Stripe, PayPal, Razorpay, UPI, Apple Pay, Google Pay if found
- Flag crypto, bank transfer, or gift card payments as risky
- Only consider explicit payment fraud such as unauthorized charges, fake checkout pages, payment redirection scams, or non-payment fraud.
- Ignore general customer complaints about delivery, refunds, sizing, or service quality.
- If no explicit payment fraud is found, return "none" for scam_reports.
- If information is insufficient, use "unknown"
- Do NOT add explanations outside JSON
"""

    headers = {
        "Authorization": f"Bearer {PERPLEXITY_API}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "sonar",
        "messages": [
            {"role": "system", "content": "You are a security analyst. Return only JSON."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }
    log_debug("[PaymentSecurity] Preparing Perplexity request...")
    log_debug("[PaymentSecurity] Model: sonar")

    try:
        log_debug("[PaymentSecurity] Calling Perplexity API...")
        response = requests.post(url, headers=headers, json=payload, timeout=25)
        log_debug(f"[PaymentSecurity] HTTP Status: {response.status_code}")
        response.raise_for_status()
    except Exception as e:
        log_debug(f"[PaymentSecurity] ❌ Perplexity API call failed: {str(e)}")
        raise

    try:
        '''raw = response.json()
        print("[PaymentSecurity] Raw API response keys:", raw.keys())'''
        data = response.json()
        log_debug(f"[PaymentSecurity] Parsed JSON keys: {data.keys()}")
        if "choices" not in data:
            log_debug("[PaymentSecurity] ❌ 'choices' missing in response")
            raise ValueError("Invalid Perplexity response format")

        log_debug(f"[PaymentSecurity] Choices length: {len(data["choices"])}")

        model_text = data["choices"][0]["message"]["content"]
        log_debug(f"[PaymentSecurity] Model output (first 300 chars): {model_text[:300]}")
        
    except Exception as e:
        log_debug(f"[PaymentSecurity] ❌ Failed to extract model output: {e}")
        raise

    try:    
        # ---- Hard JSON parse guard ----
        data = json.loads(model_text)
        log_debug(f"[PaymentSecurity] Parsed JSON: {data}")
    except Exception as e:
        log_debug(f"[PaymentSecurity] ❌ JSON parsing failed: {e}")
        raise
    
    try:
        # ---- Sanity normalization ----        
        allowed_reputation = {"trusted", "mixed", "bad", "unknown"}
        if data.get("gateway_reputation") not in allowed_reputation:
            log_debug("[PaymentSecurity] ⚠️ Invalid gateway_reputation, normalizing")
            data["gateway_reputation"] = "unknown"
        
        allowed_scams = {"none", "isolated", "multiple", "unknown"}
        if data.get("scam_reports") not in allowed_scams:
            log_debug("[PaymentSecurity] ⚠️ Invalid scam_reports, normalizing")
            data["scam_reports"] = "unknown"

        allowed_checkout = {"secure", "unclear", "unsafe"}
        if data.get("checkout_security") not in allowed_checkout:
            log_debug("[PaymentSecurity] ⚠️ Invalid checkout_security, normalizing")
            data["checkout_security"] = "unknown"

        allowed_confidence = {"high", "medium", "low"}
        if data.get("confidence") not in allowed_confidence:
            log_debug("[PaymentSecurity] ⚠️ Invalid confidence, normalizing")
            data["confidence"] = "low"
    except Exception as e:
        log_debug(f"[PaymentSecurity] ❌ Sanity guard failed: {e}")
        raise

    payment_methods = data.get("payment_methods", [])
    if not isinstance(payment_methods, list):
        log_debug("[PaymentSecurity] ⚠️ payment_methods not a list, resetting")
        payment_methods = []
    return {
            "payment_methods": payment_methods,
            "gateway_reputation": data.get("gateway_reputation", "unknown"),
            "scam_reports": data.get("scam_reports", "unknown"),
            "checkout_security": data.get("checkout_security", "unknown"),
            "confidence": data.get("confidence", "low"),
            "baseline_trust": baseline_trust
    }