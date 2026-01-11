# utils.py – TrustChain AI (fix Trustpilot URL check + flexible summary selector)

import os
import requests
from logger import log_debug
import praw
import json
import re
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

PERPLEXITY_URL = "https://api.perplexity.ai/chat/completions"

def fetch_website_text(domain):
    """
    Fetches visible text content from homepage safely.
    Returns lowercase cleaned text.
    """
    print(f"[FetchWebsiteText] Starting analysis for: {domain}")
    try:
        url = domain if domain.startswith("http") else f"https://{domain}"
        headers = {"User-Agent": "Mozilla/5.0"}
        res = requests.get(url, headers=headers, timeout=15)

        soup = BeautifulSoup(res.text, "html.parser")

        # Remove noise
        for tag in soup(["script", "style", "noscript", "svg"]):
            tag.decompose()

        text = soup.get_text(separator=" ")
        cleaned = " ".join(text.split()).lower()

        print("[Fetcher] Website content fetched successfully")
        return cleaned

    except Exception as e:
        print("[Fetcher] Failed to fetch website content:", str(e))
        return ""

def check_domain_age(domain):
    print(f"[DomainAgeCheck] Starting analysis for: {domain}")
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
    print(f"[BlacklistCheck] Starting analysis for: {domain}")
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

    print(f"[PaymentSecurity] Starting analysis for: {domain}")
    # ---- HARD SANITY GUARD ----
    if " " in domain or len(domain) > 80:
        log_debug(f"[PaymentSecurity] Invalid domain input detected: {domain[:120]}")
        raise ValueError("analyze_payment_security received page content instead of domain")
    
    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        baseline_trust = has_baseline_trust(domain)
        log_debug(f"[PaymentSecurity] Baseline trust: {baseline_trust}")
    except Exception as e:
        log_debug(f"[PaymentSecurity] Baseline trust check failed: {e}")
        baseline_trust = False

    if not PERPLEXITY_API:
        log_debug("[PaymentSecurity] PERPLEXITY_API key missing")
        return {
            "payment_methods": [],
            "gateway_reputation": "unknown",
            "scam_reports": "unknown",
            "checkout_security": "unknown",
            "confidence": "low",
            "baseline_trust": baseline_trust
        }

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
        response = requests.post(PERPLEXITY_URL, headers=headers, json=payload, timeout=25)
        log_debug(f"[PaymentSecurity] HTTP Status: {response.status_code}")
        response.raise_for_status()
    except Exception as e:
        log_debug(f"[PaymentSecurity] Perplexity API call failed: {str(e)}")
        raise

    try:
        data = response.json()
        log_debug(f"[PaymentSecurity] Parsed JSON keys: {data.keys()}")
        if "choices" not in data:
            log_debug("[PaymentSecurity] 'choices' missing in response")
            raise ValueError("Invalid Perplexity response format")

        model_text = data["choices"][0]["message"]["content"]
        log_debug(f"[PaymentSecurity] Model output (first 300 chars): {model_text[:300]}")
        
    except Exception as e:
        log_debug(f"[PaymentSecurity] Failed to extract model output: {e}")
        raise

    # ---- Safe JSON parse guard ----
    model_text = model_text.strip() if model_text else ""
    if not model_text:
        log_debug("[PaymentSecurity] Model output empty, returning fallback")
        return {
            "payment_methods": [],
            "gateway_reputation": "unknown",
            "scam_reports": "unknown",
            "checkout_security": "unknown",
            "confidence": "low",
            "baseline_trust": baseline_trust
        }
    try:
        data = json.loads(model_text)
        log_debug(f"[PaymentSecurity] Parsed JSON: {data}")
    except json.JSONDecodeError as e:
        log_debug(f"[PaymentSecurity] JSON parsing failed: {e}")
        log_debug(f"[PaymentSecurity] Raw model output (first 300 chars): {model_text[:300]}")
        return {
            "payment_methods": [],
            "gateway_reputation": "unknown",
            "scam_reports": "unknown",
            "checkout_security": "unknown",
            "confidence": "low",
            "baseline_trust": baseline_trust
        }
    
    try:
        # ---- Sanity normalization ----        
        allowed_reputation = {"trusted", "mixed", "bad", "unknown"}
        if data.get("gateway_reputation") not in allowed_reputation:
            log_debug("[PaymentSecurity] Invalid gateway_reputation, normalizing")
            data["gateway_reputation"] = "unknown"
        
        allowed_scams = {"none", "isolated", "multiple", "unknown"}
        if data.get("scam_reports") not in allowed_scams:
            log_debug("[PaymentSecurity] Invalid scam_reports, normalizing")
            data["scam_reports"] = "unknown"

        allowed_checkout = {"secure", "unclear", "unsafe"}
        if data.get("checkout_security") not in allowed_checkout:
            log_debug("[PaymentSecurity] Invalid checkout_security, normalizing")
            data["checkout_security"] = "unknown"

        allowed_confidence = {"high", "medium", "low"}
        if data.get("confidence") not in allowed_confidence:
            log_debug("[PaymentSecurity] Invalid confidence, normalizing")
            data["confidence"] = "low"
    except Exception as e:
        log_debug(f"[PaymentSecurity] Sanity guard failed: {e}")
        raise

    payment_methods = data.get("payment_methods", [])
    if not isinstance(payment_methods, list):
        log_debug("[PaymentSecurity] payment_methods not a list, resetting")
        payment_methods = []
    return {
            "payment_methods": payment_methods,
            "gateway_reputation": data.get("gateway_reputation", "unknown"),
            "scam_reports": data.get("scam_reports", "unknown"),
            "checkout_security": data.get("checkout_security", "unknown"),
            "confidence": data.get("confidence", "low"),
            "baseline_trust": baseline_trust
    }


def analyze_technical_behavior(domain):
    print(f"[TechBehavior] Starting analysis for: {domain}")

    result = {
        "https": False,
        "redirects": "unknown",
        "script_risk": "unknown",
        "popup_behavior": "unknown",
        "page_errors": "unknown",
        "confidence": "low"
    }

    try:
        # ---- Normalize domain ----
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

        url = f"https://{domain}"
        headers = {"User-Agent": "Mozilla/5.0"}

        # ---- A. HTTPS + Redirect Analysis ----
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        redirects_count = len(response.history)

        result["https"] = response.url.startswith("https")

        if redirects_count == 0:
            result["redirects"] = "clean"
        elif redirects_count <= 2:
            result["redirects"] = "acceptable"
        else:
            result["redirects"] = "excessive"

        # ---- B. HTML Parsing ----
        soup = BeautifulSoup(response.text, "html.parser")

        scripts = soup.find_all("script")
        inline_scripts = [s for s in scripts if not s.get("src")]

        risky_keywords = ["eval(", "document.write", "atob(", "fromCharCode", "window.location"]
        risky_count = 0

        for script in inline_scripts:
            code = script.text.lower()
            if any(k in code for k in risky_keywords):
                risky_count += 1

        if risky_count == 0:
            result["script_risk"] = "low"
        elif risky_count <= 2:
            result["script_risk"] = "medium"
        else:
            result["script_risk"] = "high"

        # ---- C. Popup / Cloaking Detection ----
        high_risk_popup_patterns = [
            "window.open(",
            "onbeforeunload",
            "alert(",
            "confirm(",
            "prompt(",
            "setinterval(",
            "settimeout("
        ]
        popup_hits = 0

        for script in inline_scripts:
            code = script.text.lower()

            if "window.open(" in code and "click" not in code:
                popup_hits += 2  # very strong signal

            if "onbeforeunload" in code:
                popup_hits += 2

            if any(k in code for k in ["alert(", "confirm(", "prompt("]):
                popup_hits += 1

        if popup_hits == 0:
            result["popup_behavior"] = "none"
        elif popup_hits <= 1:
            result["popup_behavior"] = "mild"
        else:
            result["popup_behavior"] = "aggressive"

        # ---- D. Page Errors ----
        if response.status_code >= 500:
            result["page_errors"] = "severe"
        elif response.status_code >= 400:
            result["page_errors"] = "minor"
        else:
            result["page_errors"] = "none"

        result["confidence"] = "high"

    except Exception as e:
        log_debug(f"[TechBehavior] Error: {str(e)}")

    return result

def analyze_onsite_legitimacy(domain):
    print("[OnSiteLegitimacy] Starting analysis for:", domain)

    result = {
        "legal_pages": {
            "terms": False,
            "privacy": False,
            "refund": False,
            "shipping": False
        },
        "contact_info": {
            "email": False,
            "contact_page": False,
            "address": False,
            "phone": False
        },
        "policy_depth": "missing",
        "site_effort": "low"
    }

    try:
        # ---- Normalize domain ----
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        url = f"https://{domain}"
        headers = {"User-Agent": "Mozilla/5.0"}

        response = requests.get(url, headers=headers, timeout=15)
        soup = BeautifulSoup(response.text, "html.parser")

        page_text = soup.get_text(separator=" ").lower()
        links = soup.find_all("a", href=True)

        # -----------------------------
        # 1. Legal Page Detection
        # -----------------------------
        legal_patterns = {
            "terms": ["terms", "terms-of-service", "terms-of-use"],
            "privacy": ["privacy", "privacy-policy"],
            "refund": ["refund", "return", "cancellation"],
            "shipping": ["shipping", "delivery"]
        }

        legal_links_found = 0

        for link in links:
            href = link["href"].lower()
            text = link.get_text().lower()

            for key, patterns in legal_patterns.items():
                if any(p in href or p in text for p in patterns):
                    result["legal_pages"][key] = True
                    legal_links_found += 1

        # -----------------------------
        # 2. Contact Info Detection
        # -----------------------------
        # Email
        email_match = re.search(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", page_text)

        free_email_domains = [
            "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "protonmail.com"
        ]

        if email_match:
            email = email_match.group()
            email_domain = email.split("@")[-1]

            result["contact_info"]["email"] = True
            result["contact_info"]["free_email"] = email_domain in free_email_domains
        else:
            result["contact_info"]["free_email"] = False

        # Contact page
        for link in links:
            if "contact" in link.get_text().lower() or "contact" in link["href"].lower():
                result["contact_info"]["contact_page"] = True
                break

        # Phone number (very loose, international-friendly)
        phone_match = re.search(r"\+\d{1,3}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}", page_text)
        if phone_match:
            result["contact_info"]["phone"] = True

        # Address Detection (pattern-based)
        address_patterns = [
            r"\d{1,5}\s+\w+(\s\w+){0,4},?\s*(street|st|road|rd|lane|ln|avenue|ave|boulevard|blvd|floor|flr)",
            r"\b\d{5,6}\b",  # ZIP / PIN code
        ]

        address_found = False

        # Check <address> tag first
        if soup.find("address"):
            address_found = True

        # Pattern-based search
        for pattern in address_patterns:
            if re.search(pattern, page_text):
                address_found = True

        if address_found:
            result["contact_info"]["address"] = True

        # -----------------------------
        # 3. Policy Depth Evaluation
        # -----------------------------
        # Patterns indicating a refund/return/cancellation policy
        positive_patterns = [
            r"refund", r"return", r"cancellation", r"eligible for refund",
            r"refunds will be issued", r"returns accepted", r"money back"
        ]

        # Patterns indicating restrictions (negative phrases)
        negative_patterns = [
            r"no refunds", r"non[- ]?refundable", r"all sales final", r"no returns",
            r"returns not accepted"
        ]

        policy_score = 0
        positive_hits = 0
        negative_hits = 0

        for pattern in positive_patterns:
            matches = re.findall(pattern, page_text)
            if matches:
                positive_hits += len(matches)
                policy_score += 2  # each positive mention adds to clarity

        for pattern in negative_patterns:
            matches = re.findall(pattern, page_text)
            if matches:
                negative_hits += len(matches)
                policy_score += 1  # still indicates a policy exists, but vague/negative

        # Decide policy_depth
        if policy_score >= 4 and positive_hits > 0:
            result["policy_depth"] = "clear"
        elif policy_score >= 2:
            result["policy_depth"] = "vague"
        else:
            result["policy_depth"] = "missing"

        # -----------------------------
        # 4. Site Effort Heuristic
        # -----------------------------
        effort_score = 0

        effort_score += legal_links_found
        effort_score += sum(result["contact_info"].values())

        if effort_score >= 6:
            result["site_effort"] = "high"
        elif effort_score >= 3:
            result["site_effort"] = "medium"
        else:
            result["site_effort"] = "low"

    except Exception as e:
        log_debug("[OnSiteLegitimacy] Error:", str(e))

    return result

def analyze_offsite_legitimacy(domain: str) -> dict:
    """
    Uses Perplexity (sonar) to evaluate off-site business legitimacy.
    Returns structured, confidence-aware legitimacy signals.
    """

    print(f"[OffsiteLegitimacy] Starting analysis for: {domain}")

    # ---- Sanity guard ----
    if not domain or "." not in domain:
        log_debug("[OffsiteLegitimacy] Invalid domain input")
        return _offsite_fallback("invalid_domain")

    if not PERPLEXITY_API:
        log_debug("[OffsiteLegitimacy] Missing PERPLEXITY_API key")
        return _offsite_fallback("missing_api_key")

    # ---- Prompt ----
    prompt = f"""
You are an online trust and fraud detection system.

Analyze the off-site legitimacy of the e-commerce business operating on the domain:
{domain}

Search the web and evaluate ONLY the following:

1. Whether the company or brand is recognized externally
2. Whether the domain is associated with a legitimate business
3. Presence of scam, fraud, or non-delivery reports
4. Presence of independent media, Wikipedia, Crunchbase, or authoritative mentions
5. Whether external information is consistent with the website's business

IMPORTANT RULES:
- Do NOT assume legitimacy
- If information is insufficient, say "unknown"
- Ignore isolated customer complaints unless they indicate fraud
- Use multiple independent sources if available

Respond ONLY in valid JSON with this exact structure:

{{
  "company_existence": "confirmed | weak | not_found",
  "brand_recognition": "high | medium | low | unknown",
  "scam_reports": "none | isolated | multiple",
  "media_presence": "strong | limited | none",
  "consistency": "consistent | inconsistent",
  "confidence": "high | medium | low"
}}
"""

    payload = {
        "model": "sonar",
        "messages": [
            {"role": "system", "content": "You are a strict JSON-only response engine."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1
    }

    headers = {
        "Authorization": f"Bearer {PERPLEXITY_API}",
        "Content-Type": "application/json"
    }

    try:
        print("[OffsiteLegitimacy] Preparing Perplexity request...")

        response = requests.post(
            PERPLEXITY_URL,
            headers=headers,
            json=payload,
            timeout=30
        )

        log_debug(f"[OffsiteLegitimacy] HTTP Status: {response.status_code}")

        if response.status_code != 200:
            log_debug(f"[OffsiteLegitimacy] API error: {response.text[:300]}")
            return _offsite_fallback("api_error")

        try:
            data = response.json()
        except Exception as e:
            log_debug(f"[OffsiteLegitimacy] JSON parsing of API response failed: {e}")
            log_debug(f"[OffsiteLegitimacy] Raw response: {response.text[:500]}")
            return _offsite_fallback("json_parse_error")

        log_debug(f"[OffsiteLegitimacy] Response keys: {data.keys()}")

        choices = data.get("choices", [])
        if not choices:
            log_debug("[OffsiteLegitimacy] No choices returned in API response")
            return _offsite_fallback("no_choices")

        raw_output = choices[0].get("message", {}).get("content", "")
        if not raw_output:
            log_debug("[OffsiteLegitimacy] Empty model output")
            return _offsite_fallback("empty_output")

        log_debug("[OffsiteLegitimacy] Model output (first 300 chars):")
        log_debug(f"{raw_output[:300]}")

        # ---- Extract first JSON object safely ----
        json_match = re.search(r"\{[\s\S]*?\}", raw_output)

        if not json_match:
            log_debug("[OffsiteLegitimacy] No JSON object found in model output")
            return _offsite_fallback("no_json")

        json_str = json_match.group(0)

        try:
            parsed = json.loads(json_str)
        except Exception as e:
            log_debug(f"[OffsiteLegitimacy] JSON parsing failed after extraction: {str(e)}")
            log_debug(f"[OffsiteLegitimacy] Extracted JSON: {json_str}")
            return _offsite_fallback("json_parse_error")

        log_debug(f"[OffsiteLegitimacy] Parsed JSON keys: {list(parsed.keys())}")

        if parsed["company_existence"] == "confirmed" and parsed["brand_recognition"] == "high":
            parsed["scam_reports"] = "isolated"
            parsed["consistency"] = "consistent"

        required_keys = {
            "company_existence",
            "brand_recognition",
            "scam_reports",
            "media_presence",
            "consistency",
            "confidence"
        }

        missing_keys = required_keys - set(parsed.keys())
        if missing_keys:
            log_debug(f"[OffsiteLegitimacy] Missing required fields: {missing_keys}")
            return _offsite_fallback("invalid_schema")

        log_debug(f"[OffsiteLegitimacy] Parsed legitimacy data: {parsed}")
        return parsed

    except Exception as e:
        log_debug(f"[OffsiteLegitimacy] Unexpected error during off-site analysis: {e}")
        return _offsite_fallback("exception")

# ---- Safe fallback ----
def _offsite_fallback(reason):
    log_debug(f"[OffsiteLegitimacy] Fallback triggered ({reason})")
    return {
        "company_existence": "unknown",
        "brand_recognition": "unknown",
        "scam_reports": "unknown",
        "media_presence": "none",
        "consistency": "unknown",
        "confidence": "low"
    }