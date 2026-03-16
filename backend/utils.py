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
        # ---- SAFE JSON EXTRACTION ----
        clean_output = model_text.strip()

        # Remove ```json and ``` fences
        clean_output = re.sub(r"^```json\s*", "", clean_output, flags=re.IGNORECASE)
        clean_output = re.sub(r"\s*```$", "", clean_output)

        log_debug(f"[PaymentSecurity] Cleaned model output (first 300 chars): {clean_output[:300]}")

        # ---- Hard JSON completeness check ----
        if not clean_output.startswith("{") or not clean_output.endswith("}"):
            log_debug("[PaymentSecurity] Incomplete JSON detected, triggering fallback")
            raise ValueError("Incomplete JSON from model")

        # ---- Strict JSON parse ----
        data = json.loads(clean_output)
        log_debug(f"[PaymentSecurity] Parsed JSON successfully")
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

        total_risk_score = 0

        for script in inline_scripts:
            code = script.text.lower()

            script_score = 0

            # ---- High Risk Primitives ----
            if "eval(" in code:
                script_score += 3

            if "new function(" in code:
                script_score += 3

            if "document.write" in code:
                script_score += 2

            # ---- Obfuscation Signals ----
            if "atob(" in code:
                script_score += 2

            if "fromcharcode" in code:
                script_score += 2

            # ---- Dangerous Combinations ----
            if "eval(" in code and "atob(" in code:
                script_score += 3  # encoded payload execution

            if "eval(" in code and "fromcharcode" in code:
                script_score += 3  # charcode-based obfuscation

            # ---- Timed String Execution ----
            if 'settimeout("' in code or "settimeout('" in code:
                script_score += 2

            if 'setinterval("' in code or "setinterval('" in code:
                script_score += 2

            # ---- Redirect Behavior ----
            if "window.location" in code:
                script_score += 1

                # Escalate if redirect appears automatic
                if "window.location=" in code and "click" not in code:
                    script_score += 1

            total_risk_score += script_score

        # ---- Final Classification ----
        if total_risk_score == 0:
            result["script_risk"] = "low"
        elif total_risk_score <= 4:
            result["script_risk"] = "medium"
        else:
            result["script_risk"] = "high"

        # ---- C. Popup / Cloaking Detection ----
        popup_score = 0

        for script in inline_scripts:
            code = script.text.lower()

            # ---- 1. Automatic window spawning ----
            if "window.open(" in code:
                popup_score += 1

                # Escalate if likely auto-triggered (not user event based)
                if not any(evt in code for evt in ["onclick", "addeventlistener", "click", "mousedown"]):
                    popup_score += 2  # strong auto-popup signal

            # ---- 2. Exit trapping ----
            if "onbeforeunload" in code:
                popup_score += 3  # very strong manipulation signal

            # ---- 3. Blocking dialogs ----
            if "alert(" in code:
                popup_score += 1

            if "confirm(" in code:
                popup_score += 1

            if "prompt(" in code:
                popup_score += 2  # stronger than alert, often phishing-related

            # ---- 4. Timed popup triggers ----
            if "settimeout(" in code or "setinterval(" in code:
                # Escalate only if combined with popup functions
                if any(k in code for k in ["alert(", "confirm(", "prompt(", "window.open("]):
                    popup_score += 2

        # ---- Final Classification ----
        if popup_score == 0:
            result["popup_behavior"] = "none"
        elif popup_score <= 2:
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
        from urllib.parse import urljoin, urlparse

        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        base_domain = domain.replace("www.", "")
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
            "terms": [
                "terms", "terms-of-service", "terms-of-use", "terms-and-conditions", "conditions"
            ],
            "privacy": [
                "privacy", "privacy-policy"
            ],
            "refund": [
                "refund", "return", "cancellation"
            ],
            "exchange": [
                "exchange", "replacement"
            ],
            "shipping": [
                "shipping", "delivery"
            ]
        }

        legal_links_found = 0
        legal_page_urls = []
        base_url = f"https://{domain}"

        for link in links:
            raw_href = link["href"]
            link_text = link.get_text().strip().lower()

            full_url = urljoin(base_url, raw_href)
            parsed = urlparse(full_url)

            parsed_domain = parsed.netloc.replace("www.", "")

            # Strict same domain check
            if parsed_domain != base_domain:
                continue

            path = parsed.path.lower()
            path_segments = path.strip("/").split("/")

            for key, patterns in legal_patterns.items():
                if result["legal_pages"].get(key):
                    continue

                if (
                    any(p in segment for segment in path_segments for p in patterns)
                    or any(p in link_text for p in patterns)
                ):
                    result["legal_pages"][key] = True
                    legal_links_found += 1
                    legal_page_urls.append(full_url)

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
        combined_policy_text = page_text

        # Fetch up to 5 legal pages for deeper scan
        for legal_url in legal_page_urls[:5]:
            try:
                legal_response = requests.get(legal_url, headers=headers, timeout=10)
                legal_soup = BeautifulSoup(legal_response.text, "html.parser")
                legal_text = legal_soup.get_text(separator=" ").lower()
                combined_policy_text += " " + legal_text
            except Exception:
                continue

        positive_patterns = [
            r"refund", r"return", r"cancellation",
            r"eligible for refund", r"refunds will be issued",
            r"returns accepted", r"money back"
        ]

        negative_patterns = [
            r"no refunds", r"non[- ]?refundable",
            r"all sales final", r"no returns",
            r"returns not accepted"
        ]

        policy_mentions = []
        positive_hits = 0
        negative_hits = 0

        sentences = re.split(r"[.\n]", combined_policy_text)

        for sentence in sentences:
            sentence = sentence.strip()
            if any(k in sentence for k in ["refund", "return", "cancellation", "exchange"]):
                policy_mentions.append(sentence)

        for pattern in positive_patterns:
            positive_hits += len(re.findall(pattern, combined_policy_text))

        for pattern in negative_patterns:
            negative_hits += len(re.findall(pattern, combined_policy_text))

        policy_length_score = sum(len(s.split()) for s in policy_mentions)

        policy_score = 0

        if positive_hits + negative_hits > 0:
            policy_score += 2

        if policy_length_score > 100:
            policy_score += 2
        elif policy_length_score > 40:
            policy_score += 1

        if negative_hits > 0:
            policy_score += 2

        if positive_hits >= 3:
            policy_score += 2

        if policy_score >= 5:
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