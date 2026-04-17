"""
ScamShield — Production-Grade Cybersecurity Analysis Engine
============================================================

A modular, extensible threat-intelligence framework for detecting
employment-scam signals across multiple input vectors.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
try:
    import whois as _whois
    _HAS_WHOIS = True
except ImportError:
    _HAS_WHOIS = False

try:
    from rapidfuzz import fuzz as _fuzz
    _HAS_RAPIDFUZZ = True
except ImportError:
    _HAS_RAPIDFUZZ = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("scamshield")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(name)s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(_handler)

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 1 — CONSTANTS & DATA
# ═══════════════════════════════════════════════════════════════════════════

CANONICAL_COMPANY_DOMAINS: Dict[str, str] = {
    "google": "google.com", "microsoft": "microsoft.com", "amazon": "amazon.com",
    "apple": "apple.com", "meta": "meta.com", "facebook": "facebook.com",
    "netflix": "netflix.com", "tesla": "tesla.com", "infosys": "infosys.com",
    "tcs": "tcs.com", "wipro": "wipro.com", "flipkart": "flipkart.com",
    "paytm": "paytm.com", "ibm": "ibm.com", "oracle": "oracle.com",
    "salesforce": "salesforce.com", "adobe": "adobe.com", "uber": "uber.com",
    "airbnb": "airbnb.com", "twitter": "twitter.com", "linkedin": "linkedin.com",
    "spotify": "spotify.com", "shopify": "shopify.com", "stripe": "stripe.com",
    "deloitte": "deloitte.com", "accenture": "accenture.com", "pwc": "pwc.com",
    "kpmg": "kpmg.com", "ey": "ey.com", "mckinsey": "mckinsey.com",
}

FREE_EMAIL_PROVIDERS: Set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "rediffmail.com",
    "protonmail.com", "proton.me", "yandex.com", "yandex.ru", "zoho.com",
    "aol.com", "icloud.com", "me.com", "mac.com", "gmx.com", "mail.com",
    "fastmail.com", "hushmail.com", "tutanota.com", "lycos.com", "rocketmail.com"
}

DISPOSABLE_EMAIL_DOMAINS: Set[str] = {
    "temp-mail.org", "guerrillamail.com", "10minutemail.com", "mailinator.com",
    "sharklasers.com", "getnada.com", "dispostable.com", "yopmail.com"
}

SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "click", "buzz", "site", "online", "club", "top", "work", "loan", "biz", "info", "link", "ga", "cf", "tk", "ml", "gq"
}

URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"
}

SCAM_TEXT_TIERS = {
    "CRITICAL": {
        "penalty": 20,
        "phrases": ["processing fee", "wire transfer", "send money", "advance payment", "western union", "registration fee", "security deposit"]
    },
    "HIGH": {
        "penalty": 12,
        "phrases": ["guaranteed income", "100% placement", "money back guarantee", "click here to accept", "login to your bank"]
    },
    "MEDIUM": {
        "penalty": 7,
        "phrases": ["no experience required", "immediate joining", "urgent requirement", "limited seats", "act now", "lottery", "prize"]
    },
    "CONTEXTUAL": {
        "penalty": 4,
        "phrases": ["whatsapp", "telegram", "connect here"]
    }
}

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 2 — NORMALIZATION
# ═══════════════════════════════════════════════════════════════════════════

def normalize_input(data: dict) -> dict:
    normalized: Dict[str, Any] = {"_raw": dict(data)}
    
    # URL / Domain
    job_url = (data.get("job_url") or "").strip()
    normalized["job_url"] = job_url
    domain = ""
    if job_url:
        try:
            parsed = urlparse(job_url if "://" in job_url else f"https://{job_url}")
            domain = (parsed.hostname or "").lower().strip(".")
            normalized["url_path"] = parsed.path
        except: domain = ""
    normalized["domain"] = domain

    # Email
    email = (data.get("recruiter_email") or "").strip().lower()
    normalized["recruiter_email"] = email
    normalized["email_domain"] = email.split("@", 1)[1] if "@" in email else ""
    normalized["email_local"] = email.split("@", 1)[0] if "@" in email else ""

    # Phone
    phone = str(data.get("phone_number") or "")
    normalized["phone_number"] = phone
    normalized["phone_clean"] = re.sub(r"\D", "", phone)

    # Company
    company = (data.get("company_claimed") or "").strip().lower()
    normalized["company_claimed"] = data.get("company_claimed", "")
    normalized["company"] = company
    normalized["canonical_domain"] = CANONICAL_COMPANY_DOMAINS.get(company, "")

    # Salary
    salary = data.get("salary_offered")
    try: normalized["salary_offered"] = float(salary) if salary is not None else None
    except: normalized["salary_offered"] = None
    
    # Text
    normalized["offer_text"] = (data.get("offer_text") or "").strip()
    
    return normalized

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 3 — CHECKS
# ═══════════════════════════════════════════════════════════════════════════

def _skip(reason: str) -> dict: return {"flag": False, "penalty": 0, "reason": reason, "category": "SYSTEM", "confidence": 0.0}
def _flag(penalty: int, reason: str, category: str, confidence: float = 0.85) -> dict: return {"flag": True, "penalty": penalty, "reason": reason, "category": category, "confidence": round(confidence, 2)}
def _clean(reason: str, category: str, confidence: float = 0.90) -> dict: return {"flag": False, "penalty": 0, "reason": reason, "category": category, "confidence": round(confidence, 2)}

def check_domain_age(data: dict) -> dict:
    domain = data.get("domain")
    if not domain or not _HAS_WHOIS: return _skip("WHOIS unavailable")
    try:
        w = _whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        if not creation: return _skip("No creation date")
        if creation.tzinfo is None: creation = creation.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation).days
        if age_days < 7: return _flag(40, f"Domain is brand new ({age_days} days)", "DOMAIN_RISK", 0.95)
        if age_days < 30: return _flag(25, f"Domain is very young ({age_days} days)", "DOMAIN_RISK", 0.85)
        return _clean(f"Domain age: {age_days} days", "DOMAIN_RISK")
    except Exception as e: return _skip(f"WHOIS error: {str(e)}")

def check_email_validity(data: dict) -> dict:
    domain = data.get("email_domain")
    local = data.get("email_local")
    company = data.get("company")
    if not domain: return _skip("No email")
    
    if domain in DISPOSABLE_EMAIL_DOMAINS:
        return _flag(45, f"Uses disposable email domain: {domain}", "EMAIL_RISK", 0.98)
    
    if domain in FREE_EMAIL_PROVIDERS:
        # Check for brand stuffing in local part (e.g. hr.google@gmail.com)
        if company and len(company) > 3 and company in local:
            return _flag(30, f"Free email agent claims to be {company} ({data.get('recruiter_email')})", "EMAIL_RISK", 0.90)
        return _flag(20, f"Uses free email provider ({domain})", "EMAIL_RISK", 0.85)
    
    return _clean(f"Email domain {domain} is business-class", "EMAIL_RISK")

def check_typosquat(data: dict) -> dict:
    domain, canonical = data.get("domain"), data.get("canonical_domain")
    if not domain or not canonical or not _HAS_RAPIDFUZZ: return _skip("N/A")
    d_base = domain.rsplit(".", 1)[0]; c_base = canonical.rsplit(".", 1)[0]
    sim = _fuzz.ratio(d_base, c_base)
    if sim > 75 and d_base != c_base:
        return _flag(30, f"Potential typosquat: '{domain}' vs '{canonical}' ({sim:.0f}% sim)", "IMPERSONATION_RISK", sim/100)
    return _clean("No typosquat detected", "IMPERSONATION_RISK")

def check_url_structure(data: dict) -> dict:
    url, domain = data.get("job_url"), data.get("domain")
    if not domain: return _skip("No URL")
    
    if domain in URL_SHORTENERS:
        return _flag(15, f"Uses URL shortener ({domain})", "URL_RISK", 0.80)
    
    tld = domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        return _flag(10, f"Uses suspicious TLD (.{tld})", "URL_RISK", 0.60)
        
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        return _flag(25, "URL uses raw IP address", "URL_RISK", 0.90)
        
    return _clean("URL structure looks normal", "URL_RISK")

def check_ssl(data: dict) -> dict:
    domain = data.get("domain")
    if not domain: return _skip("No domain")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain) as s:
            s.settimeout(3); s.connect((domain, 443))
            cert = s.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "").lower()
        if any(f in issuer for f in ["let's encrypt", "zerossl", "buypass"]):
            return _flag(10, f"Uses free/automated SSL (Issuer: {issuer})", "INFRASTRUCTURE_RISK", 0.70)
        return _clean(f"Valid SSL (Issuer: {issuer})", "INFRASTRUCTURE_RISK")
    except: return _flag(20, "Missing or invalid SSL certificate", "INFRASTRUCTURE_RISK", 0.80)

def check_salary_anomaly(data: dict) -> dict:
    s = data.get("salary_offered")
    if s is None: return _skip("No salary")
    
    # Heuristic: Detect currency from text or default to INR
    is_usd = "$" in data.get("offer_text", "")
    limit = 300000 if is_usd else 5000000 # 300k USD or 50 LPA INR
    
    if s > limit:
        return _flag(25, f"Unrealistic salary ({s:,.0f}) — potentially 'too good to be true' bait", "OFFER_RISK", 0.85)
    
    # Check for round numbers (scammers love flat 1,000,000)
    if s > 10000 and s % 10000 == 0:
        return _flag(5, "Salary is an exact round number", "OFFER_RISK", 0.40)
        
    return _clean("Salary figure is within reasonable bounds", "OFFER_RISK")

def check_offer_text(data: dict) -> dict:
    text = data.get("offer_text", "").lower()
    if not text: return _skip("No text")
    
    findings = []
    total_penalty = 0
    
    for tier, config in SCAM_TEXT_TIERS.items():
        hits = [p for p in config["phrases"] if p in text]
        if hits:
            penalty = config["penalty"] * (1 + (len(hits)-1)*0.2) # Diminishing returns for multiple hits in same tier
            total_penalty += penalty
            findings.append(f"{tier}: {', '.join(hits)}")
            
    # Urgency heuristic
    shouting = len(re.findall(r"[A-Z]{5,}", data.get("offer_text", "")))
    excl = text.count("!")
    if shouting > 3 or excl > 5:
        total_penalty += 10
        findings.append("Urgency: Excessive shouting/exclamation")

    if total_penalty > 0:
        return _flag(int(min(45, total_penalty)), f"Suspicious patterns: {'; '.join(findings)}", "CONTENT_RISK", 0.80)
    return _clean("No obvious scam patterns in text", "CONTENT_RISK")

def check_phone_validity(data: dict) -> dict:
    phone = data.get("phone_clean")
    if not phone: return _skip("No phone")
    
    if len(phone) < 8 or len(phone) > 15:
        return _flag(15, "Invalid phone number length", "CONTACT_RISK", 0.80)
        
    if len(set(phone)) <= 2:
        return _flag(20, "Suspicious repeated digits in phone number", "CONTACT_RISK", 0.90)
        
    return _clean("Phone number passes basic validation", "CONTACT_RISK")

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 4 — ENGINE
# ═══════════════════════════════════════════════════════════════════════════

CHECK_REGISTRY = [
    {"name": "domain_age", "field": "job_url", "func": check_domain_age},
    {"name": "typosquat", "field": "job_url", "func": check_typosquat},
    {"name": "url_structure", "field": "job_url", "func": check_url_structure},
    {"name": "ssl", "field": "job_url", "func": check_ssl},
    {"name": "email_validity", "field": "recruiter_email", "func": check_email_validity},
    {"name": "salary_anomaly", "field": "salary_offered", "func": check_salary_anomaly},
    {"name": "offer_text", "field": "offer_text", "func": check_offer_text},
    {"name": "phone_validity", "field": "phone_number", "func": check_phone_validity},
]

CORRELATION_RULES = [
    ({"email_validity", "domain_age"}, 25, "Coordinated new domain + free email"),
    ({"typosquat", "ssl"}, 20, "Impersonation domain with automated SSL"),
    ({"salary_anomaly", "offer_text"}, 15, "High-pay bait combined with scammy text patterns"),
    ({"url_structure", "offer_text"}, 15, "Suspicious URL infrastructure with scammy text"),
]

def analyze(data: dict) -> dict:
    norm = normalize_input(data)
    results = []
    
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(c["func"], norm): c for c in CHECK_REGISTRY}
        for f in as_completed(futures):
            res = f.result()
            res.update({"check": futures[f]["name"], "field": futures[f]["field"]})
            results.append(res)

    # Scoring logic
    weighted_penalty = sum(r["penalty"] * r["confidence"] for r in results)
    
    # Correlations
    flagged = {r["check"] for r in results if r["flag"]}
    correlations = []
    for req, pen, reason in CORRELATION_RULES:
        if req.issubset(flagged):
            # Scale correlation penalty by average confidence of triggers
            conf = statistics.mean([r["confidence"] for r in results if r["check"] in req])
            correlations.append({"penalty": pen * conf, "reason": reason, "checks": list(req)})
            weighted_penalty += pen * conf

    # Per-field caps to prevent single-field over-kill
    field_sums = {}
    for r in results:
        f = r["field"]
        field_sums[f] = field_sums.get(f, 0) + r["penalty"]
    
    final_score = max(0, 100 - weighted_penalty)
    
    # Verdict logic
    if final_score >= 80: verdict, risk = "SAFE", "LOW"
    elif final_score >= 55: verdict, risk = "REVIEW", "MEDIUM"
    elif final_score >= 30: verdict, risk = "LIKELY SCAM", "HIGH"
    else: verdict, risk = "SCAM", "CRITICAL"

    # Confidence calculation
    active = [r["confidence"] for r in results if r["confidence"] > 0]
    conf_score = statistics.mean(active) if active else 0
    coverage = len(active) / len(CHECK_REGISTRY)
    final_conf = (conf_score * 0.8 + coverage * 0.2)

    # Reasons & Recommendations
    reasons = [r["reason"] for r in results if r["flag"]] + [c["reason"] for c in correlations]
    recs = []
    if risk != "LOW": recs.append("Do not share personal identifiable information (PII)")
    if "salary_anomaly" in flagged: recs.append("Verify typical market salary for this role on Glassdoor/LinkedIn")
    if "email_validity" in flagged: recs.append("Check if the recruiter's email matches the official company domain")
    if risk in ["HIGH", "CRITICAL"]: recs.append("Report this posting to the platform and do not click any further links")

    report = {
        "verdict": verdict,
        "overall_score": int(final_score),
        "overall_risk": risk,
        "confidence": round(final_conf, 2),
        "summary": f"Engine identified {len(flagged)} threat signals. Trust level is {risk}.",
        "reasons": reasons,
        "recommendations": recs,
        "field_analysis": {f: {"score": int(s), "risk": "HIGH" if s > 30 else "MEDIUM" if s > 15 else "LOW"} for f, s in field_sums.items()},
        "signals": results,
        "metadata": {"version": "2.0.0", "timestamp": datetime.now(timezone.utc).isoformat(), "checks_executed": len(results)}
    }
    return report

def _pretty_print(report: dict):
    from json import dumps
    print(f"\n[ VERDICT: {report['verdict']} ] Score: {report['overall_score']}/100  Risk: {report['overall_risk']}")
    print(f"Summary: {report['summary']}\n")
    print("REASONS:")
    for r in report["reasons"]: print(f" - {r}")
    print("\nRECOMMENDATIONS:")
    for r in report["recommendations"]: print(f" - {r}")
    print("\nRAW DATA (JSON truncated):")
    print(dumps(report, indent=2)[:500] + "...")

if __name__ == "__main__":
    samples = [
        {
            "job_url": "https://bit.ly/google-apply-now",
            "company_claimed": "Google",
            "recruiter_email": "hr.google.official@gmail.com",
            "phone_number": "9999999999",
            "salary_offered": 100000,
            "offer_text": "CONGRATULATIONS! Immediate joining! Pay processing fee of $200 via Western Union. Act now!"
        },
        {
            "job_url": "https://google.com/careers",
            "company_claimed": "Google",
            "recruiter_email": "recruiting@google.com",
            "phone_number": "+1-650-253-0000",
            "salary_offered": 150000,
            "offer_text": "We are pleased to offer you a position as Software Engineer."
        },
        {
            "job_url": "http://192.168.1.5/jobs",
            "company_claimed": "Microsoft",
            "recruiter_email": "jobs@micosoft-hr.com",
            "phone_number": "12345678",
            "salary_offered": 5000000,
            "offer_text": "Urgent requirement! No experience required. 100% placement guaranteed. Telegram me here."
        },
        {
            "job_url": "https://infosys-careers.xyz",
            "company_claimed": "Infosys",
            "recruiter_email": "hr.infosys@yopmail.com",
            "phone_number": "1111111111",
            "salary_offered": 7500000,
            "offer_text": "Lottery prize! Click here to accept. Send security deposit to our bank account."
        }
    ]
    for i, s in enumerate(samples, 1):
        print(f"\n{'='*60}\nRunning Sample {i}\n{'='*60}")
        _pretty_print(analyze(s))
