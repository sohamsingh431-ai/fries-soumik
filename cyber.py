"""
ScamShield — Production-Grade Cybersecurity Analysis Engine (FULL POWER)
=========================================================================
Version: 3.0.0
Built from: ScamShield_Cyber_Layer.pdf architecture spec

Modules implemented:
  01 — Domain & Web Intelligence
  02 — Network & Infrastructure
  03 — Email Intelligence
  04 — Phone Intelligence
  05 — Impersonation Detection
  06 — OSINT & Web Presence
  +  — Correlation Engine, Hard Overrides, Confidence Scoring
"""

from __future__ import annotations

import hashlib
import logging
import re
import socket
import ssl
import statistics
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Optional dependencies — graceful degradation for every single one
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

try:
    import dns.resolver as _dns_resolver
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False

try:
    import phonenumbers as _phonenumbers
    _HAS_PHONENUMBERS = True
except ImportError:
    _HAS_PHONENUMBERS = False

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    try:
        import urllib.request as _urllib_req
        _HAS_REQUESTS = False
    except ImportError:
        _HAS_REQUESTS = False

try:
    import tldextract as _tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

try:
    import ipwhois as _ipwhois_mod
    _HAS_IPWHOIS = True
except ImportError:
    _HAS_IPWHOIS = False

try:
    import geoip2.database as _geoip2_db
    _HAS_GEOIP2 = True
except ImportError:
    _HAS_GEOIP2 = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("scamshield.cyber")
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
#  SECTION 1 — CONSTANTS & THREAT INTELLIGENCE DATA
# ═══════════════════════════════════════════════════════════════════════════

# Top 100+ company canonical domains (zero latency lookup)
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
    "cognizant": "cognizant.com", "hcl": "hcltech.com", "techm": "techmahindra.com",
    "mindtree": "mindtree.com", "lti": "lntinfotech.com", "mphasis": "mphasis.com",
    "capgemini": "capgemini.com", "reliance": "ril.com", "jio": "jio.com",
    "hdfc": "hdfcbank.com", "icici": "icicibank.com", "sbi": "sbi.co.in",
    "axis": "axisbank.com", "bajaj": "bajajfinserv.in", "razorpay": "razorpay.com",
    "phonepe": "phonepe.com", "swiggy": "swiggy.com", "zomato": "zomato.com",
    "byjus": "byjus.com", "unacademy": "unacademy.com", "ola": "olacabs.com",
    "meesho": "meesho.com", "cred": "cred.club", "groww": "groww.in",
    "nvidia": "nvidia.com", "intel": "intel.com", "amd": "amd.com",
    "samsung": "samsung.com", "sony": "sony.com", "paypal": "paypal.com",
    "visa": "visa.com", "mastercard": "mastercard.com",
    "goldman sachs": "goldmansachs.com", "jp morgan": "jpmorgan.com",
    "morgan stanley": "morganstanley.com", "barclays": "barclays.com",
    "hsbc": "hsbc.com", "deutsche bank": "db.com", "ubs": "ubs.com",
    "citibank": "citigroup.com", "wells fargo": "wellsfargo.com",
}

# Official email domain patterns for ATS/recruiting platforms
ATS_DOMAINS: Set[str] = {
    "lever.co", "greenhouse.io", "workday.com", "icims.com", "smartrecruiters.com",
    "jobvite.com", "breezy.hr", "bamboohr.com", "freshteam.com", "recruitee.com",
    "ashbyhq.com", "gem.com", "hired.com", "triplebyte.com", "angel.co",
}

FREE_EMAIL_PROVIDERS: Set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "rediffmail.com",
    "protonmail.com", "proton.me", "yandex.com", "yandex.ru", "zoho.com",
    "aol.com", "icloud.com", "me.com", "mac.com", "gmx.com", "mail.com",
    "fastmail.com", "hushmail.com", "tutanota.com", "lycos.com", "rocketmail.com",
    "live.com", "msn.com", "inbox.com", "mail.ru", "163.com", "qq.com",
}

DISPOSABLE_EMAIL_DOMAINS: Set[str] = {
    "temp-mail.org", "guerrillamail.com", "10minutemail.com", "mailinator.com",
    "sharklasers.com", "getnada.com", "dispostable.com", "yopmail.com",
    "throwaway.email", "tempail.com", "trashmail.com", "fakeinbox.com",
    "maildrop.cc", "guerrillamailblock.com", "grr.la", "tempmail.ninja",
    "mohmal.com", "emailondeck.com", "throwawaymail.com",
}

SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "click", "buzz", "site", "online", "club", "work",
    "loan", "biz", "info", "link", "ga", "cf", "tk", "ml", "gq",
    "stream", "download", "racing", "win", "review", "country", "science",
    "party", "date", "faith", "accountant", "cricket", "bid",
}

URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "bl.ink", "short.io",
}

# Scam text tiers with comprehensive phrase banks
SCAM_TEXT_TIERS = {
    "CRITICAL": {
        "penalty": 20,
        "phrases": [
            "processing fee", "wire transfer", "send money", "advance payment",
            "western union", "registration fee", "security deposit",
            "pay before joining", "application fee", "fee required",
            "deposit required", "money order", "bitcoin payment",
            "pay via upi", "pay rs", "transfer amount",
        ]
    },
    "HIGH": {
        "penalty": 12,
        "phrases": [
            "guaranteed income", "100% placement", "money back guarantee",
            "click here to accept", "login to your bank", "guaranteed job",
            "100% job guarantee", "no interview required", "direct hiring",
            "selected for position", "you have been chosen",
            "congratulations you are selected", "offer letter attached",
        ]
    },
    "MEDIUM": {
        "penalty": 7,
        "phrases": [
            "no experience required", "immediate joining", "urgent requirement",
            "limited seats", "act now", "lottery", "prize", "earn from home",
            "work from home earn", "daily payment", "weekly salary",
            "earn lakhs", "earn thousands", "part time job earn",
            "data entry job", "typing job", "copy paste job",
            "form filling job", "sms sending job",
        ]
    },
    "CONTEXTUAL": {
        "penalty": 4,
        "phrases": [
            "whatsapp", "telegram", "connect here", "personal number",
            "contact on whatsapp", "message on telegram",
            "add on whatsapp", "join telegram group",
        ]
    }
}

# High-risk registrars (commonly abused)
HIGH_RISK_REGISTRARS: Set[str] = {
    "namecheap", "namesilo", "dynadot", "porkbun", "hostinger",
    "freenom", "1api", "regery",
}

# Bulletproof hosting ASNs
BULLETPROOF_ASNS: Set[str] = {
    "AS200019", "AS44477", "AS49981", "AS202425", "AS210644",
    "AS209711", "AS57724", "AS60781",
}

# Known scam phone prefixes (Nigeria +234, premium-rate, etc.)
SCAM_PHONE_PREFIXES: Set[str] = {
    "+234", "+233", "+225", "+228", "+221", "+212", "+256",
    "0900", "0901", "0909",  # premium rate
}

# Salary ranges by currency
SALARY_RANGES = {
    "INR": (200000, 5000000),
    "USD": (30000, 300000),
    "default": (200000, 5000000),
}

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 2 — SIGNAL HELPERS & NORMALIZATION
# ═══════════════════════════════════════════════════════════════════════════

def _skip(reason: str) -> dict:
    """Check was skipped (missing data / dependency)."""
    return {"flag": False, "penalty": 0, "reason": reason, "category": "SYSTEM", "confidence": 0.0}

def _flag(penalty: int, reason: str, category: str, confidence: float = 0.85) -> dict:
    """Threat signal detected."""
    return {"flag": True, "penalty": penalty, "reason": reason, "category": category, "confidence": round(confidence, 2)}

def _clean(reason: str, category: str, confidence: float = 0.90) -> dict:
    """Check passed clean."""
    return {"flag": False, "penalty": 0, "reason": reason, "category": category, "confidence": round(confidence, 2)}


def normalize_input(data: dict) -> dict:
    """
    Comprehensive input normalizer — canonicalizes all input fields.
    Handles: job_url, recruiter_email, phone_number, company_claimed,
             salary_offered, offer_text, job_title, job_description,
             location, experience_required
    """
    norm: Dict[str, Any] = {"_raw": dict(data)}

    # ── URL / Domain ──
    job_url = (data.get("job_url") or "").strip()
    norm["job_url"] = job_url
    domain = ""
    if job_url:
        try:
            parsed = urlparse(job_url if "://" in job_url else f"https://{job_url}")
            domain = (parsed.hostname or "").lower().strip(".")
            norm["url_path"] = parsed.path
            norm["url_scheme"] = parsed.scheme
            norm["url_query"] = parsed.query
        except Exception:
            domain = ""
    norm["domain"] = domain

    # Extract SLD (second-level domain) using tldextract or fallback
    if domain and _HAS_TLDEXTRACT:
        try:
            ext = _tldextract.extract(domain)
            norm["sld"] = ext.domain
            norm["tld"] = ext.suffix
            norm["subdomain"] = ext.subdomain
        except Exception:
            parts = domain.rsplit(".", 2)
            norm["sld"] = parts[-2] if len(parts) >= 2 else domain
            norm["tld"] = parts[-1] if len(parts) >= 2 else ""
            norm["subdomain"] = ".".join(parts[:-2]) if len(parts) > 2 else ""
    else:
        parts = domain.rsplit(".", 2) if domain else [""]
        norm["sld"] = parts[-2] if len(parts) >= 2 else domain
        norm["tld"] = parts[-1] if len(parts) >= 2 else ""
        norm["subdomain"] = ".".join(parts[:-2]) if len(parts) > 2 else ""

    # ── Email ──
    email = (data.get("recruiter_email") or "").strip().lower()
    norm["recruiter_email"] = email
    norm["email_domain"] = email.split("@", 1)[1] if "@" in email else ""
    norm["email_local"] = email.split("@", 1)[0] if "@" in email else ""

    # ── Phone ──
    phone = str(data.get("phone_number") or "").strip()
    norm["phone_number"] = phone
    norm["phone_clean"] = re.sub(r"\D", "", phone)
    # Try to parse with phonenumbers
    if phone and _HAS_PHONENUMBERS:
        try:
            parsed_phone = _phonenumbers.parse(phone, "IN")  # default India
            norm["phone_country_code"] = f"+{parsed_phone.country_code}"
            norm["phone_national"] = str(parsed_phone.national_number)
            norm["phone_valid"] = _phonenumbers.is_valid_number(parsed_phone)
            number_type = _phonenumbers.number_type(parsed_phone)
            norm["phone_type"] = str(number_type)
            # VOIP detection
            norm["phone_is_voip"] = number_type == _phonenumbers.PhoneNumberType.VOIP
        except Exception:
            norm["phone_country_code"] = ""
            norm["phone_national"] = norm["phone_clean"]
            norm["phone_valid"] = None
            norm["phone_type"] = "unknown"
            norm["phone_is_voip"] = False
    else:
        norm["phone_country_code"] = ""
        norm["phone_national"] = norm["phone_clean"]
        norm["phone_valid"] = None
        norm["phone_type"] = "unknown"
        norm["phone_is_voip"] = False

    # ── Company ──
    company = (data.get("company_claimed") or "").strip().lower()
    norm["company_claimed"] = data.get("company_claimed", "")
    norm["company"] = company
    norm["canonical_domain"] = CANONICAL_COMPANY_DOMAINS.get(company, "")

    # ── Salary ──
    salary = data.get("salary_offered")
    try:
        norm["salary_offered"] = float(salary) if salary is not None else None
    except (ValueError, TypeError):
        norm["salary_offered"] = None

    # ── Text fields ──
    norm["offer_text"] = (data.get("offer_text") or "").strip()
    norm["job_title"] = (data.get("job_title") or "").strip()
    norm["job_description"] = (data.get("job_description") or "").strip()
    norm["location"] = (data.get("location") or "").strip()

    experience = data.get("experience_required")
    try:
        norm["experience_required"] = float(experience) if experience is not None else None
    except (ValueError, TypeError):
        norm["experience_required"] = None

    # ── Combined text for NLP scanning ──
    norm["_all_text"] = " ".join(filter(None, [
        norm["offer_text"], norm["job_title"], norm["job_description"]
    ])).lower()

    return norm


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 3 — MODULE 01: DOMAIN & WEB INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════

def check_domain_age(data: dict) -> dict:
    """WHOIS domain age analysis with registrar risk scoring."""
    domain = data.get("domain")
    if not domain or not _HAS_WHOIS:
        return _skip("WHOIS unavailable or no domain provided")
    try:
        w = _whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return _skip("No creation date in WHOIS")
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation).days

        # Check expiration — scammers register for exactly 1 year
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        reg_years = None
        if expiration and creation:
            try:
                if expiration.tzinfo is None:
                    expiration = expiration.replace(tzinfo=timezone.utc)
                reg_years = round((expiration - creation).days / 365, 1)
            except Exception:
                pass

        # Registrar risk
        registrar = str(w.registrar or "").lower()
        registrar_risky = any(r in registrar for r in HIGH_RISK_REGISTRARS)

        # WHOIS privacy/masked
        org = str(w.org or "").lower()
        whois_masked = any(kw in org for kw in [
            "privacy", "redacted", "domains by proxy", "whoisguard",
            "contact privacy", "private", "withheld"
        ])

        # Scoring
        if age_days < 7:
            result = _flag(40, f"Domain is brand new ({age_days} days old)", "DOMAIN_RISK", 0.95)
        elif age_days < 30:
            result = _flag(30, f"Domain age < 30 days ({age_days} days)", "DOMAIN_RISK", 0.90)
        elif age_days < 90:
            result = _flag(15, f"Domain age < 90 days ({age_days} days)", "DOMAIN_RISK", 0.75)
        else:
            result = _clean(f"Domain age: {age_days} days ({age_days//365} years)", "DOMAIN_RISK")

        # Bonus penalties
        if registrar_risky and result["flag"]:
            result["penalty"] += 15
            result["reason"] += f" | High-risk registrar: {registrar}"

        if reg_years and reg_years <= 1.0 and age_days < 365:
            result["penalty"] += 5
            result["reason"] += " | Registered for only 1 year (disposable pattern)"

        if whois_masked:
            result["penalty"] += 8
            result["reason"] += " | WHOIS privacy masking enabled"

        return result
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return _skip(f"WHOIS lookup failed: {str(e)[:80]}")


def check_dns_records(data: dict) -> dict:
    """DNS deep analysis: MX, SPF, DMARC, NS record checks."""
    domain = data.get("domain")
    if not domain or not _HAS_DNS:
        return _skip("DNS resolver unavailable or no domain")

    findings = []
    penalty = 0

    try:
        # MX Records
        try:
            mx_records = _dns_resolver.resolve(domain, "MX")
            mx_hosts = [str(r.exchange).lower().rstrip(".") for r in mx_records]
            free_mx = any(
                any(fp in mx for fp in ["google", "yahoo", "outlook", "hotmail"])
                for mx in mx_hosts
            )
            if free_mx:
                penalty += 25
                findings.append(f"MX routes to free email provider ({', '.join(mx_hosts[:2])})")
        except Exception:
            penalty += 5
            findings.append("No MX records found")

        # SPF Record
        try:
            txt_records = _dns_resolver.resolve(domain, "TXT")
            spf_found = False
            spf_open = False
            for r in txt_records:
                txt = str(r).strip('"')
                if txt.startswith("v=spf1"):
                    spf_found = True
                    if "+all" in txt:
                        spf_open = True
                        penalty += 15
                        findings.append("SPF record allows ANY sender (+all) — spoofable")
            if not spf_found:
                penalty += 10
                findings.append("No SPF record — email spoofing possible")
        except Exception:
            penalty += 5
            findings.append("Could not query TXT/SPF records")

        # DMARC
        try:
            dmarc_records = _dns_resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_found = False
            for r in dmarc_records:
                txt = str(r).strip('"')
                if "v=DMARC1" in txt.upper():
                    dmarc_found = True
                    if "p=none" in txt.lower():
                        penalty += 5
                        findings.append("DMARC policy is 'none' — no enforcement")
                    elif "p=reject" in txt.lower():
                        findings.append("DMARC policy is 'reject' — strong protection ✓")
            if not dmarc_found:
                penalty += 8
                findings.append("No DMARC record — email authentication weak")
        except Exception:
            penalty += 5
            findings.append("No DMARC record found")

        # NS Records
        try:
            ns_records = _dns_resolver.resolve(domain, "NS")
            ns_hosts = [str(r).lower().rstrip(".") for r in ns_records]
            # Check for anonymous/free nameservers
            anon_ns = any(
                any(kw in ns for kw in ["freedns", "afraid.org", "he.net"])
                for ns in ns_hosts
            )
            if anon_ns:
                penalty += 10
                findings.append(f"Uses anonymous/free nameservers: {', '.join(ns_hosts[:2])}")
        except Exception:
            pass

        if penalty > 0:
            return _flag(
                min(45, penalty),
                f"DNS issues: {'; '.join(findings)}",
                "DNS_RISK",
                min(0.95, 0.5 + penalty * 0.01)
            )
        return _clean("DNS records look healthy (MX, SPF, DMARC present)", "DNS_RISK")

    except Exception as e:
        return _skip(f"DNS analysis failed: {str(e)[:80]}")


def check_typosquat(data: dict) -> dict:
    """Advanced typosquatting: Levenshtein + homoglyph + TLD hijack + hyphen tricks."""
    domain = data.get("domain", "")
    canonical = data.get("canonical_domain", "")
    company = data.get("company", "")
    sld = data.get("sld", "")

    if not domain or not company:
        return _skip("No domain or company to check")

    # Skip if domain IS the canonical domain or a subdomain of it
    if canonical and (domain == canonical or domain.endswith(f".{canonical}")):
        return _clean(f"Domain '{domain}' is the official '{canonical}' domain", "IMPERSONATION_RISK", 0.95)

    findings = []
    max_penalty = 0

    # 1. Check against canonical domain if known
    if canonical and _HAS_RAPIDFUZZ:
        c_base = canonical.rsplit(".", 1)[0]
        d_base = domain.rsplit(".", 1)[0]
        sim = _fuzz.ratio(d_base, c_base)
        if d_base != c_base and sim > 70:
            max_penalty = max(max_penalty, 35)
            findings.append(f"Typosquatting: '{domain}' is {sim:.0f}% similar to '{canonical}'")

    # 2. Company name in domain but wrong TLD
    if company in sld and canonical and domain != canonical:
        max_penalty = max(max_penalty, 30)
        findings.append(f"Company name '{company}' found in domain but official is '{canonical}'")

    # 3. Homoglyph detection
    HOMOGLYPH_MAP = {
        'o': ['0'], 'l': ['1', 'i'], 'i': ['1', 'l'],
        'a': ['@'], 'e': ['3'], 's': ['5', '$'],
        'g': ['9'], 'rn': ['m'], 'vv': ['w'],
    }
    if canonical:
        c_base = canonical.rsplit(".", 1)[0]
        for real_char, fakes in HOMOGLYPH_MAP.items():
            for fake in fakes:
                homoglyph_domain = c_base.replace(real_char, fake)
                if homoglyph_domain in domain and homoglyph_domain != c_base:
                    max_penalty = max(max_penalty, 40)
                    findings.append(f"Homoglyph substitution: '{real_char}'→'{fake}' in domain")

    # 4. Hyphen insertion (amazon-jobs.com, infosys-career.com)
    if company and len(company) > 3:
        if f"{company}-" in sld or f"-{company}" in sld:
            if canonical and domain != canonical:
                max_penalty = max(max_penalty, 30)
                findings.append(f"Hyphen-stuffed domain: '{domain}' impersonates '{company}'")

    # 5. TLD hijacking: amazon.com.in-jobs.com (but NOT legitimate subdomains like careers.google.com)
    if canonical and canonical in domain and domain != canonical and not domain.endswith(f".{canonical}"):
        max_penalty = max(max_penalty, 45)
        findings.append(f"TLD hijacking: '{domain}' embeds the real domain '{canonical}'")

    # 6. Subdomain abuse: google.com.scamdomain.xyz (but NOT careers.google.com)
    subdomain = data.get("subdomain", "")
    if subdomain and canonical and not domain.endswith(f".{canonical}"):
        c_base = canonical.rsplit(".", 1)[0]
        if c_base in subdomain:
            max_penalty = max(max_penalty, 35)
            findings.append(f"Subdomain abuse: '{subdomain}.{domain}' impersonates '{canonical}'")

    if findings:
        return _flag(
            min(50, max_penalty),
            f"Impersonation detected: {'; '.join(findings)}",
            "IMPERSONATION_RISK",
            min(0.98, 0.7 + max_penalty * 0.005)
        )
    return _clean("No typosquatting or impersonation detected", "IMPERSONATION_RISK")


def check_url_structure(data: dict) -> dict:
    """URL structure analysis: shorteners, suspicious TLDs, raw IPs, long paths."""
    url = data.get("job_url", "")
    domain = data.get("domain", "")
    if not domain:
        return _skip("No URL provided")

    findings = []
    penalty = 0

    # URL shortener
    if domain in URL_SHORTENERS:
        penalty += 15
        findings.append(f"Uses URL shortener ({domain}) — hides real destination")

    # Suspicious TLD
    tld = data.get("tld", domain.split(".")[-1] if "." in domain else "")
    if tld in SUSPICIOUS_TLDS:
        penalty += 10
        findings.append(f"Suspicious TLD (.{tld}) commonly used in scams")

    # Raw IP address
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        penalty += 25
        findings.append("URL uses raw IP address instead of domain name")

    # Very long URL path (phishing indicator)
    path = data.get("url_path", "")
    if len(path) > 100:
        penalty += 5
        findings.append("Unusually long URL path (potential phishing)")

    # HTTP (no S)
    scheme = data.get("url_scheme", "")
    if scheme == "http":
        penalty += 10
        findings.append("URL uses HTTP instead of HTTPS — no encryption")

    # Excessive subdomains
    subdomain = data.get("subdomain", "")
    if subdomain and subdomain.count(".") >= 2:
        penalty += 15
        findings.append(f"Excessive subdomains: {subdomain}")

    # URL contains suspicious keywords
    url_lower = url.lower()
    sus_keywords = ["login", "verify", "secure", "update", "confirm", "account", "banking"]
    url_keyword_hits = [kw for kw in sus_keywords if kw in url_lower]
    if url_keyword_hits:
        penalty += 10
        findings.append(f"URL contains suspicious keywords: {', '.join(url_keyword_hits)}")

    if penalty > 0:
        return _flag(min(40, penalty), f"URL risks: {'; '.join(findings)}", "URL_RISK", min(0.90, 0.5 + penalty * 0.01))
    return _clean("URL structure looks legitimate", "URL_RISK")


def check_ssl(data: dict) -> dict:
    """SSL certificate analysis: issuer, age, SANs count."""
    domain = data.get("domain")
    if not domain:
        return _skip("No domain for SSL check")
    # Skip IP addresses
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        return _flag(15, "Cannot verify SSL on raw IP", "INFRASTRUCTURE_RISK", 0.70)

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

        findings = []
        penalty = 0

        # Issuer analysis
        issuer_parts = cert.get("issuer", [])
        issuer_org = ""
        for part in issuer_parts:
            for key, value in part:
                if key == "organizationName":
                    issuer_org = value.lower()

        auto_ssl = ["let's encrypt", "zerossl", "buypass", "ssl.com free"]
        if any(f in issuer_org for f in auto_ssl):
            penalty += 10
            findings.append(f"Uses free/automated SSL (Issuer: {issuer_org})")

        # Certificate age (was it just issued?)
        not_before = cert.get("notBefore")
        if not_before:
            try:
                issued_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                issued_date = issued_date.replace(tzinfo=timezone.utc)
                cert_age_days = (datetime.now(timezone.utc) - issued_date).days
                if cert_age_days < 7:
                    penalty += 15
                    findings.append(f"SSL certificate issued only {cert_age_days} days ago")
            except Exception:
                pass

        # SAN count (too many unrelated domains = suspicious, but big companies have many SANs)
        sans = cert.get("subjectAltName", [])
        if len(sans) > 200:
            penalty += 10
            findings.append(f"Certificate covers {len(sans)} domains - shared/cheap cert")

        # EV certificate check (from issuer org)
        ev_issuers = ["digicert", "comodo", "sectigo", "globalsign", "entrust", "symantec"]
        is_ev = any(ev in issuer_org for ev in ev_issuers)
        if is_ev:
            findings.append("Extended Validation (EV) certificate detected ✓")

        if penalty > 0:
            return _flag(min(30, penalty), f"SSL concerns: {'; '.join(findings)}", "INFRASTRUCTURE_RISK", 0.75)
        reason = f"Valid SSL from {issuer_org}" if issuer_org else "Valid SSL certificate"
        if findings:
            reason += f" | {'; '.join(findings)}"
        return _clean(reason, "INFRASTRUCTURE_RISK")

    except socket.timeout:
        return _flag(15, "SSL connection timed out", "INFRASTRUCTURE_RISK", 0.65)
    except ssl.SSLCertVerificationError as e:
        return _flag(25, f"SSL certificate verification failed: {str(e)[:60]}", "INFRASTRUCTURE_RISK", 0.90)
    except Exception:
        return _flag(20, "Missing or invalid SSL certificate", "INFRASTRUCTURE_RISK", 0.80)


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 4 — MODULE 02: NETWORK & INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════

def check_ip_geolocation(data: dict) -> dict:
    """IP geolocation mismatch detection."""
    domain = data.get("domain")
    company = data.get("company", "")
    location = data.get("location", "").lower()

    if not domain:
        return _skip("No domain for IP geo check")

    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return _skip("Could not resolve domain to IP")

    # Try GeoIP2 first (offline, fast)
    if _HAS_GEOIP2:
        try:
            reader = _geoip2_db.Reader("GeoLite2-City.mmdb")
            resp = reader.city(ip)
            country = resp.country.name or "Unknown"
            city = resp.city.name or "Unknown"
            reader.close()

            # Check mismatch
            india_companies = {"tcs", "infosys", "wipro", "flipkart", "paytm", "jio", "reliance", "swiggy", "zomato", "ola"}
            if company in india_companies and country.lower() not in ["india", "united states", "singapore"]:
                return _flag(25, f"IP geo mismatch: {company} claims India but resolves to {country} ({city})", "INFRASTRUCTURE_RISK", 0.80)

            return _clean(f"IP resolves to {city}, {country}", "INFRASTRUCTURE_RISK")
        except Exception:
            pass

    # Fallback: use ipwhois
    if _HAS_IPWHOIS:
        try:
            from ipwhois import IPWhois
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=0)
            asn_desc = results.get("asn_description", "")
            country = results.get("asn_country_code", "??")

            # Check for bulletproof hosting
            asn = f"AS{results.get('asn', '')}"
            if asn in BULLETPROOF_ASNS:
                return _flag(35, f"IP hosted on bulletproof hosting ASN ({asn}: {asn_desc})", "INFRASTRUCTURE_RISK", 0.95)

            return _clean(f"IP: {ip} | ASN: {asn_desc} | Country: {country}", "INFRASTRUCTURE_RISK")
        except Exception:
            pass

    # Ultimate fallback — just report the IP
    return _clean(f"Resolved IP: {ip} (geo lookup unavailable)", "INFRASTRUCTURE_RISK", 0.30)


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 5 — MODULE 03: EMAIL INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════

def check_email_validity(data: dict) -> dict:
    """Comprehensive email intelligence: free provider, disposable, brand stuffing, ATS."""
    email = data.get("recruiter_email", "")
    domain_part = data.get("email_domain", "")
    local_part = data.get("email_local", "")
    company = data.get("company", "")

    if not domain_part:
        return _skip("No recruiter email provided")

    findings = []
    penalty = 0

    # 1. Disposable email (highest risk)
    if domain_part in DISPOSABLE_EMAIL_DOMAINS:
        return _flag(45, f"Uses disposable/throwaway email domain: {domain_part}", "EMAIL_RISK", 0.98)

    # 2. ATS domain (allowlisted — reduce penalty)
    if domain_part in ATS_DOMAINS:
        return _clean(f"Email sent via known ATS platform: {domain_part}", "EMAIL_RISK", 0.85)

    # 3. Free email provider
    if domain_part in FREE_EMAIL_PROVIDERS:
        penalty += 20
        findings.append(f"Uses free email provider ({domain_part})")

        # Brand stuffing: hr.google@gmail.com
        if company and len(company) > 3 and company in local_part:
            penalty += 20
            findings.append(f"Brand stuffing: '{company}' in local part of free email ({email})")

        # Professional name format mitigation (firstname.lastname@gmail.com)
        if re.match(r"^[a-z]+\.[a-z]+$", local_part):
            penalty = max(penalty - 5, 15)  # Cap penalty reduction
            findings.append("Professional name format detected — slightly reduced risk")

    # 4. Company domain mismatch
    canonical = data.get("canonical_domain", "")
    if canonical and domain_part != canonical and domain_part not in ATS_DOMAINS:
        if domain_part not in FREE_EMAIL_PROVIDERS:
            penalty += 15
            findings.append(f"Email domain '{domain_part}' doesn't match company's official '{canonical}'")

    # 5. Suspicious local part patterns
    if local_part:
        if re.match(r"^[a-z]{1,3}\d{3,}$", local_part):
            penalty += 10
            findings.append(f"Suspicious email username pattern: {local_part}")
        if len(local_part) > 30:
            penalty += 5
            findings.append("Unusually long email local part")

    if penalty > 0:
        return _flag(
            min(50, penalty),
            f"Email risks: {'; '.join(findings)}",
            "EMAIL_RISK",
            min(0.95, 0.6 + penalty * 0.008)
        )
    return _clean(f"Email domain {domain_part} appears legitimate", "EMAIL_RISK")


def check_email_domain_dns(data: dict) -> dict:
    """Verify email domain has proper MX and SPF records."""
    email_domain = data.get("email_domain", "")
    if not email_domain or not _HAS_DNS:
        return _skip("No email domain or DNS unavailable")

    if email_domain in FREE_EMAIL_PROVIDERS or email_domain in ATS_DOMAINS:
        return _clean(f"Known provider {email_domain} — DNS check not needed", "EMAIL_DNS_RISK")

    findings = []
    penalty = 0

    try:
        # Check MX
        try:
            mx = _dns_resolver.resolve(email_domain, "MX")
            if not mx:
                penalty += 15
                findings.append("Email domain has no MX records")
        except Exception:
            penalty += 15
            findings.append("Email domain has no MX records — can't receive email")

        # Check SPF
        try:
            txt = _dns_resolver.resolve(email_domain, "TXT")
            spf_found = any("v=spf1" in str(r) for r in txt)
            if not spf_found:
                penalty += 8
                findings.append("Email domain has no SPF record")
        except Exception:
            penalty += 5
            findings.append("Could not verify email domain TXT records")

        if penalty > 0:
            return _flag(min(25, penalty), f"Email DNS: {'; '.join(findings)}", "EMAIL_DNS_RISK", 0.70)
        return _clean("Email domain DNS records are properly configured", "EMAIL_DNS_RISK")

    except Exception:
        return _skip("Email domain DNS check failed")


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 6 — MODULE 04: PHONE INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════

def check_phone_validity(data: dict) -> dict:
    """Phone intelligence: VOIP, country mismatch, scam patterns, repeated digits."""
    phone = data.get("phone_number", "")
    phone_clean = data.get("phone_clean", "")
    company = data.get("company", "")

    if not phone_clean or len(phone_clean) < 5:
        return _skip("No phone number provided")

    findings = []
    penalty = 0

    # 1. Basic length validation
    if len(phone_clean) < 8:
        penalty += 15
        findings.append(f"Invalid phone number length ({len(phone_clean)} digits)")
    elif len(phone_clean) > 15:
        penalty += 10
        findings.append(f"Unusually long phone number ({len(phone_clean)} digits)")

    # 2. Repeated digits (9999999999)
    if len(set(phone_clean)) <= 2:
        penalty += 25
        findings.append("Phone number has suspicious repeated digits")
    elif len(set(phone_clean)) <= 3 and len(phone_clean) >= 8:
        penalty += 10
        findings.append("Phone number has very low digit diversity")

    # 3. Sequential numbers
    if any(seq in phone_clean for seq in ["123456", "654321", "111111", "000000"]):
        penalty += 15
        findings.append("Phone number contains sequential/repeating patterns")

    # 4. VOIP detection (via phonenumbers library)
    if data.get("phone_is_voip"):
        penalty += 20
        findings.append("VOIP number detected — commonly used in scams")

    # 5. Phone validity (via phonenumbers)
    if data.get("phone_valid") is False:
        penalty += 15
        findings.append("Phone number failed validation (invalid format)")

    # 6. Country mismatch
    phone_country = data.get("phone_country_code", "")
    if phone_country:
        for prefix in SCAM_PHONE_PREFIXES:
            if phone.startswith(prefix) or phone_country == prefix:
                penalty += 20
                findings.append(f"Phone prefix {prefix} is high-risk")
                break

        # India company but non-India phone
        india_cos = {"tcs", "infosys", "wipro", "flipkart", "paytm", "reliance", "swiggy", "zomato"}
        if company in india_cos and phone_country not in ["+91", ""]:
            penalty += 15
            findings.append(f"Phone country ({phone_country}) doesn't match Indian company")

    # 7. Premium rate numbers
    if phone_clean[:4] in ["0900", "0901", "0909", "1900", "1976"]:
        penalty += 30
        findings.append("Premium-rate phone number detected")

    if penalty > 0:
        return _flag(
            min(45, penalty),
            f"Phone risks: {'; '.join(findings)}",
            "CONTACT_RISK",
            min(0.95, 0.5 + penalty * 0.01)
        )
    return _clean("Phone number passes validation", "CONTACT_RISK")


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 7 — MODULE 05: CONTENT & TEXT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def check_offer_text(data: dict) -> dict:
    """Deep text analysis: scam phrases, urgency signals, shouting, suspicious patterns."""
    text = data.get("_all_text", "")
    raw_text = data.get("offer_text", "") + " " + data.get("job_description", "")
    if not text:
        return _skip("No text provided for analysis")

    findings = []
    total_penalty = 0

    # 1. Tiered phrase matching
    for tier, config in SCAM_TEXT_TIERS.items():
        hits = [p for p in config["phrases"] if p in text]
        if hits:
            # Diminishing returns for multiple hits in same tier
            tier_penalty = config["penalty"] * (1 + (len(hits) - 1) * 0.15)
            total_penalty += tier_penalty
            findings.append(f"{tier}: {', '.join(hits[:3])}")

    # 2. Urgency heuristics
    shouting = len(re.findall(r"[A-Z]{5,}", raw_text))
    exclamation = raw_text.count("!")
    if shouting > 3:
        total_penalty += 10
        findings.append(f"Excessive SHOUTING ({shouting} instances)")
    if exclamation > 5:
        total_penalty += 5
        findings.append(f"Excessive exclamation marks ({exclamation})")

    # 3. Currency/payment patterns
    payment_patterns = [
        r"(?:rs\.?|inr|₹)\s*\d{2,}",
        r"\$\s*\d{2,}",
        r"pay\s+(?:rs\.?|inr|₹|\$)\s*\d+",
        r"transfer\s+(?:rs\.?|inr|₹|\$)\s*\d+",
        r"(?:upi|neft|rtgs|imps)\s+(?:transfer|payment)",
    ]
    payment_hits = sum(1 for p in payment_patterns if re.search(p, text, re.IGNORECASE))
    if payment_hits >= 2:
        total_penalty += 15
        findings.append(f"Multiple payment-related patterns found ({payment_hits})")

    # 4. Grammar red flags (common in scam texts)
    grammar_flags = [
        r"dear\s+(?:sir|madam|candidate|applicant)",
        r"kindly\s+(?:do\s+the\s+needful|revert|confirm)",
        r"we\s+are\s+pleased\s+to\s+(?:inform|announce)",
        r"your\s+(?:resume|cv|profile)\s+(?:has\s+been\s+)?(?:shortlisted|selected)",
    ]
    grammar_hits = sum(1 for p in grammar_flags if re.search(p, text, re.IGNORECASE))
    if grammar_hits >= 2:
        total_penalty += 8
        findings.append("Multiple generic/templated phrases detected")

    # 5. Contact method red flags
    personal_contact = re.findall(
        r"(?:call|contact|message|reach)\s+(?:me|us)\s+(?:at|on)\s+(?:\d|whatsapp|telegram)",
        text, re.IGNORECASE
    )
    if personal_contact:
        total_penalty += 8
        findings.append("Directs to personal contact channels")

    if total_penalty > 0:
        return _flag(
            int(min(50, total_penalty)),
            f"Text analysis: {'; '.join(findings[:5])}",
            "CONTENT_RISK",
            min(0.95, 0.5 + total_penalty * 0.008)
        )
    return _clean("Text content analysis passed — no obvious scam patterns", "CONTENT_RISK")


def check_salary_anomaly(data: dict) -> dict:
    """Salary anomaly detection with currency awareness and role context."""
    salary = data.get("salary_offered")
    if salary is None:
        return _skip("No salary provided")

    company = data.get("company", "")
    text = data.get("_all_text", "")
    job_title = data.get("job_title", "").lower()

    # Detect currency — check salary magnitude too
    is_usd = "$" in text or "usd" in text or "dollar" in text
    # If salary < 500000, it's likely USD (no one earns < 5 LPA in INR for a corporate job)
    if is_usd or (salary < 500000 and salary > 0):
        lo, hi = SALARY_RANGES["USD"]
    else:
        lo, hi = SALARY_RANGES["INR"]

    findings = []
    penalty = 0

    # Big tech companies have higher salary ranges
    big_tech = {"google", "microsoft", "amazon", "apple", "meta", "facebook", "netflix", "uber", "stripe"}
    if company in big_tech:
        hi = hi * 3

    # Entry level roles should have lower max
    entry_keywords = ["intern", "fresher", "entry level", "trainee", "junior", "associate"]
    is_entry = any(kw in job_title for kw in entry_keywords)
    if is_entry:
        hi = hi * 0.5

    if salary > hi:
        penalty += 25
        findings.append(f"Salary ({salary:,.0f}) significantly above market max ({hi:,.0f})")

    if salary < lo and salary > 0:
        penalty += 5
        findings.append(f"Salary ({salary:,.0f}) below typical market range")

    # Round number check (scammers love flat numbers)
    if salary > 10000 and salary % 100000 == 0:
        penalty += 5
        findings.append("Salary is an exact round number (common in scam postings)")

    # Ratio check for experience
    experience = data.get("experience_required")
    if experience is not None and experience == 0 and salary > 1500000:
        penalty += 15
        findings.append("High salary with zero experience requirement — suspicious")

    if penalty > 0:
        return _flag(min(35, penalty), f"Salary analysis: {'; '.join(findings)}", "OFFER_RISK", 0.80)
    return _clean(f"Salary ({salary:,.0f}) within expected range", "OFFER_RISK")


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 8 — MODULE 06: OSINT & WEB PRESENCE (light checks)
# ═══════════════════════════════════════════════════════════════════════════

def check_domain_reputation(data: dict) -> dict:
    """Basic domain reputation via DNS-based blocklist checks (IP-based only, not domain-based)."""
    domain = data.get("domain", "")
    if not domain:
        return _skip("No domain for reputation check")

    # Skip URL shorteners — they always hit blocklists
    if domain in URL_SHORTENERS:
        return _skip("URL shortener — skipping blocklist check (handled by URL check)")

    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return _skip("Could not resolve domain IP for reputation check")

    # Skip private/reserved IPs
    if ip.startswith(("10.", "172.16.", "192.168.", "127.")):
        return _skip("Private/reserved IP — skipping blocklist check")

    # IP-based DNSBL checks only (NOT domain-based like dbl.spamhaus.org which gives false positives)
    blocklists = [
        ("zen.spamhaus.org", "Spamhaus ZEN"),
        ("multi.surbl.org", "SURBL"),
    ]

    hits = []
    for bl_domain, bl_name in blocklists:
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            query = f"{reversed_ip}.{bl_domain}"
            socket.gethostbyname(query)
            hits.append(bl_name)
        except socket.gaierror:
            pass  # Not listed = good
        except Exception:
            pass

    if hits:
        return _flag(40, f"Domain/IP listed on blocklists: {', '.join(hits)}", "REPUTATION_RISK", 0.95)
    return _clean("Domain not found on major blocklists", "REPUTATION_RISK", 0.60)


def check_company_domain_crossref(data: dict) -> dict:
    """Cross-reference: does the job URL domain match the company's official domain?"""
    domain = data.get("domain", "")
    canonical = data.get("canonical_domain", "")
    company = data.get("company", "")

    if not domain or not company:
        return _skip("No domain or company for cross-reference")

    if not canonical:
        # Unknown company — can't verify, but not a red flag
        return _clean(f"Company '{company}' not in our known-company database", "CROSSREF_RISK", 0.30)

    # Exact match
    if domain == canonical or domain.endswith(f".{canonical}"):
        return _clean(f"Domain '{domain}' matches official company domain '{canonical}' ✓", "CROSSREF_RISK", 0.95)

    # Different domain entirely
    return _flag(
        30,
        f"Domain mismatch: job posted on '{domain}' but {data.get('company_claimed', company)}'s official domain is '{canonical}'",
        "CROSSREF_RISK",
        0.85
    )


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 9 — CHECK REGISTRY & CORRELATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

CHECK_REGISTRY = [
    # Module 01 — Domain Intelligence
    {"name": "domain_age",        "field": "job_url",          "func": check_domain_age,          "module": "domain_intel"},
    {"name": "dns_records",       "field": "job_url",          "func": check_dns_records,         "module": "domain_intel"},
    {"name": "typosquat",         "field": "job_url",          "func": check_typosquat,           "module": "domain_intel"},
    {"name": "url_structure",     "field": "job_url",          "func": check_url_structure,       "module": "domain_intel"},
    {"name": "ssl",               "field": "job_url",          "func": check_ssl,                 "module": "domain_intel"},
    # Module 02 — Network & Infrastructure
    {"name": "ip_geolocation",    "field": "job_url",          "func": check_ip_geolocation,      "module": "network_infra"},
    # Module 03 — Email Intelligence
    {"name": "email_validity",    "field": "recruiter_email",  "func": check_email_validity,      "module": "email_intel"},
    {"name": "email_domain_dns",  "field": "recruiter_email",  "func": check_email_domain_dns,    "module": "email_intel"},
    # Module 04 — Phone Intelligence
    {"name": "phone_validity",    "field": "phone_number",     "func": check_phone_validity,      "module": "phone_intel"},
    # Module 05 — Content Analysis
    {"name": "offer_text",        "field": "offer_text",       "func": check_offer_text,          "module": "content_analysis"},
    {"name": "salary_anomaly",    "field": "salary_offered",   "func": check_salary_anomaly,      "module": "content_analysis"},
    # Module 06 — OSINT
    {"name": "domain_reputation", "field": "job_url",          "func": check_domain_reputation,   "module": "osint"},
    {"name": "company_crossref",  "field": "job_url",          "func": check_company_domain_crossref, "module": "osint"},
]

# Correlation rules: when multiple weak signals co-occur, amplify
CORRELATION_RULES = [
    ({"email_validity", "domain_age"},           25, "Coordinated: new domain + suspicious email"),
    ({"typosquat", "ssl"},                       20, "Impersonation: typosquatting domain with automated SSL"),
    ({"salary_anomaly", "offer_text"},           15, "Bait: unrealistic salary combined with scammy text"),
    ({"url_structure", "offer_text"},            15, "Suspicious URL + scam text patterns"),
    ({"email_validity", "phone_validity"},       15, "Both contact channels are suspicious"),
    ({"domain_age", "dns_records"},              20, "New domain with poor DNS infrastructure"),
    ({"typosquat", "company_crossref"},          25, "Typosquatting + domain doesn't match company"),
    ({"offer_text", "email_validity", "domain_age"}, 30, "Triple threat: scam text + bad email + new domain"),
    ({"phone_validity", "email_validity", "offer_text"}, 25, "All contact + content checks flagged"),
]

# Hard override conditions — instant SCAM verdict
HARD_OVERRIDE_CONDITIONS = [
    ({"domain_reputation"},                           "Domain found on threat intelligence blocklist"),
    ({"offer_text", "domain_age", "email_validity"},  "Payment language + new domain + free email = confirmed scam pattern"),
]


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 10 — ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def analyze(data: dict) -> dict:
    """
    Main analysis engine.
    Runs all checks in parallel, applies correlation rules, hard overrides,
    computes confidence, generates human-readable output.
    """
    norm = normalize_input(data)
    results = []
    errors = []

    # Run all checks in parallel
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {}
        for check in CHECK_REGISTRY:
            future = pool.submit(_safe_run_check, check["func"], norm)
            futures[future] = check

        for f in as_completed(futures):
            check_info = futures[f]
            try:
                res = f.result()
                res["check"] = check_info["name"]
                res["field"] = check_info["field"]
                res["module"] = check_info["module"]
                results.append(res)
            except Exception as e:
                errors.append({"check": check_info["name"], "error": str(e)})
                results.append({
                    "check": check_info["name"],
                    "field": check_info["field"],
                    "module": check_info["module"],
                    **_skip(f"Check failed: {str(e)[:60]}")
                })

    # ── Weighted penalty calculation ──
    weighted_penalty = sum(
        r["penalty"] * r.get("confidence", 1.0)
        for r in results
        if r.get("confidence", 0) > 0
    )

    # ── Correlation engine ──
    flagged_checks = {r["check"] for r in results if r["flag"]}
    correlations = []
    for required_checks, bonus_penalty, reason in CORRELATION_RULES:
        if required_checks.issubset(flagged_checks):
            trigger_results = [r for r in results if r["check"] in required_checks]
            avg_conf = statistics.mean([r["confidence"] for r in trigger_results]) if trigger_results else 0.5
            corr_penalty = bonus_penalty * avg_conf
            correlations.append({
                "penalty": round(corr_penalty, 1),
                "reason": reason,
                "triggered_by": list(required_checks),
                "confidence": round(avg_conf, 2)
            })
            weighted_penalty += corr_penalty

    # ── Hard overrides ──
    hard_override = False
    hard_override_reasons = []
    for required_checks, reason in HARD_OVERRIDE_CONDITIONS:
        if required_checks.issubset(flagged_checks):
            hard_override = True
            hard_override_reasons.append(reason)

    # ── Final score ──
    raw_score = max(0, 100 - weighted_penalty)

    # Low-coverage amplification: when most checks were skipped but flags exist,
    # the few signals we DO have should weigh more heavily.
    active_checks = [r for r in results if r.get("confidence", 0) > 0]
    skipped_checks = [r for r in results if r.get("category") == "SYSTEM"]
    coverage_ratio = len(active_checks) / len(CHECK_REGISTRY) if CHECK_REGISTRY else 1

    if coverage_ratio < 0.35 and flagged_checks:
        # Scale up: if only 2/13 checks ran but both flagged, the risk is higher than raw math shows
        amplification = min(2.0, 1.0 + (1 - coverage_ratio))
        raw_score = max(0, 100 - (weighted_penalty * amplification))

    if hard_override:
        final_score = min(int(raw_score), 15)
    else:
        final_score = int(raw_score)

    # ── Verdict ──
    if final_score >= 70:
        verdict, risk = "VERIFIED", "LOW"
    elif final_score >= 40:
        verdict, risk = "SUSPICIOUS", "MEDIUM"
    else:
        verdict, risk = "SCAM", "CRITICAL"

    if hard_override:
        verdict = "SCAM"
        risk = "CRITICAL"

    # ── Confidence calculation ──
    active_confidences = [r["confidence"] for r in results if r["confidence"] > 0]
    base_confidence = statistics.mean(active_confidences) if active_confidences else 0
    coverage = len(active_confidences) / len(CHECK_REGISTRY)
    final_confidence = round(base_confidence * 0.8 + coverage * 0.2, 2)

    # ── Per-field analysis ──
    field_sums: Dict[str, float] = {}
    for r in results:
        f = r["field"]
        field_sums[f] = field_sums.get(f, 0) + r["penalty"]
    field_analysis = {
        f: {
            "total_penalty": int(s),
            "risk": "CRITICAL" if s > 40 else "HIGH" if s > 25 else "MEDIUM" if s > 10 else "LOW"
        }
        for f, s in field_sums.items()
    }

    # ── Per-module analysis ──
    module_sums: Dict[str, Dict] = {}
    for r in results:
        mod = r.get("module", "unknown")
        if mod not in module_sums:
            module_sums[mod] = {"penalty": 0, "flags": 0, "checks": 0}
        module_sums[mod]["penalty"] += r["penalty"]
        module_sums[mod]["flags"] += 1 if r["flag"] else 0
        module_sums[mod]["checks"] += 1

    # ── Human-readable reasons ──
    reasons = [r["reason"] for r in results if r["flag"]]
    reasons += [c["reason"] for c in correlations]
    if hard_override_reasons:
        reasons = [f"[!!] HARD OVERRIDE: {r}" for r in hard_override_reasons] + reasons

    # ── Recommendations ──
    recommendations = []
    if risk != "LOW":
        recommendations.append("Do not share personal identifiable information (PII)")
    if "salary_anomaly" in flagged_checks:
        recommendations.append("Verify typical market salary for this role on Glassdoor/LinkedIn")
    if "email_validity" in flagged_checks:
        recommendations.append("Verify the recruiter's email matches the official company domain")
    if "phone_validity" in flagged_checks:
        recommendations.append("Cross-check the phone number on Truecaller or official company contacts")
    if "domain_age" in flagged_checks:
        recommendations.append("Check how long this website has been active — scam sites are usually < 30 days old")
    if "typosquat" in flagged_checks or "company_crossref" in flagged_checks:
        recommendations.append("Visit the company's official website directly to verify this job posting")
    if risk in ["HIGH", "CRITICAL"]:
        recommendations.append("Report this posting to the platform and do NOT click any further links")
    if "offer_text" in flagged_checks:
        recommendations.append("Never pay any fees for job applications — legitimate companies do not charge candidates")

    # ── Build report ──
    report = {
        "verdict": verdict,
        "overall_score": final_score,
        "overall_risk": risk,
        "confidence": final_confidence,
        "hard_override": hard_override,
        "summary": _generate_summary(verdict, risk, final_score, len(flagged_checks), final_confidence),
        "reasons": reasons,
        "recommendations": recommendations,
        "field_analysis": field_analysis,
        "module_analysis": module_sums,
        "correlations": correlations,
        "signals": results,
        "errors": errors,
        "metadata": {
            "version": "3.0.0",
            "engine": "ScamShield Cyber Layer",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks_executed": len(results),
            "checks_flagged": len(flagged_checks),
            "checks_skipped": sum(1 for r in results if r["category"] == "SYSTEM"),
            "correlation_triggers": len(correlations),
        }
    }
    return report


def _safe_run_check(func, data: dict) -> dict:
    """Wrapper to ensure checks never crash the engine."""
    try:
        return func(data)
    except Exception as e:
        logger.error(f"Check {func.__name__} crashed: {e}")
        return _skip(f"Check crashed: {str(e)[:60]}")


def _generate_summary(verdict: str, risk: str, score: int, flag_count: int, confidence: float) -> str:
    """Generate human-readable summary for the report."""
    if verdict == "SCAM":
        return (
            f"[!!] HIGH ALERT: ScamShield identified {flag_count} threat signals with {confidence:.0%} confidence. "
            f"Trust score is {score}/100 (CRITICAL risk). This posting is very likely a scam. "
            f"Do NOT share personal information or make any payments."
        )
    elif verdict == "SUSPICIOUS":
        return (
            f"[!] CAUTION: ScamShield detected {flag_count} warning signals. "
            f"Trust score is {score}/100 (MEDIUM risk). "
            f"Verify this posting independently before engaging further."
        )
    else:
        return (
            f"[OK] This posting appears legitimate. Trust score is {score}/100 with {confidence:.0%} confidence. "
            f"Standard caution is still recommended."
        )


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 11 — INTEGRATION API (for main.py)
# ═══════════════════════════════════════════════════════════════════════════

def run_cyber_checks(
    job_url: str = "",
    recruiter_email: str = "",
    company_claimed: str = "",
    salary_offered: float = 0,
    offer_text: str = "",
    phone_number: str = "",
    job_title: str = "",
    job_description: str = "",
    location: str = "",
    experience_required: float = None,
) -> dict:
    """
    Main integration point for FastAPI main.py.
    Accepts all possible input fields.
    Returns the full analysis report.
    """
    input_data = {
        "job_url": job_url,
        "recruiter_email": recruiter_email,
        "company_claimed": company_claimed,
        "salary_offered": salary_offered,
        "offer_text": offer_text,
        "phone_number": phone_number,
        "job_title": job_title,
        "job_description": job_description,
        "location": location,
        "experience_required": experience_required,
    }
    return analyze(input_data)


# ═══════════════════════════════════════════════════════════════════════════
#  SMOKE TEST
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    from json import dumps

    print("=" * 70)
    print("  ScamShield Cyber Layer v3.0.0 — Smoke Test")
    print("=" * 70)

    # Test 1: Obvious scam
    scam_sample = {
        "job_url": "https://bit.ly/google-careers-apply",
        "company_claimed": "Google",
        "recruiter_email": "hr.google.official@gmail.com",
        "phone_number": "9999999999",
        "salary_offered": 15000000,
        "offer_text": "CONGRATULATIONS! You have been SELECTED! Pay processing fee of Rs.5000 via UPI. Immediate joining! Act NOW! WhatsApp us at 9876543210. Registration fee required.",
        "job_title": "Senior Software Engineer",
        "location": "Bangalore",
        "experience_required": 0,
    }

    print("\n--- TEST 1: OBVIOUS SCAM ---")
    report = analyze(scam_sample)
    print(f"Verdict: {report['verdict']} | Score: {report['overall_score']}/100 | Risk: {report['overall_risk']}")
    print(f"Confidence: {report['confidence']:.0%}")
    print(f"Summary: {report['summary']}")
    print(f"Reasons ({len(report['reasons'])}):")
    for r in report['reasons']:
        print(f"  → {r}")
    print(f"Recommendations:")
    for r in report['recommendations']:
        print(f"  → {r}")

    # Test 2: Legitimate posting
    legit_sample = {
        "job_url": "https://careers.google.com/jobs/results/123456",
        "company_claimed": "Google",
        "recruiter_email": "recruiter@google.com",
        "phone_number": "+14155551234",
        "salary_offered": 180000,
        "offer_text": "We are excited to extend this offer for the position of Software Engineer at Google. Please review the attached compensation details and benefits package.",
        "job_title": "Software Engineer L4",
        "location": "Mountain View, CA",
        "experience_required": 3,
    }

    print("\n\n--- TEST 2: LEGITIMATE POSTING ---")
    report2 = analyze(legit_sample)
    print(f"Verdict: {report2['verdict']} | Score: {report2['overall_score']}/100 | Risk: {report2['overall_risk']}")
    print(f"Confidence: {report2['confidence']:.0%}")
    print(f"Summary: {report2['summary']}")
    print(f"Reasons ({len(report2['reasons'])}):")
    for r in report2['reasons']:
        print(f"  → {r}")
