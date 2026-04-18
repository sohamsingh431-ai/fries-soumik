"""
ScamShield Engine — Test Suite
================================
Runs two batches of test cases against the live API:
  • LEGIT  — real job postings from genuine companies
  • SCAM   — fabricated fraudulent offers

Usage:
    # Server must be running first:
    #   uvicorn main:app --reload
    python run_tests.py
"""

import sys
import requests

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT  = 30

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

LEGIT_CASES = [
    {
        "label":            "Infosys — Software Engineer",
        "expected_verdicts": {"SAFE", "REVIEW"},
        "payload": {
            "job_url":         "https://www.infosys.com/careers/job-listing/software-engineer-2024.html",
            "recruiter_email": "talent.acquisition@infosys.com",
            "company_claimed": "Infosys",
            "phone_number":    "",
            "salary_offered":  700000,
            "offer_text": (
                "Infosys is hiring Software Engineers (0-2 years experience) for our Bengaluru "
                "and Pune offices. Candidates must clear our online assessment and two interview "
                "rounds. No fees required at any stage of recruitment. Apply through the official "
                "Infosys careers portal only. Relocation support provided."
            ),
        },
    },
    {
        "label":            "Wipro — Business Analyst",
        "expected_verdicts": {"SAFE", "REVIEW"},
        "payload": {
            "job_url":         "https://careers.wipro.com/job/bangalore/business-analyst/123456",
            "recruiter_email": "wipro.ta@wipro.com",
            "company_claimed": "Wipro",
            "phone_number":    "",
            "salary_offered":  850000,
            "offer_text": (
                "Wipro Limited is looking for a Business Analyst with 2-4 years of experience in "
                "process documentation and stakeholder management. Role based in Hyderabad. "
                "Candidates will undergo HR screening, aptitude test, and two technical interviews. "
                "Wipro never charges candidates any fee during hiring."
            ),
        },
    },
    {
        "label":            "Razorpay — Data Scientist (LinkedIn)",
        "expected_verdicts": {"SAFE", "REVIEW"},
        "payload": {
            "job_url":         "https://www.linkedin.com/jobs/view/data-scientist-at-razorpay-987654",
            "recruiter_email": "hiring@razorpay.com",
            "company_claimed": "Razorpay",
            "phone_number":    "",
            "salary_offered":  1800000,
            "offer_text": (
                "Razorpay is hiring a Data Scientist with strong Python and ML fundamentals. "
                "3+ years experience required. You will work on fraud detection and payment "
                "intelligence models. Interview process includes a take-home assignment, technical "
                "round, and culture fit interview. CTC between 16-20 LPA based on experience."
            ),
        },
    },
    {
        "label":            "TCS — Frontend Developer (Naukri)",
        "expected_verdicts": {"SAFE", "REVIEW"},
        "payload": {
            "job_url": (
                "https://www.naukri.com/job-listings/"
                "frontend-developer-tata-consultancy-services-mumbai-3-5-years-240418"
            ),
            "recruiter_email": "tcs.recruitment@tcs.com",
            "company_claimed": "TCS",
            "phone_number":    "",
            "salary_offered":  950000,
            "offer_text": (
                "TCS is hiring a Frontend Developer with 3-5 years of experience in React.js "
                "and TypeScript. Position based in Mumbai. Selected candidates will go through "
                "TCS NQT or direct interview process. Offer letter issued only through official "
                "TCS HR systems. No payment required at any stage."
            ),
        },
    },
    {
        "label":            "Amazon — SDE-II (amazon.jobs)",
        "expected_verdicts": {"SAFE", "REVIEW"},
        "payload": {
            "job_url": (
                "https://www.amazon.jobs/en/jobs/2345678/"
                "software-development-engineer-india"
            ),
            "recruiter_email": "amazon-recruiting@amazon.com",
            "company_claimed": "Amazon",
            "phone_number":    "",
            "salary_offered":  2200000,
            "offer_text": (
                "Amazon India is hiring an SDE-II for the Payments team in Bengaluru. Candidates "
                "with 4+ years of experience in distributed systems are encouraged to apply. "
                "Interview loop includes online assessment, two coding rounds, system design, and "
                "bar raiser interview. Compensation includes base salary, RSUs, and joining bonus."
            ),
        },
    },
]

SCAM_CASES = [
    {
        "label":            "Fake TCS — WFH typist / registration fee",
        "expected_verdicts": {"LIKELY SCAM", "SCAM"},
        "payload": {
            "job_url":         "https://tcs-jobs-hiring.net/apply/data-entry",
            "recruiter_email": "hr.tcs.recruitment@gmail.com",
            "company_claimed": "TCS",
            "phone_number":    "8800000001",
            "salary_offered":  7200000,
            "offer_text": (
                "IMMEDIATE HIRING!! TCS is recruiting work from home typists. "
                "Earn 72,000/month guaranteed. No interview needed. You have been shortlisted. "
                "Pay 1,999 registration fee via Paytm to activate your account. "
                "WhatsApp us NOW. Offer valid for 12 hours only!!"
            ),
        },
    },
    {
        "label":            "Fake Wipro — WFH form-filling / Western Union deposit",
        "expected_verdicts": {"LIKELY SCAM", "SCAM"},
        "payload": {
            "job_url":         "https://wipro-remote-jobs.blogspot.com/apply",
            "recruiter_email": "wipro.hr.team@yahoo.com",
            "company_claimed": "Wipro",
            "phone_number":    "9100000002",
            "salary_offered":  10800000,
            "offer_text": (
                "WORK FROM HOME OPPORTUNITY with Wipro!! No qualification required. "
                "Earn 90,000/month just by filling forms. 100% job guarantee. "
                "Selected candidates must pay 3,500 refundable deposit via Western Union "
                "within 24 hours to secure seat. Limited 10 seats left. Reply ASAP!!"
            ),
        },
    },
    {
        "label":            "Fake Amazon — home packing / security deposit",
        "expected_verdicts": {"LIKELY SCAM", "SCAM"},
        "payload": {
            "job_url":         "https://amazon-jobs-india.work/home-packing",
            "recruiter_email": "amazon.recruitment.india@gmail.com",
            "company_claimed": "Amazon",
            "phone_number":    "7000000003",
            "salary_offered":  8400000,
            "offer_text": (
                "Amazon Home Packing Jobs Available!! Earn 700 per packet packed at home. "
                "No experience needed. Weekly payment guaranteed. Send 2,000 as security deposit "
                "via Google Pay to receive your starter kit. Contact on WhatsApp only. "
                "Do not delay -- positions filling fast!!"
            ),
        },
    },
    {
        "label":            "Fake Google — remote analyst / processing fee (.xyz)",
        "expected_verdicts": {"LIKELY SCAM", "SCAM"},
        "payload": {
            "job_url":         "https://google-wfh-india.xyz/apply-now",
            "recruiter_email": "google.hr.india2024@gmail.com",
            "company_claimed": "Google",
            "phone_number":    "9900000004",
            "salary_offered":  15600000,
            "offer_text": (
                "Google India is hiring remote data analysts!! Earn 1,30,000/month from home. "
                "You were selected based on your LinkedIn profile. No technical skills required. "
                "Pay 4,999 one-time processing fee to HR portal link below. "
                "Offer expires tonight at midnight. Immediate joining!!"
            ),
        },
    },
    {
        "label":            "Fake HDFC Bank — lucky draw / NEFT fee",
        "expected_verdicts": {"LIKELY SCAM", "SCAM"},
        "payload": {
            "job_url":         "https://hdfc-bank-recruitment.net/clerk-apply",
            "recruiter_email": "hdfc.hr.recruitment@rediffmail.com",
            "company_claimed": "HDFC Bank",
            "phone_number":    "8500000005",
            "salary_offered":  6000000,
            "offer_text": (
                "HDFC Bank Clerk Vacancy 2024!! 500 posts available. Work from home. "
                "Salary 50,000/month plus incentives. No exam required. Selected via lucky draw. "
                "Pay 1,500 document verification fee via NEFT to confirm appointment. "
                "Joining letter will be emailed instantly after payment!!"
            ),
        },
    },
]

# ---------------------------------------------------------------------------
# Required output field contract (per spec)
# ---------------------------------------------------------------------------

REQUIRED_TOP_KEYS = {
    "verdict", "overall_score", "overall_risk", "confidence",
    "summary", "reasons", "recommendations", "field_analysis",
    "signals", "metadata",
}
REQUIRED_SIGNAL_KEYS = {"flag", "penalty", "reason", "category", "confidence", "check", "field"}
VALID_VERDICTS      = {"SAFE", "REVIEW", "LIKELY SCAM", "SCAM"}
VALID_RISK_LEVELS   = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

# ---------------------------------------------------------------------------
# Core test runner
# ---------------------------------------------------------------------------

passed = 0
failed = 0
errors = []


def run_case(batch: str, idx: int, label: str, payload: dict, expected: set) -> None:
    global passed, failed

    try:
        resp = requests.post(f"{BASE_URL}/analyze", json=payload, timeout=TIMEOUT)
    except requests.exceptions.ConnectionError:
        print(f"  FAIL  [{batch} #{idx}] {label}")
        print(f"         ERROR: Cannot connect to {BASE_URL} — is the server running?")
        failed += 1
        errors.append(f"[{batch} #{idx}] Connection refused")
        return

    # ── HTTP status ─────────────────────────────────────────────────────────
    if resp.status_code != 200:
        print(f"  FAIL  [{batch} #{idx}] {label}")
        print(f"         HTTP {resp.status_code}: {resp.text[:200]}")
        failed += 1
        errors.append(f"[{batch} #{idx}] HTTP {resp.status_code}")
        return

    data = resp.json()
    case_errors = []

    # ── Output contract: top-level keys ─────────────────────────────────────
    missing_top = REQUIRED_TOP_KEYS - set(data.keys())
    if missing_top:
        case_errors.append(f"Missing top-level keys: {sorted(missing_top)}")

    # ── Verdict is one of the four valid values ──────────────────────────────
    verdict = data.get("verdict", "")
    if verdict not in VALID_VERDICTS:
        case_errors.append(f"verdict='{verdict}' is not a valid value")

    # ── overall_score in 0-100 ───────────────────────────────────────────────
    score = data.get("overall_score", -1)
    if not (0 <= score <= 100):
        case_errors.append(f"overall_score={score} is out of range [0, 100]")

    # ── overall_risk is valid ────────────────────────────────────────────────
    risk = data.get("overall_risk", "")
    if risk not in VALID_RISK_LEVELS:
        case_errors.append(f"overall_risk='{risk}' is not a valid value")

    # ── confidence in [0.0, 1.0] ────────────────────────────────────────────
    conf = data.get("confidence", -1)
    if not (0.0 <= conf <= 1.0):
        case_errors.append(f"confidence={conf} is out of range [0.0, 1.0]")

    # ── summary is a non-empty string ───────────────────────────────────────
    if not isinstance(data.get("summary"), str) or not data["summary"].strip():
        case_errors.append("summary is missing or empty")

    # ── reasons and recommendations are lists ───────────────────────────────
    for key in ("reasons", "recommendations"):
        if not isinstance(data.get(key), list):
            case_errors.append(f"'{key}' should be a list")

    # ── field_analysis is a dict ────────────────────────────────────────────
    if not isinstance(data.get("field_analysis"), dict):
        case_errors.append("'field_analysis' should be a dict")

    # ── signals: each entry has all required keys ───────────────────────────
    signals = data.get("signals", [])
    if not isinstance(signals, list):
        case_errors.append("'signals' should be a list")
    else:
        for sig in signals:
            missing_s = REQUIRED_SIGNAL_KEYS - set(sig.keys())
            if missing_s:
                case_errors.append(f"signal '{sig.get('check','?')}' missing keys: {sorted(missing_s)}")

    # ── metadata has required keys ───────────────────────────────────────────
    meta = data.get("metadata", {})
    for mk in ("version", "timestamp", "checks_executed"):
        if mk not in meta:
            case_errors.append(f"metadata missing key: '{mk}'")

    # ── Expected verdict for this batch ─────────────────────────────────────
    if verdict not in expected:
        case_errors.append(
            f"verdict='{verdict}' not in expected set {sorted(expected)}"
        )

    # ── Report ───────────────────────────────────────────────────────────────
    status = "PASS" if not case_errors else "FAIL"
    flag   = "  PASS" if not case_errors else "  FAIL"
    print(
        f"{flag}  [{batch} #{idx}] {label}\n"
        f"         verdict={verdict:<12}  score={score:3d}  "
        f"risk={risk:<8}  conf={conf:.2f}  checks={len(signals)}"
    )
    if case_errors:
        for e in case_errors:
            print(f"         ! {e}")
        failed += 1
        errors.extend([f"[{batch} #{idx}] {e}" for e in case_errors])
    else:
        passed += 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("  ScamShield Engine — Test Suite")
    print("=" * 70)

    print("\n[ LEGIT CASES — Expected: SAFE or REVIEW ]\n")
    for i, case in enumerate(LEGIT_CASES, 1):
        run_case("LEGIT", i, case["label"], case["payload"], case["expected_verdicts"])

    print("\n[ SCAM CASES — Expected: LIKELY SCAM or SCAM ]\n")
    for i, case in enumerate(SCAM_CASES, 1):
        run_case("SCAM", i, case["label"], case["payload"], case["expected_verdicts"])

    total = passed + failed
    print("\n" + "=" * 70)
    if failed == 0:
        print(f"  RESULT: {passed}/{total} tests passed — ALL OK")
    else:
        print(f"  RESULT: {passed}/{total} passed, {failed} FAILED")
        print()
        for e in errors:
            print(f"  ! {e}")
    print("=" * 70)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
