"""
Run both LEGIT and SCAM test batches against the live API and print a full report.
"""
import json
import requests

BASE = "http://127.0.0.1:8000"

LEGIT = [
    {
        "job_url": "https://www.infosys.com/careers/job-listing/software-engineer-2024.html",
        "recruiter_email": "talent.acquisition@infosys.com",
        "company_claimed": "Infosys",
        "phone_number": "",
        "salary_offered": 700000,
        "offer_text": "Infosys is hiring Software Engineers (0-2 years experience) for our Bengaluru and Pune offices. Candidates must clear our online assessment and two interview rounds. No fees required at any stage of recruitment. Apply through the official Infosys careers portal only. Relocation support provided."
    },
    {
        "job_url": "https://careers.wipro.com/job/bangalore/business-analyst/123456",
        "recruiter_email": "wipro.ta@wipro.com",
        "company_claimed": "Wipro",
        "phone_number": "",
        "salary_offered": 850000,
        "offer_text": "Wipro Limited is looking for a Business Analyst with 2-4 years of experience in process documentation and stakeholder management. Role based in Hyderabad. Candidates will undergo HR screening, aptitude test, and two technical interviews. Wipro never charges candidates any fee during hiring."
    },
    {
        "job_url": "https://www.linkedin.com/jobs/view/data-scientist-at-razorpay-987654",
        "recruiter_email": "hiring@razorpay.com",
        "company_claimed": "Razorpay",
        "phone_number": "",
        "salary_offered": 1800000,
        "offer_text": "Razorpay is hiring a Data Scientist with strong Python and ML fundamentals. 3+ years experience required. You will work on fraud detection and payment intelligence models. Interview process includes a take-home assignment, technical round, and culture fit interview. CTC between 16-20 LPA based on experience."
    },
    {
        "job_url": "https://www.naukri.com/job-listings/frontend-developer-tata-consultancy-services-mumbai-3-5-years-240418",
        "recruiter_email": "tcs.recruitment@tcs.com",
        "company_claimed": "TCS",
        "phone_number": "",
        "salary_offered": 950000,
        "offer_text": "TCS is hiring a Frontend Developer with 3-5 years of experience in React.js and TypeScript. Position based in Mumbai. Selected candidates will go through TCS NQT or direct interview process. Offer letter issued only through official TCS HR systems. No payment required at any stage."
    },
    {
        "job_url": "https://www.amazon.jobs/en/jobs/2345678/software-development-engineer-india",
        "recruiter_email": "amazon-recruiting@amazon.com",
        "company_claimed": "Amazon",
        "phone_number": "",
        "salary_offered": 2200000,
        "offer_text": "Amazon India is hiring an SDE-II for the Payments team in Bengaluru. Candidates with 4+ years of experience in distributed systems are encouraged to apply. Interview loop includes online assessment, two coding rounds, system design, and bar raiser interview. Compensation includes base salary, RSUs, and joining bonus."
    },
]

SCAM = [
    {
        "job_url": "https://tcs-jobs-hiring.net/apply/data-entry",
        "recruiter_email": "hr.tcs.recruitment@gmail.com",
        "company_claimed": "TCS",
        "phone_number": "8800000001",
        "salary_offered": 7200000,
        "offer_text": "IMMEDIATE HIRING!! TCS is recruiting work from home typists. Earn 72,000/month guaranteed. No interview needed. You have been shortlisted. Pay 1,999 registration fee via Paytm to activate your account. WhatsApp us NOW. Offer valid for 12 hours only!!"
    },
    {
        "job_url": "https://wipro-remote-jobs.blogspot.com/apply",
        "recruiter_email": "wipro.hr.team@yahoo.com",
        "company_claimed": "Wipro",
        "phone_number": "9100000002",
        "salary_offered": 10800000,
        "offer_text": "WORK FROM HOME OPPORTUNITY with Wipro!! No qualification required. Earn 90,000/month just by filling forms. 100% job guarantee. Selected candidates must pay 3,500 refundable deposit via Western Union within 24 hours to secure seat. Limited 10 seats left. Reply ASAP!!"
    },
    {
        "job_url": "https://amazon-jobs-india.work/home-packing",
        "recruiter_email": "amazon.recruitment.india@gmail.com",
        "company_claimed": "Amazon",
        "phone_number": "7000000003",
        "salary_offered": 8400000,
        "offer_text": "Amazon Home Packing Jobs Available!! Earn 700 per packet packed at home. No experience needed. Weekly payment guaranteed. Send 2,000 as security deposit via Google Pay to receive your starter kit. Contact on WhatsApp only. Do not delay -- positions filling fast!!"
    },
    {
        "job_url": "https://google-wfh-india.xyz/apply-now",
        "recruiter_email": "google.hr.india2024@gmail.com",
        "company_claimed": "Google",
        "phone_number": "9900000004",
        "salary_offered": 15600000,
        "offer_text": "Google India is hiring remote data analysts!! Earn 1,30,000/month from home. You were selected based on your LinkedIn profile. No technical skills required. Pay 4,999 one-time processing fee to HR portal link below. Offer expires tonight at midnight. Immediate joining!!"
    },
    {
        "job_url": "https://hdfc-bank-recruitment.net/clerk-apply",
        "recruiter_email": "hdfc.hr.recruitment@rediffmail.com",
        "company_claimed": "HDFC Bank",
        "phone_number": "8500000005",
        "salary_offered": 6000000,
        "offer_text": "HDFC Bank Clerk Vacancy 2024!! 500 posts available. Work from home. Salary 50,000/month plus incentives. No exam required. Selected via lucky draw. Pay 1,500 document verification fee via NEFT to confirm appointment. Joining letter will be emailed instantly after payment!!"
    },
]

EXPECTED_LEGIT  = {"SAFE", "REVIEW"}
EXPECTED_SCAM   = {"LIKELY SCAM", "SCAM"}
REQUIRED_TOP_KEYS = {"verdict", "overall_score", "overall_risk", "confidence",
                     "summary", "reasons", "recommendations", "field_analysis",
                     "signals", "metadata"}
REQUIRED_SIGNAL_KEYS = {"flag", "penalty", "reason", "category", "confidence", "check", "field"}

errors = []
passed = 0

def check_response(label, payload, expected_verdicts, idx):
    global passed
    try:
        r = requests.post(f"{BASE}/analyze", json=payload, timeout=30)
    except Exception as e:
        errors.append(f"[{label} #{idx}] REQUEST FAILED: {e}")
        return

    if r.status_code != 200:
        errors.append(f"[{label} #{idx}] HTTP {r.status_code}: {r.text[:300]}")
        return

    try:
        data = r.json()
    except Exception as e:
        errors.append(f"[{label} #{idx}] JSON parse error: {e}")
        return

    # Check top-level keys
    missing = REQUIRED_TOP_KEYS - set(data.keys())
    if missing:
        errors.append(f"[{label} #{idx}] Missing top-level keys: {missing}")

    # Check verdict
    verdict = data.get("verdict", "")
    if verdict not in expected_verdicts:
        errors.append(f"[{label} #{idx}] Unexpected verdict '{verdict}' (expected one of {expected_verdicts})")

    # Check signals structure
    signals = data.get("signals", [])
    for s in signals:
        missing_s = REQUIRED_SIGNAL_KEYS - set(s.keys())
        if missing_s:
            errors.append(f"[{label} #{idx}] Signal '{s.get('check','?')}' missing keys: {missing_s}")

    # Check metadata
    meta = data.get("metadata", {})
    for mk in ("version", "timestamp", "checks_executed"):
        if mk not in meta:
            errors.append(f"[{label} #{idx}] metadata missing key: {mk}")

    score = data.get("overall_score", -1)
    if not (0 <= score <= 100):
        errors.append(f"[{label} #{idx}] overall_score out of range: {score}")

    conf = data.get("confidence", -1)
    if not (0.0 <= conf <= 1.0):
        errors.append(f"[{label} #{idx}] confidence out of range: {conf}")

    print(f"  [{label} #{idx}] company={payload['company_claimed']:10s}  "
          f"verdict={verdict:12s}  score={score:3d}  risk={data.get('overall_risk','?'):8s}  "
          f"conf={conf:.2f}  signals={len(signals)}")
    passed += 1

print("=" * 70)
print("LEGIT CASES")
print("=" * 70)
for i, p in enumerate(LEGIT, 1):
    check_response("LEGIT", p, EXPECTED_LEGIT, i)

print()
print("=" * 70)
print("SCAM CASES")
print("=" * 70)
for i, p in enumerate(SCAM, 1):
    check_response("SCAM", p, EXPECTED_SCAM, i)

print()
print("=" * 70)
if errors:
    print(f"RESULT: {passed} passed, {len(errors)} ERRORS:")
    for e in errors:
        print("  !", e)
else:
    print(f"RESULT: ALL {passed} TESTS PASSED [OK]")
print("=" * 70)
