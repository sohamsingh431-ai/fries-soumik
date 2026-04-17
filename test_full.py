"""
Comprehensive test suite — 5 diverse scenarios for ScamShield CyberScam engine.
Tests: obvious scam, legitimate posting, subtle scam, borderline/suspicious, minimal input.
"""
import sys
import json
sys.path.insert(0, ".")
from cyber import analyze

def run_test(name, data, expected_verdict_range):
    print(f"\n{'='*70}")
    print(f"  TEST: {name}")
    print(f"{'='*70}")
    report = analyze(data)

    v = report["verdict"]
    s = report["overall_score"]
    r = report["overall_risk"]
    c = report["confidence"]
    flags = len([sig for sig in report["signals"] if sig["flag"]])
    corrs = len(report.get("correlations", []))
    hard = report.get("hard_override", False)

    print(f"  Verdict: {v} | Score: {s}/100 | Risk: {r} | Confidence: {c:.0%}")
    print(f"  Flags: {flags} | Correlations: {corrs} | Hard Override: {hard}")
    print(f"  Summary: {report['summary'][:120]}...")

    if report["reasons"]:
        print(f"  Reasons ({len(report['reasons'])}):")
        for reason in report["reasons"][:5]:
            print(f"    -> {reason[:100]}")
    if report["recommendations"]:
        print(f"  Recommendations ({len(report['recommendations'])}):")
        for rec in report["recommendations"][:3]:
            print(f"    -> {rec[:100]}")

    # Validate
    passed = v in expected_verdict_range
    status = "PASS" if passed else "FAIL"
    print(f"\n  [{status}] Expected one of {expected_verdict_range}, got '{v}'")
    return passed

# ─────────────────────────────────────────────────────────────────────
results = []

# TEST 1: Obvious scam — every red flag
results.append(run_test(
    "OBVIOUS SCAM — all red flags",
    {
        "job_url": "https://bit.ly/google-apply-now",
        "company_claimed": "Google",
        "recruiter_email": "hr.google.official@gmail.com",
        "phone_number": "9999999999",
        "salary_offered": 15000000,
        "offer_text": "CONGRATULATIONS! You are SELECTED! Pay processing fee of Rs.5000 via UPI. Immediate joining! Registration fee required. WhatsApp us NOW!",
        "job_title": "Senior Engineer",
        "experience_required": 0,
    },
    ["SCAM"]
))

# TEST 2: Legit posting — real company domain + corporate email
results.append(run_test(
    "LEGITIMATE — real Google posting",
    {
        "job_url": "https://careers.google.com/jobs/results/12345",
        "company_claimed": "Google",
        "recruiter_email": "recruiter@google.com",
        "phone_number": "+14155551234",
        "salary_offered": 180000,
        "offer_text": "We are pleased to extend this offer for the role of Software Engineer at Google. Please review the compensation and benefits.",
        "job_title": "Software Engineer L4",
        "location": "Mountain View, CA",
        "experience_required": 3,
    },
    ["VERIFIED"]
))

# TEST 3: Subtle scam — fake domain, free email, moderate text
results.append(run_test(
    "SUBTLE SCAM — fake domain + free email",
    {
        "job_url": "https://amazon-careers-apply.xyz/job/12345",
        "company_claimed": "Amazon",
        "recruiter_email": "amazon.hr.team@yahoo.com",
        "phone_number": "+2341234567890",
        "salary_offered": 8000000,
        "offer_text": "Dear Candidate, You have been shortlisted for the position of Data Analyst at Amazon. Kindly revert with your documents. Guaranteed income of 8 LPA. Contact us on WhatsApp.",
        "job_title": "Data Analyst",
        "experience_required": 0,
    },
    ["SCAM", "SUSPICIOUS"]
))

# TEST 4: Borderline / Suspicious — startup-ish signals
results.append(run_test(
    "BORDERLINE — unknown startup, free email",
    {
        "job_url": "https://techstartupx.com/careers/frontend-dev",
        "company_claimed": "TechStartupX",
        "recruiter_email": "hr@techstartupx.com",
        "phone_number": "+919876543210",
        "salary_offered": 800000,
        "offer_text": "We are looking for a Frontend Developer to join our growing team. Competitive salary and equity offered. Apply through our portal.",
        "job_title": "Frontend Developer",
        "location": "Bangalore",
        "experience_required": 2,
    },
    ["VERIFIED", "SUSPICIOUS"]
))

# TEST 5: Minimal input — only offer text
results.append(run_test(
    "MINIMAL INPUT — only offer text, no URL/email",
    {
        "offer_text": "You have won a prize! Send Rs.500 registration fee to claim your reward. Act NOW before offer expires! WhatsApp 9988776655.",
    },
    ["SCAM", "SUSPICIOUS"]
))

# ─────────────────────────────────────────────────────────────────────
print(f"\n\n{'='*70}")
print(f"  RESULTS: {sum(results)}/{len(results)} tests passed")
print(f"{'='*70}")
if all(results):
    print("  ALL TESTS PASSED!")
else:
    print("  SOME TESTS FAILED — review output above")
