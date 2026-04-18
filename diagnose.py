"""Diagnosis: print all flagged signals for the two failing legit cases."""
import json, requests

BASE = "http://127.0.0.1:8000"

cases = [
    {
        "label": "LEGIT #3 Razorpay",
        "payload": {
            "job_url": "https://www.linkedin.com/jobs/view/data-scientist-at-razorpay-987654",
            "recruiter_email": "hiring@razorpay.com",
            "company_claimed": "Razorpay",
            "phone_number": "",
            "salary_offered": 1800000,
            "offer_text": "Razorpay is hiring a Data Scientist with strong Python and ML fundamentals. 3+ years experience required. You will work on fraud detection and payment intelligence models. Interview process includes a take-home assignment, technical round, and culture fit interview. CTC between 16-20 LPA based on experience."
        }
    },
    {
        "label": "LEGIT #5 Amazon",
        "payload": {
            "job_url": "https://www.amazon.jobs/en/jobs/2345678/software-development-engineer-india",
            "recruiter_email": "amazon-recruiting@amazon.com",
            "company_claimed": "Amazon",
            "phone_number": "",
            "salary_offered": 2200000,
            "offer_text": "Amazon India is hiring an SDE-II for the Payments team in Bengaluru. Candidates with 4+ years of experience in distributed systems are encouraged to apply. Interview loop includes online assessment, two coding rounds, system design, and bar raiser interview. Compensation includes base salary, RSUs, and joining bonus."
        }
    }
]

for case in cases:
    r = requests.post(f"{BASE}/analyze", json=case["payload"], timeout=30)
    data = r.json()
    print(f"\n{'='*60}")
    print(f"{case['label']}  verdict={data['verdict']}  score={data['overall_score']}")
    print("--- FLAGGED SIGNALS ---")
    for s in data["signals"]:
        if s["flag"]:
            print(f"  check={s['check']:30s}  penalty={s['penalty']:3d}  conf={s['confidence']:.2f}")
            print(f"    reason: {s['reason']}")
    print("--- CORRELATIONS (from reasons) ---")
    for r2 in data["reasons"]:
        print(f"  {r2}")
    print(f"\nraw_penalty={data['metadata'].get('raw_penalty','?')}")
