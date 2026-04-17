# ScamShield — Cybersecurity Analysis Engine

ScamShield is a production-grade threat-intelligence engine that detects employment-scam signals. It exposes a **FastAPI** endpoint where users submit job-offer data and receive a full risk report.

---

## Quick Start (Fresh Laptop)

### 1. Prerequisites
- **Python 3.8+** (3.10+ recommended)
- **Git**

### 2. Clone & Setup
```bash
git clone https://github.com/sohamsingh431-ai/fries-soumik.git
cd fries-soumik

# Create a virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Mac / Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the API Server
```bash
python main.py
```
The server starts at **http://127.0.0.1:8000**.

Open the interactive docs at **http://127.0.0.1:8000/docs** to try it out directly in your browser.

---

## How to Use

### Via the Swagger UI (Easiest)
1. Open **http://127.0.0.1:8000/docs** in your browser.
2. Expand the **POST /api/v1/analyze** endpoint.
3. Click **Try it out**, fill in the fields, and hit **Execute**.

### Via curl / PowerShell
```bash
# Linux / Mac
curl -X POST http://127.0.0.1:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "job_url": "https://bit.ly/google-apply-now",
    "company_claimed": "Google",
    "recruiter_email": "hr.google@gmail.com",
    "phone_number": "9999999999",
    "salary_offered": 100000,
    "offer_text": "Pay processing fee of $200 via Western Union."
  }'
```

```powershell
# Windows PowerShell
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/analyze -Method Post `
  -ContentType "application/json" `
  -Body '{"job_url":"https://bit.ly/google-apply-now","company_claimed":"Google","recruiter_email":"hr.google@gmail.com","phone_number":"9999999999","salary_offered":100000,"offer_text":"Pay processing fee of $200 via Western Union."}'
```

### Input Fields

| Field | Type | Description |
|---|---|---|
| `job_url` | string | URL of the job posting or application link |
| `company_claimed` | string | Company the recruiter claims to represent |
| `recruiter_email` | string | Email address used by the recruiter |
| `phone_number` | string | Phone / WhatsApp number provided |
| `salary_offered` | number | Proposed salary figure |
| `offer_text` | string | Full text of the email, message, or job description |

All fields are **optional** — submit whatever you have and the engine will analyze the available data.

---

## What Checks Are Run

| Check | What It Detects |
|---|---|
| Domain Age | Brand-new domains registered to lure victims |
| Typosquat | Lookalike domains (e.g. `g00gle.com`) |
| URL Structure | URL shorteners, raw IPs, suspicious TLDs |
| SSL Certificate | Missing or free/automated SSL on the job site |
| Email Validity | Disposable or free-email recruiters impersonating companies |
| Salary Anomaly | Unrealistically high salary bait |
| Offer Text | Scam phrases like "processing fee", "wire transfer", urgency tactics |
| Phone Validity | Fake or suspicious phone numbers |

The engine also applies **correlation rules** — e.g. a new domain + free email together gets a bonus penalty.

---

## Sample Response
```json
{
  "verdict": "SCAM",
  "overall_score": 0,
  "overall_risk": "CRITICAL",
  "confidence": 0.84,
  "summary": "Engine identified 6 threat signals. Trust level is CRITICAL.",
  "reasons": ["Uses URL shortener (bit.ly)", "..."],
  "recommendations": ["Do not share personal identifiable information (PII)", "..."],
  "field_analysis": { "job_url": { "score": 15, "risk": "LOW" }, "..." : "..." },
  "signals": ["..."],
  "metadata": { "version": "2.0.0", "timestamp": "...", "checks_executed": 8 }
}
```
