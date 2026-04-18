# ScamShield Engine API

ScamShield is a production-grade cybersecurity analysis engine designed to detect employment and recruitment scams across multiple input vectors natively.

## Features
- **Domain & URL Analysis**: Domain age, typosquatting, URL structure, and subdomain brand abuse.
- **Email Validation**: Disposable/free email checks, local-part entropy, and typosquatting impersonation.
- **Content Inspection**: NLP-lite on offer text.
- **Contact Details**: Phone validity checks (premium-rate codes, sequential patterns).
- **Salary Constraints**: Salary anomaly detection per company-tier logic.
- **Cross-Field Checks**: Mismatch detection between email, URL domains, and claimed company domains.

## Requirements
- `fastapi`
- `uvicorn`
- `pydantic`
- `whois` (optional for domain age checks)
- `rapidfuzz` (optional for enhanced typosquat analysis)

## Running the API

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the Uvicorn server:
   ```bash
   uvicorn main:app --reload
   ```

3. Access the API documentation:
   - [Swagger UI](http://127.0.0.1:8000/docs)
   - [ReDoc](http://127.0.0.1:8000/redoc)

## Endpoints

- **`POST /analyze`**: Provide exhaustive input (`job_url`, `recruiter_email`, `company_claimed`, `phone_number`, `salary_offered`, `offer_text`) to receive the complete threat intelligence report containing the trust score, verdict, penalties and recommended actions.
- **`POST /run_cyber_checks`**: Basic verification wrapper processing only `job_url`, `recruiter_email`, and `company_claimed` to output raw signal dictionaries exclusively.
