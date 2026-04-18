from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import uvicorn

from scamshield_engine import analyze, run_cyber_checks

app = FastAPI(
    title="ScamShield Engine API", 
    version="3.0",
    description="Cybersecurity Analysis Engine for Employment Scams"
)

class AnalyzeRequest(BaseModel):
    job_url: str = ""
    recruiter_email: str = ""
    company_claimed: str = ""
    phone_number: str = ""
    salary_offered: Optional[float] = None
    offer_text: str = ""

@app.post("/analyze", summary="Run full ScamShield analysis")
def api_analyze(req: AnalyzeRequest):
    """
    Accepts all input fields and returns the full detailed threat intelligence report.
    """
    return analyze(req.model_dump())

class CyberChecksRequest(BaseModel):
    job_url: str = ""
    recruiter_email: str = ""
    company_claimed: str = ""

@app.post("/run_cyber_checks", summary="Run partial cyber checks")
def api_run_cyber_checks(req: CyberChecksRequest):
    """
    Accepts limited input fields and returns a signals dictionary keyed by check name.
    """
    return run_cyber_checks(req.job_url, req.recruiter_email, req.company_claimed)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
