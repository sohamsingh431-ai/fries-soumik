from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
import cyber

app = FastAPI(
    title="ScamShield API",
    description="Production-Grade Cybersecurity Analysis Engine",
    version="1.0.0"
)

# ---------------------------------------------------------------------------
#  PYDANTIC MODELS (INPUT SCHEMA)
# ---------------------------------------------------------------------------
class JobOfferAnalysisRequest(BaseModel):
    job_url: Optional[str] = Field(
        default=None, 
        description="URL of the job posting or application link",
        json_schema_extra={"example": "https://g00gle-careers.com/apply"}
    )
    company_claimed: Optional[str] = Field(
        default=None, 
        description="The company the recruiter claims to represent",
        json_schema_extra={"example": "Google"}
    )
    recruiter_email: Optional[str] = Field(
        default=None, 
        description="Email address used by the recruiter to contact the candidate",
        json_schema_extra={"example": "hr.google@gmail.com"}
    )
    phone_number: Optional[str] = Field(
        default=None, 
        description="Phone or WhatsApp number provided by the recruiter",
        json_schema_extra={"example": "+91-9999999999"}
    )
    salary_offered: Optional[float] = Field(
        default=None, 
        description="Proposed salary figure",
        json_schema_extra={"example": 950000.0}
    )
    offer_text: Optional[str] = Field(
        default=None, 
        description="Text content of the email, message, or job description",
        json_schema_extra={"example": "Immediate joining opportunity! Pay processing fee via wire transfer."}
    )

# ---------------------------------------------------------------------------
#  API ENDPOINTS
# ---------------------------------------------------------------------------
@app.post("/api/v1/analyze", summary="Run Threat Analysis", tags=["Scoring"])
async def run_analysis(request: JobOfferAnalysisRequest):
    """
    Submits a job offer data payload to the ScamShield engine.
    
    The engine will run all configured heuristic checks in parallel, apply mapping rules, 
    compute both field-level and global risk scores, and return the comprehensive analysis.
    """
    try:
        # Convert schema to dict, keeping None values so the engine can parse them correctly
        data = request.model_dump()
        
        # Execute the core engine logic
        report = cyber.analyze(data)
        
        return report
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Engine failure: {str(exc)}")

@app.get("/health", summary="Health Check", tags=["System"])
async def health_check():
    """Verify the API is running."""
    return {"status": "healthy", "engine": "ScamShield v1.0.0"}

if __name__ == "__main__":
    import uvicorn
    # Allow running directly via `python main.py`
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
