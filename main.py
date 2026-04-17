"""
ScamShield CyberScam — FastAPI Entry Point
============================================
Full-power cybersecurity analysis API with all input fields.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import sqlite3
import json
import uuid
from datetime import datetime

# Import the analysis engine
from cyber import analyze

# ── App Init ──
app = FastAPI(
    title="ScamShield CyberScam Engine",
    description="Production-grade cybersecurity scam detection API",
    version="3.0.0",
)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request Model — ALL input fields ──
class CheckRequest(BaseModel):
    job_url: str = Field(default="", description="URL of the job posting")
    company_claimed: str = Field(default="", description="Company name claimed in the posting")
    recruiter_email: str = Field(default="", description="Recruiter's email address")
    salary_offered: Optional[float] = Field(default=None, description="Salary offered (numeric)")
    offer_text: str = Field(default="", description="Full text of the offer/posting")
    phone_number: str = Field(default="", description="Recruiter's phone number")
    job_title: str = Field(default="", description="Job title")
    job_description: str = Field(default="", description="Full job description text")
    location: str = Field(default="", description="Job location")
    experience_required: Optional[float] = Field(default=None, description="Years of experience required")


# ── Database ──
DB_PATH = "cyberscam.db"


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id TEXT PRIMARY KEY,
            job_url TEXT,
            company TEXT,
            score INTEGER,
            verdict TEXT,
            risk TEXT,
            confidence REAL,
            reasons TEXT,
            signals TEXT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.commit()
    con.close()


@app.on_event("startup")
def startup():
    init_db()


# ── Main Analysis Endpoint ──
@app.post("/api/check")
def check(req: CheckRequest):
    """
    Run full ScamShield cyber analysis on the provided input.
    Returns trust score, verdict, risk level, reasons, recommendations, and full signal breakdown.
    """
    try:
        # Build input dict from all fields
        input_data = {
            "job_url": req.job_url,
            "company_claimed": req.company_claimed,
            "recruiter_email": req.recruiter_email,
            "salary_offered": req.salary_offered if req.salary_offered is not None else None,
            "offer_text": req.offer_text,
            "phone_number": req.phone_number,
            "job_title": req.job_title,
            "job_description": req.job_description,
            "location": req.location,
            "experience_required": req.experience_required,
        }

        # Run analysis
        report = analyze(input_data)

        # Save to DB
        rid = str(uuid.uuid4())[:8]
        con = sqlite3.connect(DB_PATH)
        con.execute(
            "INSERT INTO checks VALUES (?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)",
            (
                rid,
                req.job_url,
                req.company_claimed,
                report["overall_score"],
                report["verdict"],
                report["overall_risk"],
                report["confidence"],
                json.dumps(report["reasons"]),
                json.dumps(report["signals"], default=str),
            ),
        )
        con.commit()
        con.close()

        return {
            "request_id": rid,
            "trust_score": report["overall_score"],
            "verdict": report["verdict"],
            "overall_risk": report["overall_risk"],
            "confidence": report["confidence"],
            "hard_override": report.get("hard_override", False),
            "summary": report["summary"],
            "reasons": report["reasons"],
            "recommendations": report["recommendations"],
            "field_analysis": report["field_analysis"],
            "module_analysis": report["module_analysis"],
            "correlations": report.get("correlations", []),
            "signals": report["signals"],
            "metadata": report["metadata"],
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis engine error: {str(e)}")


# ── Stats Endpoint ──
@app.get("/api/stats")
def stats():
    """Get overall statistics of checks performed."""
    con = sqlite3.connect(DB_PATH)
    row = con.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN verdict='SCAM' THEN 1 ELSE 0 END) as scams,
            SUM(CASE WHEN verdict='SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
            SUM(CASE WHEN verdict='VERIFIED' THEN 1 ELSE 0 END) as verified,
            AVG(score) as avg_score,
            AVG(confidence) as avg_confidence
        FROM checks
    """).fetchone()
    con.close()
    return {
        "total_checks": row[0],
        "scams_caught": row[1] or 0,
        "suspicious": row[2] or 0,
        "verified": row[3] or 0,
        "average_score": round(row[4] or 0, 1),
        "average_confidence": round(row[5] or 0, 2),
    }


# ── History Endpoint ──
@app.get("/api/history")
def history(limit: int = 20):
    """Get recent check history."""
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT id, job_url, company, score, verdict, risk, confidence, ts FROM checks ORDER BY ts DESC LIMIT ?",
        (limit,),
    ).fetchall()
    con.close()
    return [
        {
            "id": r[0],
            "job_url": r[1],
            "company": r[2],
            "score": r[3],
            "verdict": r[4],
            "risk": r[5],
            "confidence": r[6],
            "timestamp": r[7],
        }
        for r in rows
    ]


# ── Health Check ──
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "engine": "ScamShield CyberScam v3.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    }
