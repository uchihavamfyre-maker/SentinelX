"""FastAPI interface for the SentinelX detection core."""
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .detection import detect_brute_force
from .evaluation import evaluate_detector
from .models import AuthEvent

app = FastAPI(title="SentinelX API", version="0.1.0",
    description="Defensive analysis of synthetic or explicitly authorized authentication logs.")

# Set SENTINELX_CORS_ORIGINS to a comma-separated allowlist for your deployed dashboard.
# Local Vite origins are enabled by default for development only.
_origins = [origin.strip() for origin in os.getenv(
    "SENTINELX_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware, allow_origins=_origins, allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Content-Type"],
)

class AnalysisRequest(BaseModel):
    events: list[AuthEvent] = Field(max_length=10000)
    threshold: int = Field(default=5, ge=2, le=1000)
    window_seconds: int = Field(default=300, ge=1, le=86400)

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "project": "SentinelX", "version": "0.1.0"}

@app.post("/analyze")
def analyze(request: AnalysisRequest) -> dict:
    try: alerts = detect_brute_force(request.events, request.threshold, request.window_seconds)
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"event_count": len(request.events), "alert_count": len(alerts),
            "alerts": [alert.model_dump(mode="json") for alert in alerts]}

@app.post("/evaluate")
def evaluate(request: AnalysisRequest) -> dict:
    if any(event.label is None for event in request.events):
        raise HTTPException(status_code=422, detail="Every event must include a label for evaluation.")
    return evaluate_detector(request.events, request.threshold, request.window_seconds).model_dump()
