"""FastAPI interface for the SentinelX defensive detection core."""
import hmac
import os
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .detection import detect_brute_force
from .evaluation import evaluate_detector
from .models import AuthEvent

app = FastAPI(
    title="SentinelX API",
    version="0.2.0",
    description="Defensive analysis and authenticated ingestion for authorized authentication telemetry.",
)

_origins = [origin.strip() for origin in os.getenv(
    "SENTINELX_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_origin_regex=r"https://[a-zA-Z0-9-]+(?:-[a-zA-Z0-9-]+)*\\.vercel\\.app",
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

class AnalysisRequest(BaseModel):
    events: list[AuthEvent] = Field(max_length=10000)
    threshold: int = Field(default=5, ge=2, le=1000)
    window_seconds: int = Field(default=300, ge=1, le=86400)

class IngestRequest(BaseModel):
    events: list[AuthEvent] = Field(min_length=1, max_length=1000)
    threshold: int = Field(default=5, ge=2, le=1000)
    window_seconds: int = Field(default=300, ge=1, le=86400)

def _analysis_payload(request: AnalysisRequest | IngestRequest) -> dict:
    alerts = detect_brute_force(request.events, request.threshold, request.window_seconds)
    return {
        "event_count": len(request.events),
        "alert_count": len(alerts),
        "alerts": [alert.model_dump(mode="json") for alert in alerts],
    }

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "project": "SentinelX", "version": "0.2.0", "capability": "defensive-auth-analytics"}

@app.post("/analyze")
def analyze(request: AnalysisRequest) -> dict:
    try:
        return _analysis_payload(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/evaluate")
def evaluate(request: AnalysisRequest) -> dict:
    if any(event.label is None for event in request.events):
        raise HTTPException(status_code=422, detail="Every event must include a label for evaluation.")
    return evaluate_detector(request.events, request.threshold, request.window_seconds).model_dump()

@app.post("/ingest")
def ingest(
    request: IngestRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    """Accept a bounded batch from an explicitly authorized log forwarder.

    Configure SENTINELX_INGEST_TOKEN in the deployment environment and send
    Authorization: Bearer <token>. Events are analyzed immediately; durable
    retention is intentionally delegated to a configured storage integration.
    """
    expected = os.getenv("SENTINELX_INGEST_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Ingestion is disabled: configure SENTINELX_INGEST_TOKEN.")
    supplied = authorization or ""
    if not hmac.compare_digest(supplied, f"Bearer {expected}"):
        raise HTTPException(status_code=401, detail="Invalid ingestion credential.")
    try:
        result = _analysis_payload(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "status": "accepted",
        "persisted": False,
        "retention_note": "This endpoint analyzes the submitted batch but does not persist it.",
        **result,
    }
