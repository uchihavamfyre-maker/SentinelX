"""FastAPI interface for the SentinelX defensive detection core."""
import hmac
import os
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .detection import detect_brute_force
from .evaluation import evaluate_detector
from .models import AuthEvent
from .storage import connect, persist_batch

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

@app.get("/health/storage")
def storage_health() -> dict:
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return {"status": "ok", "storage": "connected"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Storage unavailable: {type(exc).__name__}") from exc


@app.post("/ingest")
def ingest(request: IngestRequest, authorization: str | None = Header(default=None)) -> dict:
    """Persist an authenticated batch of authorized authentication telemetry."""
    expected = os.getenv("SENTINELX_INGEST_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Ingestion disabled: configure SENTINELX_INGEST_TOKEN.")
    if not hmac.compare_digest(authorization or "", f"Bearer {expected}"):
        raise HTTPException(status_code=401, detail="Invalid ingestion credential.")
    try:
        alerts = detect_brute_force(request.events, request.threshold, request.window_seconds)
        inserted_events, inserted_evidence = persist_batch(request.events, alerts)
        return {
            "status": "accepted",
            "persisted": True,
            "inserted_event_count": inserted_events,
            "inserted_evidence_count": inserted_evidence,
            "event_count": len(request.events),
            "alert_count": len(alerts),
            "alerts": [alert.model_dump(mode="json") for alert in alerts],
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Persistent ingestion failed: {type(exc).__name__}") from exc


@app.get("/incidents")
def list_incidents(status: str | None = None, limit: int = 100) -> dict:
    allowed = {"open", "investigating", "resolved", "false_positive"}
    if limit < 1 or limit > 500 or (status is not None and status not in allowed):
        raise HTTPException(status_code=422, detail="Invalid status or limit.")
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                if status:
                    cur.execute(
                        """SELECT incident_id,rule_id,title,severity,status,host(source_ip) AS source_ip,
                                  username,first_seen,last_seen,event_count,explanation,created_at,updated_at
                           FROM incidents WHERE status=%s ORDER BY updated_at DESC LIMIT %s""",
                        (status, limit),
                    )
                else:
                    cur.execute(
                        """SELECT incident_id,rule_id,title,severity,status,host(source_ip) AS source_ip,
                                  username,first_seen,last_seen,event_count,explanation,created_at,updated_at
                           FROM incidents ORDER BY updated_at DESC LIMIT %s""",
                        (limit,),
                    )
                rows = cur.fetchall()
        return {"count": len(rows), "incidents": rows}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Incident query failed: {type(exc).__name__}") from exc


@app.patch("/incidents/{incident_id}/status")
def update_incident_status(incident_id: str, status: str) -> dict:
    if status not in {"open", "investigating", "resolved", "false_positive"}:
        raise HTTPException(status_code=422, detail="Invalid incident status.")
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE incidents SET status=%s,updated_at=now(),
                              resolved_at=CASE WHEN %s='resolved' THEN now() ELSE NULL END
                       WHERE incident_id=%s
                       RETURNING incident_id,status,updated_at,resolved_at""",
                    (status, status, incident_id),
                )
                row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Incident not found.")
        return row
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Incident update failed: {type(exc).__name__}") from exc


@app.get("/incidents/{incident_id}/evidence")
def incident_evidence(incident_id: str, limit: int = 500) -> dict:
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 1000.")
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT e.event_id,e.occurred_at,host(e.source_ip) AS source_ip,e.username,
                              e.event_type,e.label,e.source_name
                       FROM incident_evidence ie JOIN auth_events e ON e.event_id=ie.event_id
                       WHERE ie.incident_id=%s ORDER BY e.occurred_at ASC LIMIT %s""",
                    (incident_id, limit),
                )
                rows = cur.fetchall()
        return {"count": len(rows), "evidence": rows}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Evidence query failed: {type(exc).__name__}") from exc
