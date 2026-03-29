from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.schemas import AnalyzeRequest, AnalyzeResponse, AppConfigResponse, HealthResponse, HistoryResponse, StatsResponse
from src.service import DetectionService

app = FastAPI(
    title="Phishing Detection System API",
    version="2.0.0",
    description="Typed REST API for phishing analysis and dashboard integration.",
)


def _allowed_origins() -> list[str]:
    raw_value = os.getenv("APP_CORS_ORIGINS", "")
    if raw_value.strip():
        return [origin.strip() for origin in raw_value.split(",") if origin.strip()]

    return [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

service = DetectionService()


@app.get("/api/health", response_model=HealthResponse)
def health() -> dict:
    return service.health()


@app.get("/api/config", response_model=AppConfigResponse)
def app_config() -> dict:
    return service.get_public_config()


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest) -> dict:
    return {"results": service.analyze(payload)}


@app.get("/api/history", response_model=HistoryResponse)
def history(risk_level: str | None = None) -> dict:
    items = service.list_history(risk_level)
    return {"items": items, "total": len(items)}


@app.delete("/api/history")
def clear_history() -> dict:
    service.clear_history()
    return {"status": "cleared"}


@app.get("/api/stats", response_model=StatsResponse)
def stats() -> dict:
    return service.stats()
