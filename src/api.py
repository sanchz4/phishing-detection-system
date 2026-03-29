from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.schemas import AnalyzeRequest, AnalyzeResponse, AppConfigResponse, HealthResponse
from src.service import DetectionService

app = FastAPI(
    title="Phishing Detection System API",
    version="2.0.0",
    description="Typed REST API for phishing analysis and dashboard integration.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
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
