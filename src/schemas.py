from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class AnalyzeRequest(BaseModel):
    inputs: list[str] = Field(default_factory=list)
    urls: list[str] | None = None
    input_type: Literal["auto", "url", "email"] = "auto"
    comprehensive: bool = True

    @model_validator(mode="after")
    def normalize_inputs(self) -> "AnalyzeRequest":
        if not self.inputs and self.urls:
            self.inputs = self.urls
        if not self.inputs:
            raise ValueError("At least one input is required.")
        return self


class HealthResponse(BaseModel):
    status: str
    chrome_available: bool
    tensorflow_available: bool
    banks_configured: int
    history_backend: str
    explainability_available: bool


class AppConfigResponse(BaseModel):
    banks: list[dict[str, str]]
    thresholds: dict[str, Any]
    detector_checks: list[str]
    supported_inputs: list[str]


class ExplanationItem(BaseModel):
    label: str
    value: float | str
    detail: str


class DetectionResultModel(BaseModel):
    id: str
    input_value: str
    input_type: str
    scanned_at: str
    is_phishing: bool = False
    risk_score: int = 0
    threat_category: str = "safe"
    confidence: float = 0
    confidence_level: Literal["low", "medium", "high"] = "low"
    target_brand: str | None = None
    explanation: str = ""
    reasons: list[str] = Field(default_factory=list)
    explanation_items: list[ExplanationItem] = Field(default_factory=list)
    threat_feeds: dict[str, Any] = Field(default_factory=dict)
    heuristics: dict[str, Any] = Field(default_factory=dict)
    reputation: dict[str, Any] = Field(default_factory=dict)
    ssl_analysis: dict[str, Any] = Field(default_factory=dict)
    brand_impersonation: dict[str, Any] = Field(default_factory=dict)
    content_analysis: dict[str, Any] = Field(default_factory=dict)
    qr_analysis: dict[str, Any] = Field(default_factory=dict)
    explainability: dict[str, Any] = Field(default_factory=dict)
    model_scores: dict[str, Any] = Field(default_factory=dict)
    raw_detector: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    html_analysis: dict[str, Any] = Field(default_factory=dict)


class AnalyzeResponse(BaseModel):
    results: list[DetectionResultModel]


class HistoryRecord(BaseModel):
    id: str
    input_value: str
    input_type: str
    risk_score: int
    threat_category: str
    confidence: float
    confidence_level: str
    scanned_at: str
    explanation: str


class HistoryResponse(BaseModel):
    items: list[HistoryRecord]
    total: int


class StatsResponse(BaseModel):
    total_scans: int
    dangerous_scans: int
    suspicious_scans: int
    safe_scans: int
    average_risk_score: float
    latest_scan_at: str | None = None
