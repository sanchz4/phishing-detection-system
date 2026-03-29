from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    urls: list[str] = Field(min_length=1)
    comprehensive: bool = True


class HealthResponse(BaseModel):
    status: str
    chrome_available: bool
    tensorflow_available: bool
    banks_configured: int


class AppConfigResponse(BaseModel):
    banks: list[dict[str, str]]
    thresholds: dict[str, Any]


class DetectionResultModel(BaseModel):
    url: str
    timestamp: str
    is_phishing: bool = False
    confidence: float = 0
    target_bank: str | None = None
    target_bank_name: str | None = None
    errors: list[str] = Field(default_factory=list)
    domain_analysis: dict[str, Any] = Field(default_factory=dict)
    image_analysis: dict[str, Any] = Field(default_factory=dict)
    hash_analysis: dict[str, Any] = Field(default_factory=dict)
    html_analysis: dict[str, Any] = Field(default_factory=dict)
    phishing_patterns: list[str] = Field(default_factory=list)
    analysis_type: str = "basic"


class AnalyzeResponse(BaseModel):
    results: list[DetectionResultModel]
