from __future__ import annotations

from contextlib import suppress

from src.detector_modern import PHISHING_TENSORFLOW_AVAILABLE, PhishingDetector
from src.schemas import AnalyzeRequest
from src.settings import AppSettings


class DetectionService:
    def __init__(self, config_path: str = "config.json") -> None:
        self.settings = AppSettings.from_file(config_path)
        self._detector: PhishingDetector | None = None

    @property
    def detector(self) -> PhishingDetector:
        if self._detector is None:
            self._detector = PhishingDetector(self.settings.config_path)
        return self._detector

    def analyze(self, payload: AnalyzeRequest) -> list[dict]:
        return [self.detector.analyze_url(url, comprehensive=payload.comprehensive) for url in payload.urls]

    def get_public_config(self) -> dict:
        return {
            "banks": [{"name": bank.name, "short_name": bank.short_name, "url": bank.url} for bank in self.settings.known_banks],
            "thresholds": self.settings.detection,
        }

    def health(self) -> dict:
        return {
            "status": "ok",
            "chrome_available": True,
            "tensorflow_available": PHISHING_TENSORFLOW_AVAILABLE,
            "banks_configured": len(self.settings.known_banks),
        }

    def close(self) -> None:
        if self._detector is not None:
            with suppress(Exception):
                self._detector.close()
