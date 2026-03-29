from __future__ import annotations

from contextlib import suppress

from src.cyber_engine import CyberSecurityEngine
from src.detector_modern import PHISHING_TENSORFLOW_AVAILABLE
from src.risk_model import SHAP_AVAILABLE
from src.schemas import AnalyzeRequest
from src.settings import AppSettings


class DetectionService:
    def __init__(self, config_path: str = "config.json") -> None:
        self.settings = AppSettings.from_file(config_path)
        self._engine: CyberSecurityEngine | None = None

    @property
    def engine(self) -> CyberSecurityEngine:
        if self._engine is None:
            self._engine = CyberSecurityEngine(self.settings)
        return self._engine

    def analyze(self, payload: AnalyzeRequest) -> list[dict]:
        return [
            self.engine.analyze(item, input_type=payload.input_type, comprehensive=payload.comprehensive)
            for item in payload.inputs
        ]

    def get_public_config(self) -> dict:
        return {
            "banks": [{"name": bank.name, "short_name": bank.short_name, "url": bank.url} for bank in self.settings.known_banks],
            "thresholds": self.settings.detection,
            "detector_checks": [
                "URL heuristics",
                "WHOIS and DNS reputation",
                "TLS certificate checks",
                "HTML and JavaScript analysis",
                "Brand impersonation detection",
                "NLP content classification",
                "Threat-intelligence feed lookups",
                "Ensemble phishing risk modeling",
                "Quishing and IDN detection",
            ],
            "supported_inputs": ["url", "email"],
        }

    def health(self) -> dict:
        return {
            "status": "ok",
            "chrome_available": True,
            "tensorflow_available": PHISHING_TENSORFLOW_AVAILABLE,
            "banks_configured": len(self.settings.known_banks),
            "history_backend": "sqlite",
            "explainability_available": SHAP_AVAILABLE,
        }

    def list_history(self, risk_level: str | None = None) -> list[dict]:
        return self.engine.history.list(risk_level)

    def clear_history(self) -> None:
        self.engine.history.clear()

    def stats(self) -> dict:
        return self.engine.history.stats()

    def close(self) -> None:
        if self._engine is not None:
            with suppress(Exception):
                self._engine.close()
