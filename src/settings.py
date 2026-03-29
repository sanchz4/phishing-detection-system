from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.config_loader import load_runtime_config


@dataclass(slots=True)
class BankConfig:
    name: str
    short_name: str
    url: str
    login_url: str


@dataclass(slots=True)
class AppSettings:
    config_path: str
    known_banks: list[BankConfig]
    crawling: dict[str, Any]
    detection: dict[str, Any]
    icann: dict[str, Any]
    domain_discovery: dict[str, Any]

    @classmethod
    def from_file(cls, config_path: str = "config.json") -> "AppSettings":
        raw = load_runtime_config(config_path)
        return cls(
            config_path=config_path,
            known_banks=[BankConfig(**bank) for bank in raw.get("known_banks", [])],
            crawling=raw.get("crawling", {}),
            detection=raw.get("detection", {}),
            icann=raw.get("icann", {}),
            domain_discovery=raw.get("domain_discovery", {}),
        )
