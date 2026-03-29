from __future__ import annotations

import logging
import re
from datetime import datetime
from difflib import SequenceMatcher
from urllib.parse import urlparse

import tldextract

from src.icann_api_client import ICANNApiClient

LOGGER = logging.getLogger(__name__)


class DomainAnalyzer:
    def __init__(self, known_banks: list[dict], icann_api_key: str | None = None) -> None:
        self.known_banks = known_banks
        self.known_domains = self.extract_known_domains()
        self.suspicious_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "site", "online"}
        self.icann_client = ICANNApiClient(icann_api_key) if icann_api_key else None

    def extract_known_domains(self) -> dict[str, dict[str, str]]:
        domains: dict[str, dict[str, str]] = {}
        for bank in self.known_banks:
            domain = urlparse(bank["url"]).netloc.lower()
            extracted = tldextract.extract(domain)
            domains[bank["short_name"]] = {
                "full_domain": domain,
                "subdomain": extracted.subdomain,
                "domain_name": extracted.domain,
                "tld": extracted.suffix,
            }
        return domains

    def extract_domain_components(self, url: str) -> dict[str, str]:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        domain = parsed.netloc.lower()
        extracted = tldextract.extract(domain)
        return {
            "full_domain": domain,
            "subdomain": extracted.subdomain,
            "domain_name": extracted.domain,
            "tld": extracted.suffix,
            "path": parsed.path,
        }

    def levenshtein_similarity(self, first: str, second: str) -> float:
        return SequenceMatcher(None, first, second).ratio()

    def longest_common_substring_ratio(self, first: str, second: str) -> float:
        longest = 0
        table = [[0] * (len(second) + 1) for _ in range(len(first) + 1)]
        for first_index in range(1, len(first) + 1):
            for second_index in range(1, len(second) + 1):
                if first[first_index - 1] == second[second_index - 1]:
                    table[first_index][second_index] = table[first_index - 1][second_index - 1] + 1
                    longest = max(longest, table[first_index][second_index])
        return longest / max(len(first), len(second)) if longest else 0.0

    def calculate_domain_similarity(self, test_domain: str, bank_domain_info: dict[str, str]) -> tuple[float, dict[str, float]]:
        test_extracted = tldextract.extract(test_domain)
        bank_extracted = tldextract.extract(bank_domain_info["full_domain"])
        similarities = {
            "full_domain": self.levenshtein_similarity(test_domain, bank_domain_info["full_domain"]),
            "domain_name": self.levenshtein_similarity(test_extracted.domain, bank_extracted.domain),
            "subdomain": self.levenshtein_similarity(test_extracted.subdomain, bank_extracted.subdomain)
            if test_extracted.subdomain and bank_extracted.subdomain
            else 0.0,
            "common_substring": self.longest_common_substring_ratio(test_extracted.domain, bank_extracted.domain),
        }
        weights = {"domain_name": 0.6, "full_domain": 0.2, "common_substring": 0.15, "subdomain": 0.05}
        overall = sum(similarities[key] * weights[key] for key in weights)
        return overall, similarities

    def check_suspicious_patterns(self, components: dict[str, str]) -> list[str]:
        warnings: list[str] = []
        if components["tld"] in self.suspicious_tlds:
            warnings.append(f"Suspicious TLD: {components['tld']}")
        if "-" in components["domain_name"]:
            warnings.append("Contains hyphens")
        if re.search(r"\d{3,}", components["domain_name"]):
            warnings.append("Contains long number sequence")
        if len(components["domain_name"]) > 20:
            warnings.append("Unusually long domain name")
        return warnings

    def analyze_domain(self, test_url: str) -> dict:
        components = self.extract_domain_components(test_url)
        test_domain = components["full_domain"]
        similarities: dict[str, float] = {}
        details: dict[str, dict[str, float]] = {}
        warnings = self.check_suspicious_patterns(components)
        icann_data = None
        icann_risk_score = 0.0
        icann_risk_factors: list[str] = []

        if self.icann_client:
            try:
                icann_data = self.icann_client.get_domain_data(test_domain)
                risk_analysis = icann_data.get("risk_analysis", {}) if icann_data else {}
                icann_risk_score = float(risk_analysis.get("risk_score", 0))
                icann_risk_factors = list(risk_analysis.get("risk_factors", []))
                if icann_risk_score > 0.5:
                    warnings.extend(icann_risk_factors)
            except Exception as exc:
                LOGGER.warning("ICANN lookup failed for %s: %s", test_domain, exc)

        for short_name, bank_domain in self.known_domains.items():
            score, similarity_details = self.calculate_domain_similarity(test_domain, bank_domain)
            similarities[short_name] = score
            details[short_name] = similarity_details

        most_similar = max(similarities, key=similarities.get, default=None)
        max_similarity = similarities.get(most_similar, 0.0) if most_similar else 0.0
        combined_confidence = (max_similarity * 0.6) + (icann_risk_score * 0.4) if icann_risk_score else max_similarity

        return {
            "test_domain": test_domain,
            "domain_components": components,
            "similarities": similarities,
            "detailed_similarities": details,
            "most_similar": most_similar,
            "max_similarity": max_similarity,
            "warnings": warnings,
            "suspicious_score": len(warnings) * 0.1,
            "icann_data": icann_data,
            "icann_risk_score": icann_risk_score,
            "icann_risk_factors": icann_risk_factors,
            "combined_confidence": combined_confidence,
            "timestamp": datetime.now().isoformat(),
            "analysis_method": "domain_similarity_with_optional_icann",
        }
