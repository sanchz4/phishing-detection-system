from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from src.config_loader import load_runtime_config
from src.crawler_modern import Crawler
from src.domain_analyzer_modern import DomainAnalyzer
from src.enhanced_crawler_modern import EnhancedCrawler
from src.html_comparator_modern import HTMLComparator
from src.icann_api_client import ICANNApiClient
from src.image_analyzer_modern import ImageAnalyzer, TENSORFLOW_AVAILABLE as PHISHING_TENSORFLOW_AVAILABLE
from src.image_hasher_modern import ImageHasher

LOGGER = logging.getLogger(__name__)


class PhishingDetector:
    def __init__(self, config_path: str = "config.json") -> None:
        self.config = load_runtime_config(config_path)
        self.image_analyzer = ImageAnalyzer()
        self.image_hasher = ImageHasher()

        icann_config = self.config.get("icann", {})
        api_key = icann_config.get("api_key")
        icann_enabled = bool(icann_config.get("enabled") and api_key)

        self.domain_analyzer = DomainAnalyzer(self.config["known_banks"], api_key if icann_enabled else None)
        self.icann_client = ICANNApiClient(api_key) if icann_enabled else None
        self.crawler = Crawler(self.config["crawling"])
        self.enhanced_crawler = EnhancedCrawler(self.crawler.driver, self.config["crawling"])
        self.html_comparator = HTMLComparator()

    def analyze_url(self, url: str, comprehensive: bool = True) -> dict[str, Any]:
        screenshot = self.crawler.capture_screenshot(url)
        timestamp = datetime.now().isoformat()
        if screenshot is None:
            return {
                "url": url,
                "timestamp": timestamp,
                "is_phishing": False,
                "confidence": 0,
                "errors": ["Unable to capture screenshot"],
                "analysis_type": "failed",
                "domain_analysis": {},
                "image_analysis": {},
                "hash_analysis": {},
                "html_analysis": {},
                "phishing_patterns": [],
            }

        hash_results = self._perform_hash_analysis(screenshot)
        analysis = self._comprehensive_analysis(url, screenshot) if comprehensive else self._basic_analysis(url, screenshot)
        return {**analysis, **hash_results, "timestamp": timestamp}

    def _perform_hash_analysis(self, screenshot: Any) -> dict[str, Any]:
        matches = self.image_hasher.compare_with_banks(screenshot, self.config["known_banks"])
        best_match = None
        max_similarity = 0.0
        for bank_name, result in matches.items():
            similarity = float(result.get("similarity", 0))
            if similarity > max_similarity:
                max_similarity = similarity
                best_match = bank_name
        return {
            "hash_analysis": matches,
            "best_hash_match": best_match,
            "max_hash_similarity": max_similarity,
            "hash_detection": max_similarity >= 80,
        }

    def _basic_analysis(self, url: str, screenshot: Any) -> dict[str, Any]:
        domain_results = self.domain_analyzer.analyze_domain(url)
        image_results = self.image_analyzer.analyze_screenshot(screenshot, self.config["known_banks"])
        return self.combine_results(domain_results, image_results, url, analysis_type="basic")

    def _comprehensive_analysis(self, url: str, screenshot: Any) -> dict[str, Any]:
        try:
            crawl_stats = self.enhanced_crawler.comprehensive_crawl(url)
            basic = self._basic_analysis(url, screenshot)
            main_page_html = self.enhanced_crawler.html_contents.get(url)
            html_results: dict[str, Any] = {}
            phishing_patterns: list[str] = []

            if main_page_html:
                target_features = self.html_comparator.extract_html_features(main_page_html)
                phishing_patterns = self.html_comparator.detect_phishing_patterns(target_features)
                for bank in self.config["known_banks"]:
                    try:
                        bank_html = self.crawler.fetch_html(bank["url"])
                        bank_features = self.html_comparator.extract_html_features(bank_html)
                        html_results[bank["short_name"]] = self.html_comparator.compare_html_structures(target_features, bank_features)
                    except Exception as exc:
                        html_results[bank["short_name"]] = {"error": str(exc)}

            result = {
                **basic,
                "crawl_stats": crawl_stats,
                "html_analysis": html_results,
                "phishing_patterns": phishing_patterns,
                "pages_crawled": list(self.enhanced_crawler.visited_urls),
                "subdomains_discovered": list(self.enhanced_crawler.subdomains),
                "analysis_type": "comprehensive",
            }
            return self._apply_html_weight(result)
        except Exception as exc:
            LOGGER.exception("Comprehensive analysis failed")
            basic = self._basic_analysis(url, screenshot)
            basic.setdefault("errors", []).append(f"Comprehensive analysis failed: {exc}")
            return basic

    def _apply_html_weight(self, result: dict[str, Any]) -> dict[str, Any]:
        html_results = result.get("html_analysis", {})
        if not html_results:
            return result
        best_html_similarity = max(
            (
                float(item.get("content_similarity", 0))
                for item in html_results.values()
                if isinstance(item, dict)
            ),
            default=0.0,
        )
        html_weight = float(self.config["detection"].get("html_similarity_weight", 0.3))
        result["confidence"] = (1 - html_weight) * float(result["confidence"]) + html_weight * best_html_similarity
        result["is_phishing"] = result["confidence"] >= float(self.config["detection"]["phishing_threshold"])
        return result

    def combine_results(self, domain_results: dict[str, Any], image_results: dict[str, Any], url: str, analysis_type: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "url": url,
            "domain_analysis": domain_results,
            "image_analysis": image_results,
            "is_phishing": False,
            "confidence": 0.0,
            "target_bank": None,
            "target_bank_name": None,
            "errors": [],
            "html_analysis": {},
            "phishing_patterns": [],
            "analysis_type": analysis_type,
        }

        max_similarity = 0.0
        target_bank = None
        for bank in self.config["known_banks"]:
            short_name = bank["short_name"]
            domain_similarity = float(domain_results.get("similarities", {}).get(short_name, 0))
            image_result = image_results.get("similarities", {}).get(short_name, {})
            feature_similarity = float(image_result.get("best_similarity", 0))
            structural_similarity = float(image_result.get("best_structural_similarity", 0))
            overall_similarity = (
                float(self.config["detection"]["domain_similarity_weight"]) * domain_similarity
                + float(self.config["detection"]["image_similarity_weight"]) * feature_similarity
                + float(self.config["detection"]["structural_similarity_weight"]) * structural_similarity
            )
            if overall_similarity > max_similarity:
                max_similarity = overall_similarity
                target_bank = short_name

        confidence = float(domain_results.get("combined_confidence", max_similarity))
        result["confidence"] = confidence
        result["is_phishing"] = confidence >= float(self.config["detection"]["phishing_threshold"])
        result["target_bank"] = target_bank
        if target_bank:
            result["target_bank_name"] = next(
                (bank["name"] for bank in self.config["known_banks"] if bank["short_name"] == target_bank),
                None,
            )
        return result

    def close(self) -> None:
        self.crawler.close()
