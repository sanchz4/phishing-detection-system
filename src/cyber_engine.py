from __future__ import annotations

import re
import socket
import ssl
import uuid
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

from src.content_classifier import ContentClassifier
from src.detector_modern import PhishingDetector
from src.history_store import ScanHistoryStore
from src.icann_api_client import ICANNApiClient
from src.risk_model import EnsembleRiskModel
from src.settings import AppSettings
from src.threat_feeds import ThreatFeedIntegrator

try:
    import dns.resolver
except Exception:
    dns = None


class CyberSecurityEngine:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings
        self.history = ScanHistoryStore()
        self.content_classifier = ContentClassifier()
        self.threat_feeds = ThreatFeedIntegrator()
        self.risk_model = EnsembleRiskModel()
        self.detector = PhishingDetector(settings.config_path)
        api_key = settings.icann.get("api_key") if settings.icann.get("enabled") else None
        self.icann_client = ICANNApiClient(api_key) if api_key else None

    def analyze(self, value: str, *, input_type: str = "auto", comprehensive: bool = True) -> dict[str, Any]:
        normalized_type = self._resolve_input_type(value, input_type)
        result = self._analyze_email(value) if normalized_type == "email" else self._analyze_url(value, comprehensive=comprehensive)
        self.history.append(result)
        return result

    def _resolve_input_type(self, value: str, input_type: str) -> str:
        if input_type != "auto":
            return input_type
        if value.startswith("http://") or value.startswith("https://"):
            return "url"
        if "\n" in value or "@" in parseaddr(value)[1]:
            return "email"
        return "url"

    def _analyze_email(self, content: str) -> dict[str, Any]:
        classification = self.content_classifier.classify(content)
        urls = re.findall(r"https?://[^\s<>'\"]+", content)
        suspicious_terms = [term for term in ["urgent", "verify", "password", "wallet", "invoice", "qr code", "scan now"] if term in content.lower()]
        qr_score = 0.7 if "qr" in content.lower() and "scan" in content.lower() else 0.0
        feature_map = {
            "url_length": min(len(content) / 2000, 1.0),
            "special_char_density": min(sum(1 for char in content if not char.isalnum() and not char.isspace()) / max(len(content), 1), 1.0),
            "subdomain_depth": 0.0,
            "typosquat_risk": 0.0,
            "whois_age_risk": 0.0,
            "dns_anomaly_risk": 0.0,
            "ssl_risk": 0.0,
            "html_risk": 0.0,
            "brand_risk": 0.1 if any(bank.name.lower().split()[0] in content.lower() for bank in self.settings.known_banks) else 0.0,
            "nlp_risk": classification.confidence if classification.label == "phishing" else 0.1,
            "threat_feed_risk": 0.0,
            "idn_risk": 0.0,
            "qr_risk": qr_score,
        }
        model_output = self.risk_model.score(feature_map)
        risk_score = self._calculate_risk_score(feature_map, model_output)
        category = self._category_from_score(risk_score, classification.label == "phishing", qr_score > 0.5)
        reasons = [*classification.reasons, *[f"Suspicious email term: {term}" for term in suspicious_terms]]
        if urls:
            reasons.append(f"Embedded URLs detected: {len(urls)}")
        return self._build_result(
            input_value=content,
            input_type="email",
            risk_score=risk_score,
            threat_category=category,
            target_brand=self._extract_brand(content),
            reasons=reasons,
            feature_map=feature_map,
            threat_feeds={},
            heuristics={"embedded_urls": urls, "suspicious_terms": suspicious_terms},
            reputation={},
            ssl_analysis={},
            html_analysis={},
            brand_impersonation={"brand_candidate": self._extract_brand(content)},
            content_analysis={"label": classification.label, "confidence": classification.confidence},
            qr_analysis={"possible_quishing": qr_score > 0.5},
            explainability=model_output["explainability"],
            model_scores=model_output,
            raw_detector={},
            errors=[],
        )

    def _analyze_url(self, url: str, *, comprehensive: bool) -> dict[str, Any]:
        heuristics = self._url_heuristics(url)
        reputation = self._domain_reputation(url)
        ssl_analysis = self._ssl_analysis(url)
        page_payload = self._fetch_page(url)
        html_analysis = self._html_analysis(url, page_payload.get("html", ""))
        brand_impersonation = self._brand_impersonation(url, page_payload.get("html", ""))
        content_analysis = self._page_content_analysis(page_payload.get("text", ""))
        threat_feeds = self.threat_feeds.lookup(url)
        qr_analysis = self._qr_analysis(page_payload.get("html", ""))
        raw_detector = self.detector.analyze_url(url, comprehensive=comprehensive)

        feature_map = {
            "url_length": heuristics["length_risk"],
            "special_char_density": heuristics["symbol_risk"],
            "subdomain_depth": heuristics["subdomain_risk"],
            "typosquat_risk": brand_impersonation["lookalike_risk"],
            "whois_age_risk": reputation["age_risk"],
            "dns_anomaly_risk": reputation["dns_risk"],
            "ssl_risk": ssl_analysis["risk"],
            "html_risk": html_analysis["risk"],
            "brand_risk": brand_impersonation["brand_risk"],
            "nlp_risk": content_analysis["risk"],
            "threat_feed_risk": self.threat_feeds.aggregate_score(threat_feeds) / 100,
            "idn_risk": heuristics["idn_risk"],
            "qr_risk": qr_analysis["risk"],
        }
        model_output = self.risk_model.score(feature_map)
        risk_score = self._calculate_risk_score(feature_map, model_output)
        category = self._category_from_score(risk_score, html_analysis["credential_harvest_form"] or heuristics["idn_attack"], qr_analysis["detected"])
        reasons = self._collect_reasons(
            heuristics=heuristics,
            reputation=reputation,
            ssl_analysis=ssl_analysis,
            html_analysis=html_analysis,
            brand_impersonation=brand_impersonation,
            content_analysis=content_analysis,
            threat_feeds=threat_feeds,
            qr_analysis=qr_analysis,
            explainability=model_output["explainability"],
        )
        return self._build_result(
            input_value=url,
            input_type="url",
            risk_score=risk_score,
            threat_category=category,
            target_brand=brand_impersonation.get("brand_candidate"),
            reasons=reasons,
            feature_map=feature_map,
            threat_feeds=threat_feeds,
            heuristics=heuristics,
            reputation=reputation,
            ssl_analysis=ssl_analysis,
            html_analysis=html_analysis,
            brand_impersonation=brand_impersonation,
            content_analysis=content_analysis,
            qr_analysis=qr_analysis,
            explainability=model_output["explainability"],
            model_scores=model_output,
            raw_detector=raw_detector,
            errors=page_payload.get("errors", []),
        )

    def _url_heuristics(self, url: str) -> dict[str, Any]:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = parsed.netloc
        extracted = tldextract.extract(host)
        subdomain_depth = len([segment for segment in extracted.subdomain.split(".") if segment])
        special_chars = sum(1 for char in url if char in "@-_=%?&")
        idn_attack = host.startswith("xn--") or any(ord(char) > 127 for char in host)
        return {
            "host": host,
            "subdomain_depth": subdomain_depth,
            "length_risk": min(len(url) / 120, 1.0),
            "symbol_risk": min(special_chars / 12, 1.0),
            "subdomain_risk": min(subdomain_depth / 5, 1.0),
            "contains_ip": bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)),
            "has_at_symbol": "@" in url,
            "has_percent_encoding": "%" in url,
            "idn_attack": idn_attack,
            "idn_risk": 1.0 if idn_attack else 0.0,
        }

    def _domain_reputation(self, url: str) -> dict[str, Any]:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = parsed.netloc.lower()
        rdap = self.icann_client.get_domain_data(host) if self.icann_client else {"risk_analysis": {"risk_score": 0}}
        age_risk = float(rdap.get("risk_analysis", {}).get("risk_score", 0))
        dns_issues: list[str] = []
        dns_risk = 0.0
        try:
            socket.gethostbyname(host)
        except Exception:
            dns_issues.append("Host failed A record resolution")
            dns_risk += 0.5
        if dns is not None:
            try:
                answers = dns.resolver.resolve(host, "NS")
                if len([str(answer) for answer in answers]) <= 1:
                    dns_issues.append("Domain has limited NS redundancy")
                    dns_risk += 0.2
            except Exception:
                dns_issues.append("Unable to resolve NS records")
                dns_risk += 0.3
        return {"rdap": rdap, "age_risk": min(age_risk, 1.0), "dns_risk": min(dns_risk, 1.0), "dns_issues": dns_issues}

    def _ssl_analysis(self, url: str) -> dict[str, Any]:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        if parsed.scheme != "https":
            return {"valid": False, "risk": 1.0, "issuer": None, "expires_in_days": None, "reason": "URL is not HTTPS"}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((parsed.netloc, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.netloc) as wrapped:
                    certificate = wrapped.getpeercert()
            issuer = dict(item[0] for item in certificate.get("issuer", []))
            expiry = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            expires_in_days = (expiry - datetime.now(timezone.utc)).days
            risk = 0.5 if expires_in_days < 15 else 0.0
            return {
                "valid": True,
                "risk": min(risk, 1.0),
                "issuer": issuer.get("organizationName"),
                "expires_in_days": expires_in_days,
                "reason": "Certificate expires soon" if expires_in_days < 15 else "Certificate appears valid",
            }
        except Exception as exc:
            return {"valid": False, "risk": 0.9, "issuer": None, "expires_in_days": None, "reason": f"TLS validation failed: {exc}"}

    def _fetch_page(self, url: str) -> dict[str, Any]:
        try:
            response = requests.get(url, timeout=12, headers={"User-Agent": self.settings.crawling.get("user_agent", "Mozilla/5.0")})
            html = response.text
            soup = BeautifulSoup(html, "html.parser")
            return {"html": html, "text": soup.get_text(" ", strip=True)[:4000], "errors": []}
        except Exception as exc:
            return {"html": "", "text": "", "errors": [f"Failed to fetch page content: {exc}"]}

    def _html_analysis(self, url: str, html: str) -> dict[str, Any]:
        if not html:
            return {"risk": 0.0, "hidden_iframes": 0, "suspicious_form_actions": [], "obfuscated_js_indicators": [], "credential_harvest_form": False}
        soup = BeautifulSoup(html, "html.parser")
        hidden_iframes = len([iframe for iframe in soup.find_all("iframe") if "display:none" in iframe.get("style", "").replace(" ", "").lower() or iframe.get("width") == "0"])
        suspicious_form_actions = []
        credential_harvest_form = False
        parsed = urlparse(url)
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action and action.startswith("http") and urlparse(action).netloc != parsed.netloc:
                suspicious_form_actions.append(action)
            if "password" in {field.get("type", "").lower() for field in form.find_all("input")}:
                credential_harvest_form = True
        html_lower = html.lower()
        obfuscated_tokens = [token for token in ["eval(", "atob(", "fromcharcode", "unescape(", "settimeout("] if token in html_lower]
        risk = min((hidden_iframes * 0.2) + (len(suspicious_form_actions) * 0.2) + (len(obfuscated_tokens) * 0.15), 1.0)
        return {
            "risk": risk,
            "hidden_iframes": hidden_iframes,
            "suspicious_form_actions": suspicious_form_actions,
            "obfuscated_js_indicators": obfuscated_tokens,
            "credential_harvest_form": credential_harvest_form,
        }

    def _brand_impersonation(self, url: str, html: str) -> dict[str, Any]:
        host = urlparse(url if "://" in url else f"https://{url}").netloc.lower()
        domain = tldextract.extract(host).domain.lower()
        best_bank = None
        best_score = 0.0
        html_lower = html.lower()
        for bank in self.settings.known_banks:
            bank_key = bank.short_name.lower()
            bank_name = bank.name.lower()
            shared = sum(1 for char in domain if char in bank_key)
            similarity = min(shared / max(len(domain), len(bank_key), 1), 1.0)
            page_mentions = 0.25 if bank_name in html_lower or bank_key in html_lower else 0.0
            score = min(similarity + page_mentions, 1.0)
            if score > best_score:
                best_score = score
                best_bank = bank.name
        return {"brand_candidate": best_bank, "lookalike_risk": best_score, "brand_risk": best_score}

    def _page_content_analysis(self, text: str) -> dict[str, Any]:
        classification = self.content_classifier.classify(text[:5000])
        risk = classification.confidence if classification.label == "phishing" else 0.1
        return {"label": classification.label, "confidence": classification.confidence, "risk": risk, "reasons": classification.reasons}

    def _qr_analysis(self, html: str) -> dict[str, Any]:
        html_lower = html.lower()
        suspicious_tokens = [token for token in ["qr", "scan code", "scan this", "wallet connect", "device pairing"] if token in html_lower]
        risk = min(len(suspicious_tokens) * 0.25, 1.0)
        return {"detected": bool(suspicious_tokens), "risk": risk, "signals": suspicious_tokens}

    def _collect_reasons(self, **sections: dict[str, Any]) -> list[str]:
        reasons: list[str] = []
        heuristics = sections["heuristics"]
        if heuristics.get("has_at_symbol"):
            reasons.append("URL contains '@' redirection indicator")
        if heuristics.get("contains_ip"):
            reasons.append("URL uses direct IP addressing")
        if heuristics.get("subdomain_depth", 0) >= 3:
            reasons.append("Excessive subdomain depth")
        if heuristics.get("idn_attack"):
            reasons.append("Possible homograph/IDN attack")
        reputation = sections["reputation"]
        reasons.extend(reputation.get("dns_issues", []))
        if reputation.get("age_risk", 0) > 0.4:
            reasons.append("Young or risky domain registration profile")
        ssl_analysis = sections["ssl_analysis"]
        if ssl_analysis.get("risk", 0) > 0.3:
            reasons.append(ssl_analysis.get("reason", "SSL/TLS anomalies detected"))
        html_analysis = sections["html_analysis"]
        if html_analysis.get("hidden_iframes", 0):
            reasons.append("Hidden iframes detected in page content")
        if html_analysis.get("suspicious_form_actions"):
            reasons.append("Forms submit to suspicious or off-domain targets")
        if html_analysis.get("obfuscated_js_indicators"):
            reasons.append("Obfuscated JavaScript patterns detected")
        brand = sections["brand_impersonation"]
        if brand.get("brand_risk", 0) > 0.35 and brand.get("brand_candidate"):
            reasons.append(f"Potential brand impersonation of {brand['brand_candidate']}")
        content = sections["content_analysis"]
        reasons.extend(content.get("reasons", [])[:3])
        threat_feeds = sections["threat_feeds"]
        for name, result in threat_feeds.items():
            if result.get("listed"):
                reasons.append(f"Matched in {name.replace('_', ' ').title()}")
        qr_analysis = sections["qr_analysis"]
        if qr_analysis.get("detected"):
            reasons.append("QR phishing indicators detected on page")
        explainability = sections["explainability"]
        for item in explainability.get("top_features", [])[:3]:
            reasons.append(f"Model signal: {item['feature']} ({item['impact']})")
        deduped = []
        for reason in reasons:
            if reason not in deduped:
                deduped.append(reason)
        return deduped[:10]

    def _calculate_risk_score(self, feature_map: dict[str, float], model_output: dict[str, Any]) -> int:
        heuristic_score = sum(feature_map.values()) / max(len(feature_map), 1)
        model_score = (model_output["ensemble_probability"] * 0.75) + min(model_output["anomaly_score"], 1.0) * 0.25
        return max(0, min(100, round(((heuristic_score * 0.55) + (model_score * 0.45)) * 100)))

    def _category_from_score(self, risk_score: int, credential_signal: bool, qr_signal: bool) -> str:
        if qr_signal and risk_score >= 55:
            return "dangerous"
        if credential_signal and risk_score >= 50:
            return "dangerous"
        if risk_score >= 70:
            return "dangerous"
        if risk_score >= 40:
            return "suspicious"
        return "safe"

    def _build_result(self, *, input_value: str, input_type: str, risk_score: int, threat_category: str, target_brand: str | None, reasons: list[str], feature_map: dict[str, float], threat_feeds: dict[str, Any], heuristics: dict[str, Any], reputation: dict[str, Any], ssl_analysis: dict[str, Any], html_analysis: dict[str, Any], brand_impersonation: dict[str, Any], content_analysis: dict[str, Any], qr_analysis: dict[str, Any], explainability: dict[str, Any], model_scores: dict[str, Any], raw_detector: dict[str, Any], errors: list[str]) -> dict[str, Any]:
        confidence = round(min(0.99, max(risk_score / 100, model_scores.get("ensemble_probability", 0))), 4)
        confidence_level = "high" if confidence >= 0.75 else "medium" if confidence >= 0.45 else "low"
        explanation_items = [{"label": name.replace("_", " ").title(), "value": round(value * 100, 2), "detail": f"Feature contribution for {name}"} for name, value in sorted(feature_map.items(), key=lambda item: item[1], reverse=True)[:5]]
        return {
            "id": str(uuid.uuid4()),
            "input_value": input_value,
            "input_type": input_type,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "is_phishing": threat_category != "safe",
            "risk_score": risk_score,
            "threat_category": threat_category,
            "confidence": confidence,
            "confidence_level": confidence_level,
            "target_brand": target_brand,
            "explanation": reasons[0] if reasons else "No major phishing indicators detected.",
            "reasons": reasons,
            "explanation_items": explanation_items,
            "threat_feeds": threat_feeds,
            "heuristics": heuristics,
            "reputation": reputation,
            "ssl_analysis": ssl_analysis,
            "html_analysis": html_analysis,
            "brand_impersonation": brand_impersonation,
            "content_analysis": content_analysis,
            "qr_analysis": qr_analysis,
            "explainability": explainability,
            "model_scores": model_scores,
            "raw_detector": raw_detector,
            "errors": errors,
        }

    def _extract_brand(self, text: str) -> str | None:
        lower = text.lower()
        for bank in self.settings.known_banks:
            if bank.short_name in lower or bank.name.lower() in lower:
                return bank.name
        return None

    def close(self) -> None:
        self.detector.close()
