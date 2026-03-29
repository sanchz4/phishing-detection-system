from __future__ import annotations

import os
from urllib.parse import urlparse

import requests


class ThreatFeedIntegrator:
    def __init__(self) -> None:
        self.safe_browsing_key = os.getenv("SAFE_BROWSING_API_KEY", "")

    def lookup(self, url: str) -> dict[str, dict]:
        return {
            "phishtank": self._lookup_phishtank(url),
            "openphish": self._lookup_openphish(url),
            "google_safe_browsing": self._lookup_safe_browsing(url),
        }

    def _lookup_phishtank(self, url: str) -> dict:
        try:
            response = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": url, "format": "json"},
                timeout=10,
                headers={"User-Agent": "phishing-detection-system"},
            )
            if response.ok:
                payload = response.json()
                results = payload.get("results", {})
                return {
                    "listed": bool(results.get("in_database") and results.get("verified")),
                    "verified": bool(results.get("verified")),
                    "source": "PhishTank",
                }
        except Exception:
            pass
        return {"listed": False, "verified": False, "source": "PhishTank", "status": "unavailable"}

    def _lookup_openphish(self, url: str) -> dict:
        host = urlparse(url).netloc.lower()
        try:
            response = requests.get("https://openphish.com/feed.txt", timeout=10)
            if response.ok:
                sample = response.text.splitlines()[:5000]
                listed = any(url == line.strip() or host in line.strip() for line in sample)
                return {"listed": listed, "source": "OpenPhish"}
        except Exception:
            pass
        return {"listed": False, "source": "OpenPhish", "status": "unavailable"}

    def _lookup_safe_browsing(self, url: str) -> dict:
        if not self.safe_browsing_key:
            return {"listed": False, "source": "Google Safe Browsing", "status": "not_configured"}
        try:
            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.safe_browsing_key}",
                json={
                    "client": {"clientId": "phishing-detection-system", "clientVersion": "2.1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                },
                timeout=10,
            )
            if response.ok:
                payload = response.json()
                matches = payload.get("matches", [])
                return {
                    "listed": bool(matches),
                    "match_count": len(matches),
                    "source": "Google Safe Browsing",
                }
        except Exception:
            pass
        return {"listed": False, "source": "Google Safe Browsing", "status": "unavailable"}

    @staticmethod
    def aggregate_score(feed_results: dict[str, dict]) -> int:
        score = 0
        for result in feed_results.values():
            if result.get("listed"):
                score += 35
                if result.get("verified"):
                    score += 10
        return min(score, 100)
