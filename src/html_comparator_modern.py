from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class HTMLComparator:
    def __init__(self) -> None:
        self.vectorizer = TfidfVectorizer(stop_words="english", max_features=1000)

    def extract_html_features(self, html_content: str) -> dict[str, Any]:
        soup = BeautifulSoup(html_content, "html.parser")
        features = {
            "forms": [],
            "text_content": soup.get_text(" ", strip=True),
            "links": [anchor.get("href") for anchor in soup.find_all("a") if anchor.get("href")],
            "scripts": [script.get("src") for script in soup.find_all("script") if script.get("src")],
        }
        for form in soup.find_all("form"):
            features["forms"].append(
                {
                    "action": form.get("action", ""),
                    "method": form.get("method", ""),
                    "inputs": [
                        {"type": input_tag.get("type", ""), "name": input_tag.get("name", ""), "id": input_tag.get("id", "")}
                        for input_tag in form.find_all("input")
                    ],
                }
            )
        return features

    def compare_html_structures(self, first: dict[str, Any], second: dict[str, Any]) -> dict[str, float]:
        return {
            "form_similarity": self._compare_forms(first["forms"], second["forms"]),
            "content_similarity": self._compare_text_content(first["text_content"], second["text_content"]),
            "link_similarity": self._compare_links(first["links"], second["links"]),
        }

    def _compare_forms(self, first_forms: list[dict], second_forms: list[dict]) -> float:
        if not first_forms or not second_forms:
            return 0.0
        count_similarity = 1 - abs(len(first_forms) - len(second_forms)) / max(len(first_forms), len(second_forms))
        best_structure_similarity = 0.0
        for first_form in first_forms:
            first_types = {field["type"] for field in first_form["inputs"]}
            for second_form in second_forms:
                second_types = {field["type"] for field in second_form["inputs"]}
                if not first_types or not second_types:
                    continue
                overlap = len(first_types.intersection(second_types)) / max(len(first_types), len(second_types))
                best_structure_similarity = max(best_structure_similarity, overlap)
        return float((count_similarity + best_structure_similarity) / 2)

    def _compare_text_content(self, first: str, second: str) -> float:
        if not first.strip() or not second.strip():
            return 0.0
        first_clean = re.sub(r"\s+", " ", first.strip())
        second_clean = re.sub(r"\s+", " ", second.strip())
        matrix = self.vectorizer.fit_transform([first_clean, second_clean])
        return float(cosine_similarity(matrix[0:1], matrix[1:2])[0][0])

    def _compare_links(self, first: list[str], second: list[str]) -> float:
        if not first or not second:
            return 0.0
        count_similarity = 1 - abs(len(first) - len(second)) / max(len(first), len(second))
        first_set = set(first)
        second_set = set(second)
        link_similarity = len(first_set.intersection(second_set)) / max(len(first_set), len(second_set))
        return float((count_similarity + link_similarity) / 2)

    def detect_phishing_patterns(self, html_features: dict[str, Any]) -> list[str]:
        warnings: list[str] = []
        for form in html_features["forms"]:
            for input_field in form["inputs"]:
                if input_field["type"] == "hidden" and "password" in input_field.get("name", "").lower():
                    warnings.append("Hidden password field detected")
            action = form.get("action", "")
            if action and not action.startswith(("http", "#", "/")):
                warnings.append("Suspicious form action")
        if len([script for script in html_features["scripts"] if script and script.startswith("http")]) > 5:
            warnings.append("Many external scripts detected")
        return warnings
