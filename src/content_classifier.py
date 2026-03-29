from __future__ import annotations

from dataclasses import dataclass

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


@dataclass(slots=True)
class ClassificationResult:
    label: str
    confidence: float
    reasons: list[str]


class ContentClassifier:
    def __init__(self) -> None:
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        self.model = LogisticRegression(max_iter=500)
        self._fit_demo_model()

    def _fit_demo_model(self) -> None:
        samples = [
            "welcome to your secure banking dashboard review recent transactions",
            "company newsletter and account overview for customers",
            "verify your account immediately to avoid suspension login now",
            "urgent security alert confirm your credentials now",
            "invoice attached please review payment details in portal",
            "reset your mailbox password to prevent account deactivation",
            "scan this qr code to re-activate your corporate vpn access",
            "limited time reward claim your banking bonus and login here",
        ]
        labels = ["safe", "safe", "phishing", "phishing", "safe", "phishing", "phishing", "phishing"]
        matrix = self.vectorizer.fit_transform(samples)
        self.model.fit(matrix, labels)

    def classify(self, text: str) -> ClassificationResult:
        if not text.strip():
            return ClassificationResult(label="safe", confidence=0.0, reasons=[])
        matrix = self.vectorizer.transform([text])
        probabilities = self.model.predict_proba(matrix)[0]
        label = self.model.predict(matrix)[0]
        confidence = float(max(probabilities))
        feature_names = self.vectorizer.get_feature_names_out()
        scores = matrix.toarray()[0]
        ranked = sorted(
            [(feature_names[index], score) for index, score in enumerate(scores) if score > 0],
            key=lambda item: item[1],
            reverse=True,
        )[:5]
        reasons = [f"Content signal: '{term}'" for term, _ in ranked]
        return ClassificationResult(label=label, confidence=confidence, reasons=reasons)
