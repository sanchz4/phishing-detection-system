from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier

try:
    import shap

    SHAP_AVAILABLE = True
except Exception:
    shap = None
    SHAP_AVAILABLE = False

try:
    from xgboost import XGBClassifier
except Exception:
    XGBClassifier = None

try:
    from lightgbm import LGBMClassifier
except Exception:
    LGBMClassifier = None


class EnsembleRiskModel:
    def __init__(self) -> None:
        self.feature_names = [
            "url_length",
            "special_char_density",
            "subdomain_depth",
            "typosquat_risk",
            "whois_age_risk",
            "dns_anomaly_risk",
            "ssl_risk",
            "html_risk",
            "brand_risk",
            "nlp_risk",
            "threat_feed_risk",
            "idn_risk",
            "qr_risk",
        ]
        self.models = self._fit_models()
        self.anomaly_model = IsolationForest(random_state=42, contamination=0.15)
        self.anomaly_model.fit(np.array(self._training_vectors()))

    def _training_vectors(self) -> list[list[float]]:
        return [
            [0.15, 0.05, 0.1, 0.0, 0.05, 0.0, 0.05, 0.1, 0.0, 0.05, 0.0, 0.0, 0.0],
            [0.25, 0.1, 0.15, 0.2, 0.1, 0.1, 0.2, 0.25, 0.1, 0.2, 0.0, 0.0, 0.0],
            [0.55, 0.45, 0.55, 0.7, 0.8, 0.4, 0.8, 0.75, 0.8, 0.7, 0.6, 0.7, 0.1],
            [0.65, 0.5, 0.7, 0.8, 0.9, 0.7, 0.9, 0.85, 0.9, 0.75, 0.8, 0.9, 0.2],
            [0.4, 0.35, 0.2, 0.35, 0.2, 0.1, 0.4, 0.3, 0.35, 0.2, 0.0, 0.1, 0.0],
            [0.5, 0.3, 0.2, 0.2, 0.1, 0.1, 0.3, 0.25, 0.2, 0.6, 0.0, 0.0, 0.8],
            [0.2, 0.15, 0.1, 0.0, 0.0, 0.0, 0.1, 0.15, 0.0, 0.1, 0.0, 0.0, 0.0],
            [0.7, 0.55, 0.4, 0.75, 0.85, 0.6, 0.85, 0.9, 0.85, 0.8, 0.7, 1.0, 0.6],
        ]

    def _training_labels(self) -> list[int]:
        return [0, 0, 1, 1, 0, 1, 0, 1]

    def _fit_models(self) -> list[Any]:
        X = np.array(self._training_vectors())
        y = np.array(self._training_labels())
        models: list[Any] = [
            RandomForestClassifier(n_estimators=120, random_state=42),
            GradientBoostingClassifier(random_state=42),
        ]
        if XGBClassifier is not None:
            models.append(XGBClassifier(n_estimators=80, max_depth=4, learning_rate=0.1, subsample=0.9, eval_metric="logloss"))
        if LGBMClassifier is not None:
            models.append(LGBMClassifier(n_estimators=100, random_state=42))
        for model in models:
            model.fit(X, y)
        return models

    def score(self, features: dict[str, float]) -> dict[str, Any]:
        vector = np.array([[float(features.get(name, 0.0)) for name in self.feature_names]])
        probabilities = []
        for model in self.models:
            if hasattr(model, "predict_proba"):
                probabilities.append(float(model.predict_proba(vector)[0][1]))
        mean_probability = float(np.mean(probabilities)) if probabilities else 0.0
        anomaly_score = float(-self.anomaly_model.score_samples(vector)[0])
        return {
            "ensemble_probability": mean_probability,
            "anomaly_score": anomaly_score,
            "per_model_scores": probabilities,
            "explainability": self.explain(features, vector),
        }

    def explain(self, features: dict[str, float], vector: np.ndarray) -> dict[str, Any]:
        ranked = sorted(features.items(), key=lambda item: abs(item[1]), reverse=True)[:5]
        fallback = [{"feature": key, "impact": round(value, 4)} for key, value in ranked]
        if not SHAP_AVAILABLE:
            return {"method": "feature-importance-fallback", "top_features": fallback}
        try:
            explainer = shap.TreeExplainer(self.models[0])
            shap_values = explainer.shap_values(vector)
            values = shap_values[0] if isinstance(shap_values, list) else shap_values[0]
            ranking = sorted(
                [{"feature": self.feature_names[index], "impact": round(float(values[index]), 4)} for index in range(len(self.feature_names))],
                key=lambda item: abs(item["impact"]),
                reverse=True,
            )[:5]
            return {"method": "shap", "top_features": ranking}
        except Exception:
            return {"method": "feature-importance-fallback", "top_features": fallback}
