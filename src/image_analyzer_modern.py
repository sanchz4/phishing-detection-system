from __future__ import annotations

from pathlib import Path
from typing import Any

import cv2
import numpy as np
from PIL import Image
from skimage.metrics import structural_similarity as ssim

try:
    from tensorflow.keras.applications.mobilenet_v2 import MobileNetV2, preprocess_input
    from tensorflow.keras.preprocessing import image as keras_image

    TENSORFLOW_AVAILABLE = True
except Exception:
    MobileNetV2 = None
    preprocess_input = None
    keras_image = None
    TENSORFLOW_AVAILABLE = False


class ImageAnalyzer:
    def __init__(self) -> None:
        self._model = None
        self._feature_cache: dict[str, np.ndarray] = {}

    @property
    def model(self):
        if self._model is None and TENSORFLOW_AVAILABLE and MobileNetV2 is not None:
            self._model = MobileNetV2(weights="imagenet", include_top=False, pooling="avg")
        return self._model

    def _load_image(self, image_input: Any) -> Image.Image:
        if isinstance(image_input, Image.Image):
            return image_input.convert("RGB")
        if isinstance(image_input, np.ndarray):
            return Image.fromarray(image_input).convert("RGB")
        return Image.open(image_input).convert("RGB")

    def extract_image_features(self, image_input: Any) -> np.ndarray:
        image_obj = self._load_image(image_input).resize((224, 224))
        if self.model is not None and keras_image is not None and preprocess_input is not None:
            array = keras_image.img_to_array(image_obj)
            array = np.expand_dims(array, axis=0)
            features = self.model.predict(preprocess_input(array), verbose=0)
            return features.flatten()
        histogram = np.array(image_obj.histogram(), dtype=np.float32)
        norm = np.linalg.norm(histogram)
        return histogram / norm if norm else histogram

    def calculate_similarity(self, first: np.ndarray, second: np.ndarray) -> float:
        numerator = float(np.dot(first, second))
        denominator = float(np.linalg.norm(first) * np.linalg.norm(second))
        return numerator / denominator if denominator else 0.0

    def structural_similarity(self, first: Image.Image, second: Image.Image) -> float:
        first_gray = cv2.cvtColor(np.array(first), cv2.COLOR_RGB2GRAY)
        second_gray = cv2.cvtColor(np.array(second.resize(first.size)), cv2.COLOR_RGB2GRAY)
        score, _ = ssim(first_gray, second_gray, full=True)
        return max(0.0, float(score))

    def analyze_screenshot(self, test_screenshot: Any, known_banks: list[dict]) -> dict[str, Any]:
        target_image = self._load_image(test_screenshot)
        target_features = self.extract_image_features(target_image)
        similarities: dict[str, dict[str, Any]] = {}
        for bank in known_banks:
            short_name = bank["short_name"]
            best_similarity = 0.0
            best_structural_similarity = 0.0
            best_type = None
            detail_map: dict[str, dict[str, Any]] = {}
            for suffix in ("_main", "_login", "_elements"):
                screenshot_path = Path("bank_screenshots") / f"{short_name}{suffix}.png"
                if not screenshot_path.exists():
                    detail_map[suffix] = {"error": "Screenshot not available", "overall_similarity": 0}
                    continue
                bank_features = self._feature_cache.get(str(screenshot_path))
                if bank_features is None:
                    bank_features = self.extract_image_features(screenshot_path)
                    self._feature_cache[str(screenshot_path)] = bank_features
                bank_image = self._load_image(screenshot_path)
                feature_similarity = self.calculate_similarity(target_features, bank_features)
                structural_similarity = self.structural_similarity(target_image, bank_image)
                overall_similarity = float((feature_similarity + structural_similarity) / 2)
                if overall_similarity > best_similarity:
                    best_similarity = overall_similarity
                    best_structural_similarity = structural_similarity
                    best_type = suffix
                detail_map[suffix] = {
                    "feature_similarity": feature_similarity,
                    "structural_similarity": structural_similarity,
                    "overall_similarity": overall_similarity,
                }
            similarities[short_name] = {
                "best_similarity": best_similarity,
                "best_structural_similarity": best_structural_similarity,
                "best_type": best_type,
                "all_similarities": detail_map,
            }
        return {"similarities": similarities, "features_extracted": True, "model": "mobilenetv2" if TENSORFLOW_AVAILABLE else "histogram-fallback"}
