from __future__ import annotations

from pathlib import Path
from typing import Any

import imagehash
import numpy as np
from PIL import Image


class ImageHasher:
    def compute_hashes(self, image_input: Any) -> dict[str, str]:
        if isinstance(image_input, np.ndarray):
            image_obj = Image.fromarray(image_input).convert("RGB")
        elif isinstance(image_input, Image.Image):
            image_obj = image_input.convert("RGB")
        else:
            image_obj = Image.open(image_input).convert("RGB")
        return {
            "ahash": str(imagehash.average_hash(image_obj)),
            "dhash": str(imagehash.dhash(image_obj)),
            "phash": str(imagehash.phash(image_obj)),
        }

    def calculate_similarity(self, first: dict[str, str], second: dict[str, str]) -> float:
        scores = []
        for algorithm in ("ahash", "dhash", "phash"):
            first_hash = imagehash.hex_to_hash(first[algorithm])
            second_hash = imagehash.hex_to_hash(second[algorithm])
            scores.append(max(0.0, 100 * (1 - ((first_hash - second_hash) / 64))))
        return float(sum(scores) / len(scores)) if scores else 0.0

    def compare_with_banks(self, image_input: Any, known_banks: list[dict]) -> dict[str, dict[str, Any]]:
        target_hashes = self.compute_hashes(image_input)
        results: dict[str, dict[str, Any]] = {}
        for bank in known_banks:
            short_name = bank["short_name"]
            screenshot_path = Path("bank_screenshots") / f"{short_name}_main.png"
            if not screenshot_path.exists():
                results[short_name] = {"similarity": 0, "error": "Screenshot not available"}
                continue
            bank_hashes = self.compute_hashes(screenshot_path)
            results[short_name] = {"similarity": self.calculate_similarity(target_hashes, bank_hashes), "hashes": bank_hashes}
        return results
