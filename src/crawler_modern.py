from __future__ import annotations

import io
import logging
from typing import Any

from PIL import Image
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

LOGGER = logging.getLogger(__name__)


class Crawler:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.driver = self._create_driver()

    def _create_driver(self) -> webdriver.Chrome:
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1600,1200")
        user_agent = self.config.get("user_agent")
        if user_agent:
            chrome_options.add_argument(f"user-agent={user_agent}")
        return webdriver.Chrome(options=chrome_options)

    def capture_screenshot(self, url: str) -> Image.Image | None:
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, self.config.get("timeout", 20)).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            return Image.open(io.BytesIO(self.driver.get_screenshot_as_png())).convert("RGB")
        except Exception as exc:
            LOGGER.warning("Failed to capture screenshot for %s: %s", url, exc)
            return None

    def fetch_html(self, url: str) -> str:
        self.driver.get(url)
        WebDriverWait(self.driver, self.config.get("timeout", 20)).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        return self.driver.page_source

    def close(self) -> None:
        self.driver.quit()
