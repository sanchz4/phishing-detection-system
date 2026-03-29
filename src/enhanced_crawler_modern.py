from __future__ import annotations

import io
import json
import time
from pathlib import Path
from urllib.parse import urlparse

from PIL import Image
from selenium.webdriver.common.by import By


class EnhancedCrawler:
    def __init__(self, driver, config: dict) -> None:
        self.driver = driver
        self.config = config
        self.visited_urls: set[str] = set()
        self.subdomains: set[str] = set()
        self.html_contents: dict[str, str] = {}
        self.screenshots: dict[str, bytes] = {}

    def get_all_subdomains(self, base_url: str) -> list[str]:
        parsed = urlparse(base_url)
        domain_parts = parsed.netloc.split(".")
        main_domain = ".".join(domain_parts[-2:])
        discovered = {f"https://{sub}.{main_domain}" for sub in ["www", "login", "secure", "online", "netbanking", "mobile", "app", "auth"]}
        self.subdomains.update(discovered)
        return sorted(discovered)

    def crawl_url(self, url: str, max_depth: int = 1, current_depth: int = 0) -> None:
        if current_depth > max_depth or url in self.visited_urls:
            return
        self.driver.get(url)
        time.sleep(1)
        self.html_contents[url] = self.driver.page_source
        self.screenshots[url] = self.driver.get_screenshot_as_png()
        self.visited_urls.add(url)
        if current_depth >= max_depth:
            return
        for link in self.driver.find_elements(By.TAG_NAME, "a"):
            href = link.get_attribute("href")
            if href and self.is_same_domain(href, url):
                self.crawl_url(href, max_depth=max_depth, current_depth=current_depth + 1)

    def is_same_domain(self, url: str, base_url: str) -> bool:
        parsed_url = urlparse(url)
        parsed_base = urlparse(base_url)
        return parsed_url.netloc == parsed_base.netloc or parsed_url.netloc.endswith(parsed_base.netloc)

    def save_crawled_data(self, output_dir: str = "data/crawled_data") -> None:
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)
        for url, content in self.html_contents.items():
            safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_")
            (path / f"{safe_name}.html").write_text(content, encoding="utf-8")
        for url, screenshot in self.screenshots.items():
            safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_")
            Image.open(io.BytesIO(screenshot)).save(path / f"{safe_name}.png")
        (path / "metadata.json").write_text(
            json.dumps({"crawled_urls": sorted(self.visited_urls), "subdomains": sorted(self.subdomains), "timestamp": time.time()}, indent=2),
            encoding="utf-8",
        )

    def comprehensive_crawl(self, target_url: str) -> dict[str, int]:
        for url in [target_url, *self.get_all_subdomains(target_url)]:
            try:
                self.crawl_url(url, max_depth=int(self.config.get("max_depth", 1)))
            except Exception:
                continue
        self.save_crawled_data()
        return {
            "total_pages": len(self.visited_urls),
            "subdomains_found": len(self.subdomains),
            "html_content_pages": len(self.html_contents),
            "screenshots_captured": len(self.screenshots),
        }
