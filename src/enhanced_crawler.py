import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import tldextract
import os
import json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By  # This import is missing
from PIL import Image
import io
import time

class EnhancedCrawler:
    def __init__(self, driver, config):
        self.driver = driver
        self.config = config
        self.visited_urls = set()
        self.subdomains = set()
        self.html_contents = {}
        self.screenshots = {}
        
    def get_all_subdomains(self, base_url):
        """Discover subdomains using common patterns"""
        parsed = urlparse(base_url)
        domain_parts = parsed.netloc.split('.')
        main_domain = '.'.join(domain_parts[-2:])
        
        common_subdomains = [
            'www', 'login', 'secure', 'online', 'netbanking',
            'internetbanking', 'mobile', 'app', 'auth', 'account'
        ]
        
        discovered = set()
        for sub in common_subdomains:
            discovered.add(f"https://{sub}.{main_domain}")
            discovered.add(f"http://{sub}.{main_domain}")
        
        return list(discovered)
    
    def crawl_url(self, url, max_depth=2, current_depth=0):
        """Recursively crawl a URL and its links"""
        if current_depth > max_depth or url in self.visited_urls:
            return
            
        try:
            print(f"Crawling: {url} (depth {current_depth})")
            self.driver.get(url)
            time.sleep(2)
            
            # Capture HTML content
            html_content = self.driver.page_source
            self.html_contents[url] = html_content
            
            # Capture screenshot
            screenshot = self.driver.get_screenshot_as_png()
            self.screenshots[url] = screenshot
            
            self.visited_urls.add(url)
            
            # Extract all links from the page
            if current_depth < max_depth:
                links = self.driver.find_elements(By.TAG_NAME, "a")
                for link in links:
                    try:
                        href = link.get_attribute("href")
                        if href and self.is_same_domain(href, url):
                            self.crawl_url(href, max_depth, current_depth + 1)
                    except:
                        continue
                        
        except Exception as e:
            print(f"Error crawling {url}: {e}")
    
    def is_same_domain(self, url, base_url):
        """Check if URL belongs to the same domain"""
        try:
            parsed_url = urlparse(url)
            parsed_base = urlparse(base_url)
            return parsed_url.netloc == parsed_base.netloc or parsed_url.netloc.endswith(parsed_base.netloc)
        except:
            return False
    
    def save_crawled_data(self, output_dir="data/crawled_data"):
        """Save all crawled data to files"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Save HTML contents
        for url, content in self.html_contents.items():
            safe_filename = url.replace('https://', '').replace('http://', '').replace('/', '_')
            with open(f"{output_dir}/{safe_filename}.html", 'w', encoding='utf-8') as f:
                f.write(content)
        
        # Save screenshots
        for url, screenshot in self.screenshots.items():
            safe_filename = url.replace('https://', '').replace('http://', '').replace('/', '_')
            img = Image.open(io.BytesIO(screenshot))
            img.save(f"{output_dir}/{safe_filename}.png")
        
        # Save metadata
        metadata = {
            "crawled_urls": list(self.visited_urls),
            "subdomains": list(self.subdomains),
            "timestamp": time.time()
        }
        
        with open(f"{output_dir}/metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def comprehensive_crawl(self, target_url):
        """Perform comprehensive crawling of a target"""
        print(f"Starting comprehensive crawl of {target_url}")
        
        # Discover subdomains
        subdomains = self.get_all_subdomains(target_url)
        print(f"Discovered {len(subdomains)} potential subdomains")
        
        # Crawl main domain and subdomains
        all_urls = [target_url] + subdomains
        
        for url in all_urls:
            try:
                self.crawl_url(url, max_depth=1)
            except Exception as e:
                print(f"Failed to crawl {url}: {e}")
        
        # Save results
        self.save_crawled_data()
        
        return {
            "total_pages": len(self.visited_urls),
            "subdomains_found": len(subdomains),
            "html_content_pages": len(self.html_contents),
            "screenshots_captured": len(self.screenshots)
        }