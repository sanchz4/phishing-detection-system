from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from PIL import Image
import io
import time

class Crawler:
    def __init__(self, driver, config):
        self.driver = driver
        self.config = config
    
    def capture_screenshot(self, url):
        """Capture screenshot of a webpage"""
        try:
            print(f"Capturing screenshot for {url}...")
            self.driver.get(url)
            
            # Wait for page to load
            WebDriverWait(self.driver, self.config["timeout"]).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            time.sleep(2)  # Additional wait for dynamic content
            
            # Take screenshot
            screenshot = self.driver.get_screenshot_as_png()
            img = Image.open(io.BytesIO(screenshot))
            return img
            
        except Exception as e:
            print(f"Error capturing screenshot for {url}: {e}")
            return None
    
    def is_relevant_link(self, url):
        """Determine if a link is relevant for phishing detection"""
        from urllib.parse import urlparse
        
        # Skip common irrelevant domains
        irrelevant_domains = [
            'facebook.com', 'twitter.com', 'linkedin.com', 
            'google.com', 'youtube.com', 'instagram.com',
            'wikipedia.org', 'amazon.com', 'flipkart.com'
        ]
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        for irr_domain in irrelevant_domains:
            if irr_domain in domain:
                return False
        
        # Focus on domains that might be phishing attempts
        suspicious_keywords = [
            'login', 'signin', 'bank', 'secure', 'verify', 
            'account', 'online', 'netbanking', 'sbi', 'idfc',
            'hdfc', 'icici', 'axis'
        ]
        
        url_lower = url.lower()
        for keyword in suspicious_keywords:
            if keyword in url_lower:
                return True
        
        return False
    
    def crawl_and_analyze(self, seed_urls, analyze_func):
        """Crawl from seed URLs and analyze each page"""
        results = []
        visited = set()
        
        for url in seed_urls:
            if len(visited) >= self.config["max_pages"]:
                break
                
            if url not in visited:
                try:
                    print(f"Crawling: {url}")
                    result = analyze_func(url)
                    results.append(result)
                    visited.add(url)
                    
                    # Extract links from page for further crawling
                    self.driver.get(url)
                    links = self.driver.find_elements(By.TAG_NAME, "a")
                    
                    for link in links:
                        if len(visited) >= self.config["max_pages"]:
                            break
                            
                        href = link.get_attribute("href")
                        if href and href not in visited and self.is_relevant_link(href):
                            try:
                                print(f"Crawling: {href}")
                                result = analyze_func(href)
                                results.append(result)
                                visited.add(href)
                                
                            except Exception as e:
                                print(f"Error processing {href}: {e}")
                                
                except Exception as e:
                    print(f"Error processing {url}: {e}")
        
        return results

# For testing
if __name__ == "__main__":
    print("Crawler class is defined correctly!")