import json
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from src.image_analyzer import ImageAnalyzer
from src.domain_analyzer import DomainAnalyzer
from src.enhanced_crawler import EnhancedCrawler
from src.html_comparator import HTMLComparator
from src.image_hasher import ImageHasher
from src.crawler import Crawler
import numpy as np

# Import ICANN API client
try:
    from src.icann_api_client import ICANNApiClient
    ICANN_AVAILABLE = True
except ImportError:
    ICANN_AVAILABLE = False

class PhishingDetector:
    def __init__(self, config_path="config.json"):
        self.load_config(config_path)
        self.setup_driver()
        self.image_analyzer = ImageAnalyzer()
        
        # Initialize domain analyzer with ICANN support
        icann_config = self.config.get("icann", {})
        icann_api_key = icann_config.get("api_key")
        icann_enabled = icann_config.get("enabled", False)
        
        if icann_enabled and icann_api_key and ICANN_AVAILABLE:
            print("🔍 ICANN domain intelligence enabled")
            self.domain_analyzer = DomainAnalyzer(self.config["known_banks"], icann_api_key)
            self.icann_client = ICANNApiClient(icann_api_key)
        else:
            if not ICANN_AVAILABLE:
                print("⚠️  ICANN client not available - make sure icann_api_client.py exists")
            elif not icann_api_key:
                print("⚠️  ICANN domain intelligence disabled (no API key in config)")
            else:
                print("⚠️  ICANN domain intelligence disabled")
            self.domain_analyzer = DomainAnalyzer(self.config["known_banks"])
            self.icann_client = None
        
        self.crawler = Crawler(self.driver, self.config["crawling"])
        self.enhanced_crawler = EnhancedCrawler(self.driver, self.config["crawling"])
        self.html_comparator = HTMLComparator()
        self.image_hasher = ImageHasher()  # NEW: Perceptual hashing
        
    def load_config(self, config_path):
        """Load configuration from JSON file"""
        with open(config_path, 'r') as f:
            self.config = json.load(f)
    
    def setup_driver(self):
        """Setup Chrome WebDriver"""
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument(f"user-agent={self.config['crawling']['user_agent']}")
        
        self.driver = webdriver.Chrome(options=chrome_options)
    
    def analyze_url(self, url, comprehensive=True):
        """Unified analysis method - performs both basic and comprehensive analysis"""
        print(f"🔍 Analyzing {url}...")
        
        # Capture screenshot
        screenshot = self.crawler.capture_screenshot(url)
        if not screenshot:
            return {"error": "Failed to capture screenshot"}
        
        # NEW: Perform perceptual hash analysis (fast)
        hash_results = self._perform_hash_analysis(screenshot)
        
        # Continue with existing analysis
        if comprehensive:
            comprehensive_results = self._comprehensive_analysis(url)
            # Combine with hash results
            return {**comprehensive_results, **hash_results}
        else:
            basic_results = self._basic_analysis(url, screenshot)
            # Combine with hash results
            return {**basic_results, **hash_results}
    
    def _perform_hash_analysis(self, screenshot):
        """Perform perceptual hash analysis as additional feature"""
        try:
            print("🔎 Performing perceptual hash analysis...")
            
            # Convert screenshot to the right format if needed
            if hasattr(screenshot, 'convert'):
                # It's already a PIL Image, ensure RGB mode
                screenshot = screenshot.convert('RGB')
            elif isinstance(screenshot, np.ndarray):
                # Convert numpy array to PIL Image
                from PIL import Image
                screenshot = Image.fromarray(screenshot)
            
            hash_results = self.image_hasher.compare_with_banks(screenshot, self.config["known_banks"])
            
            # Find best match
            best_match = None
            max_similarity = 0
            for bank_name, result in hash_results.items():
                if isinstance(result, dict) and 'similarity' in result:
                    if result['similarity'] > max_similarity:
                        max_similarity = result['similarity']
                        best_match = bank_name
            
            return {
                'hash_analysis': hash_results,
                'best_hash_match': best_match,
                'max_hash_similarity': max_similarity,
                'hash_detection': max_similarity > 80  # Threshold for hash-based detection
            }
            
        except Exception as e:
            print(f"❌ Hash analysis error: {e}")
            import traceback
            traceback.print_exc()
            return {
                'hash_analysis': {},
                'hash_error': str(e)
            }
    
    def _basic_analysis(self, url, screenshot=None):
        """Basic analysis - screenshot + domain analysis only"""
        if screenshot is None:
            screenshot = self.crawler.capture_screenshot(url)
            if not screenshot:
                return {"error": "Failed to capture screenshot"}
        
        # Analyze domain similarity (now includes ICANN data if available)
        domain_results = self.domain_analyzer.analyze_domain(url)
        
        # Analyze image similarity
        image_results = self.image_analyzer.analyze_screenshot(screenshot, self.config["known_banks"])
        
        # Combine results
        return self.combine_results(domain_results, image_results, url)
    
    def _comprehensive_analysis(self, url):
        """Comprehensive analysis with crawling and HTML comparison"""
        print("🌐 Starting comprehensive analysis...")
        
        try:
            # 1. Perform comprehensive crawling
            print("📡 Crawling website and subdomains...")
            crawl_result = self.enhanced_crawler.comprehensive_crawl(url)
            
            # 2. Perform basic analysis on the main URL
            print("📊 Performing basic analysis...")
            basic_result = self._basic_analysis(url)
            
            # 3. Extract HTML features from the main page
            main_page_html = None
            if url in self.enhanced_crawler.html_contents:
                main_page_html = self.enhanced_crawler.html_contents[url]
            
            # 4. Compare with known banks if HTML content is available
            html_comparison_results = {}
            if main_page_html:
                print("📝 Analyzing HTML structure...")
                target_features = self.html_comparator.extract_html_features(main_page_html)
                
                for bank in self.config["known_banks"]:
                    try:
                        # Quick fetch of bank's main page for comparison
                        self.driver.get(bank["url"])
                        bank_html = self.driver.page_source
                        bank_features = self.html_comparator.extract_html_features(bank_html)
                        
                        comparison = self.html_comparator.compare_html_structures(target_features, bank_features)
                        html_comparison_results[bank["short_name"]] = comparison
                    except Exception as e:
                        print(f"❌ Error analyzing {bank['short_name']}: {e}")
                        html_comparison_results[bank["short_name"]] = {"error": str(e)}
            
            # 5. Detect phishing patterns in HTML
            phishing_patterns = []
            if main_page_html:
                target_features = self.html_comparator.extract_html_features(main_page_html)
                phishing_patterns = self.html_comparator.detect_phishing_patterns(target_features)
            
            # 6. Combine all results
            combined_result = {
                **basic_result,
                "crawl_stats": crawl_result,
                "html_analysis": html_comparison_results,
                "phishing_patterns": phishing_patterns,
                "subdomains_discovered": list(self.enhanced_crawler.subdomains),
                "pages_crawled": list(self.enhanced_crawler.visited_urls),
                "analysis_type": "comprehensive"
            }
            
            # 7. Adjust confidence based on HTML analysis
            if html_comparison_results:
                best_html_sim = 0
                for bank_result in html_comparison_results.values():
                    if isinstance(bank_result, dict) and 'content_similarity' in bank_result:
                        best_html_sim = max(best_html_sim, bank_result.get('content_similarity', 0))
                
                # Adjust overall confidence with HTML similarity
                html_weight = self.config["detection"].get("html_similarity_weight", 0.3)
                combined_result["confidence"] = (
                    (1 - html_weight) * combined_result["confidence"] + 
                    html_weight * best_html_sim
                )
                
                # Re-evaluate phishing status
                combined_result["is_phishing"] = (
                    combined_result["confidence"] > self.config["detection"]["phishing_threshold"]
                )
            
            return combined_result
            
        except Exception as e:
            print(f"❌ Error in comprehensive analysis: {e}")
            # Fall back to basic analysis
            return self._basic_analysis(url)
    
    def combine_results(self, domain_results, image_results, url):
        """Combine domain and image analysis results"""
        results = {
            "url": url,
            "timestamp": self.image_analyzer.get_timestamp(),
            "domain_analysis": domain_results,
            "image_analysis": image_results,
            "is_phishing": False,
            "confidence": 0,
            "target_bank": None
        }
        
        # Calculate overall similarity
        max_similarity = 0
        target_bank = None
        
        for bank in self.config["known_banks"]:
            bank_short_name = bank["short_name"]
            
            domain_sim = domain_results["similarities"].get(bank_short_name, 0)
            image_sim = image_results["similarities"].get(bank_short_name, {}).get("feature_similarity", 0)
            structural_sim = image_results["similarities"].get(bank_short_name, {}).get("structural_similarity", 0)
            
            overall_sim = (
                self.config["detection"]["domain_similarity_weight"] * domain_sim +
                self.config["detection"]["image_similarity_weight"] * image_sim +
                self.config["detection"]["structural_similarity_weight"] * structural_sim
            )
            
            if overall_sim > max_similarity:
                max_similarity = overall_sim
                target_bank = bank_short_name
        
        # Use combined confidence if ICANN data is available
        if "combined_confidence" in domain_results:
            results["confidence"] = domain_results["combined_confidence"]
        else:
            results["confidence"] = max_similarity
            
        results["is_phishing"] = results["confidence"] > self.config["detection"]["phishing_threshold"]
        
        if target_bank:
            results["target_bank"] = target_bank
            results["target_bank_name"] = next(
                (b["name"] for b in self.config["known_banks"] if b["short_name"] == target_bank), 
                "Unknown"
            )
        
        return results
    
    def crawl_and_analyze(self, seed_urls):
        """Crawl from seed URLs and analyze each page"""
        return self.crawler.crawl_and_analyze(seed_urls, lambda url: self.analyze_url(url, comprehensive=True))
    
    def icann_analyze_domains(self, domains):
        """Standalone ICANN domain analysis"""
        if not self.icann_client:
            print("❌ ICANN client not available")
            return None
        
        print(f"🔍 Performing ICANN analysis on {len(domains)} domains...")
        return self.icann_client.batch_analyze_domains(domains)
    
    def save_icann_analysis(self, results, filename=None):
        """Save ICANN analysis results to Excel"""
        if not self.icann_client:
            print("❌ ICANN client not available")
            return None
        
        return self.icann_client.save_analysis_to_excel(results, filename)
    
    def close(self):
        """Clean up resources"""
        self.driver.quit()