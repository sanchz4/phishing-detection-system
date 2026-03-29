import re
import time
import pandas as pd
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import json  
import os

class SocialMediaCrawler:
    def __init__(self, headless=True):
        self.setup_driver(headless)
        self.suspicious_keywords = self.load_suspicious_keywords()
        self.results = []
        
    def setup_driver(self, headless=True):
        """Setup Chrome WebDriver for social media crawling"""
        chrome_options = webdriver.ChromeOptions()
        if headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        
        self.driver = webdriver.Chrome(options=chrome_options)
        self.wait = WebDriverWait(self.driver, 10)
    
    def load_suspicious_keywords(self):
        """Load suspicious keywords for monitoring"""
        return {
            'banking_keywords': [
                'sbi login', 'hdfc netbanking', 'icici bank', 'axis bank', 'idfc bank',
                'canara bank', 'kotak bank', 'pnb login', 'bank of baroda', 'union bank',
                'netbanking', 'online banking', 'secure login', 'bank verification',
                'account verification', 'atm card', 'debit card', 'credit card'
            ],
            'urgent_keywords': [
                'urgent', 'immediately', 'verify now', 'security alert', 'account suspended',
                'last warning', 'immediate action', 'verify account', 'security update',
                'limited time', 'hurry up', 'act now'
            ],
            'financial_scam_keywords': [
                'free money', 'investment', 'lottery', 'cash reward', 'prize money',
                'double your money', 'quick money', 'earn money', 'work from home',
                'part time job', 'investment opportunity', 'bitcoin', 'crypto'
            ],
            'impersonation_keywords': [
                'official', 'verified', 'customer care', 'support', 'help desk',
                'service center', 'contact us', 'helpline', 'toll free'
            ]
        }
    
    def crawl_twitter(self, search_terms=None, max_posts=50):
        """Crawl Twitter for suspicious content"""
        print("🐦 Crawling Twitter...")
        
        if not search_terms:
            search_terms = self.get_all_keywords()
        
        twitter_results = []
        
        for term in search_terms[:5]:  # Limit to 5 terms to avoid rate limiting
            try:
                print(f"  Searching for: {term}")
                search_url = f"https://twitter.com/search?q={term.replace(' ', '%20')}&f=live"
                self.driver.get(search_url)
                time.sleep(5)
                
                # Check if we got blocked or hit a login wall
                if "login" in self.driver.current_url.lower():
                    print("  ⚠️  Twitter requires login. Skipping Twitter crawl.")
                    return twitter_results
                
                # Scroll to load more content
                for _ in range(3):
                    self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    time.sleep(2)
                
                # Extract tweets
                tweets = self.driver.find_elements(By.CSS_SELECTOR, '[data-testid="tweet"]')
                
                print(f"  Found {len(tweets)} tweets, analyzing...")
                
                for tweet in tweets[:max_posts]:
                    try:
                        tweet_data = self.extract_tweet_data(tweet, term)
                        if tweet_data:
                            twitter_results.append(tweet_data)
                    except Exception as e:
                        continue
                        
            except Exception as e:
                print(f"  ❌ Error searching for '{term}': {e}")
        
        print(f"  ✅ Twitter crawl completed: {len(twitter_results)} suspicious posts found")
        return twitter_results
    
    def extract_tweet_data(self, tweet_element, search_term):
        """Extract data from a single tweet"""
        try:
            # Extract username
            username_element = tweet_element.find_element(By.CSS_SELECTOR, '[data-testid="User-Name"]')
            username = username_element.text.split('\n')[0] if username_element else "Unknown"
            
            # Extract tweet text
            tweet_text_element = tweet_element.find_element(By.CSS_SELECTOR, '[data-testid="tweetText"]')
            tweet_text = tweet_text_element.text if tweet_text_element else ""
            
            # Extract timestamp
            time_element = tweet_element.find_element(By.TAG_NAME, 'time')
            timestamp = time_element.get_attribute('datetime') if time_element else ""
            
            # Extract links
            links = []
            link_elements = tweet_element.find_elements(By.CSS_SELECTOR, 'a[href*="http"]')
            for link in link_elements:
                href = link.get_attribute('href')
                if href and 'twitter.com' not in href:
                    links.append(href)
            
            # Calculate suspicion score
            suspicion_score = self.calculate_suspicion_score(tweet_text, username, links)
            
            if suspicion_score > 0:  # Only save suspicious posts
                return {
                    'platform': 'Twitter',
                    'search_term': search_term,
                    'username': username,
                    'content': tweet_text,
                    'timestamp': timestamp,
                    'links': links,
                    'suspicion_score': suspicion_score,
                    'post_url': self.get_tweet_url(tweet_element),
                    'collected_at': datetime.now().isoformat()
                }
                
        except Exception as e:
            return None
        
        return None
    
    def crawl_facebook(self, search_terms=None, max_posts=30):
        """Crawl Facebook for suspicious content (limited due to restrictions)"""
        print("📘 Crawling Facebook...")
        
        # Note: Facebook has strong anti-scraping measures
        # This is a basic implementation that might need adjustments
        
        facebook_results = []
        
        for term in search_terms[:3]:
            try:
                print(f"  Searching for: {term}")
                search_url = f"https://www.facebook.com/search/posts?q={term.replace(' ', '%20')}"
                self.driver.get(search_url)
                time.sleep(5)
                
                # Facebook requires login for detailed search, so we get limited data
                posts = self.driver.find_elements(By.CSS_SELECTOR, '[role="article"]')
                
                for post in posts[:max_posts]:
                    try:
                        post_data = self.extract_facebook_data(post, term)
                        if post_data:
                            facebook_results.append(post_data)
                    except:
                        continue
                        
            except Exception as e:
                print(f"  ❌ Facebook search error for '{term}': {e}")
        
        return facebook_results
    
    def extract_facebook_data(self, post_element, search_term):
        """Extract data from Facebook post"""
        try:
            # Basic extraction (Facebook makes this difficult without login)
            post_text = post_element.text[:500]  # Limit text length
            
            # Look for suspicious patterns
            suspicion_score = self.calculate_suspicion_score(post_text, "", [])
            
            if suspicion_score > 0.3:
                return {
                    'platform': 'Facebook',
                    'search_term': search_term,
                    'username': 'Unknown (Login Required)',
                    'content': post_text,
                    'timestamp': datetime.now().isoformat(),
                    'links': [],
                    'suspicion_score': suspicion_score,
                    'post_url': self.driver.current_url,
                    'collected_at': datetime.now().isoformat(),
                    'note': 'Limited data due to Facebook restrictions'
                }
                
        except Exception as e:
            return None
        
        return None
    
    def crawl_instagram(self, search_terms=None, max_posts=30):
        """Crawl Instagram for suspicious content"""
        print("📷 Crawling Instagram...")
        
        instagram_results = []
        
        for term in search_terms[:3]:
            try:
                print(f"  Searching for: {term}")
                search_url = f"https://www.instagram.com/explore/tags/{term.replace(' ', '')}/"
                self.driver.get(search_url)
                time.sleep(5)
                
                # Extract posts from hashtag search
                post_elements = self.driver.find_elements(By.CSS_SELECTOR, 'article a')
                
                for post_element in post_elements[:max_posts]:
                    try:
                        post_url = post_element.get_attribute('href')
                        if post_url and '/p/' in post_url:
                            post_data = self.extract_instagram_data(post_url, term)
                            if post_data:
                                instagram_results.append(post_data)
                    except:
                        continue
                        
            except Exception as e:
                print(f"  ❌ Instagram search error for '{term}': {e}")
        
        return instagram_results
    
    def extract_instagram_data(self, post_url, search_term):
        """Extract data from Instagram post"""
        try:
            self.driver.get(post_url)
            time.sleep(3)
            
            # Extract caption
            caption_elements = self.driver.find_elements(By.CSS_SELECTOR, 'h1._aacl._aaco._aacu._aacx._aad7._aade')
            caption = caption_elements[0].text if caption_elements else ""
            
            # Extract username
            username_elements = self.driver.find_elements(By.CSS_SELECTOR, 'a._aacl._aaco._aacw._aacx._aad7._aade')
            username = username_elements[0].text if username_elements else ""
            
            # Extract bio links (if any)
            bio_links = []
            try:
                bio_link_elements = self.driver.find_elements(By.CSS_SELECTOR, 'a[href*="http"]')
                for link in bio_link_elements:
                    href = link.get_attribute('href')
                    if href and 'instagram.com' not in href:
                        bio_links.append(href)
            except:
                pass
            
            suspicion_score = self.calculate_suspicion_score(caption, username, bio_links)
            
            if suspicion_score > 0:
                return {
                    'platform': 'Instagram',
                    'search_term': search_term,
                    'username': username,
                    'content': caption,
                    'timestamp': datetime.now().isoformat(),
                    'links': bio_links,
                    'suspicion_score': suspicion_score,
                    'post_url': post_url,
                    'collected_at': datetime.now().isoformat()
                }
                
        except Exception as e:
            return None
        
        return None
    
    def calculate_suspicion_score(self, content, username, links):
        """Calculate suspicion score based on various factors"""
        score = 0
        
        content_lower = content.lower()
        username_lower = username.lower()
        
        # Check for banking keywords
        for keyword in self.suspicious_keywords['banking_keywords']:
            if keyword in content_lower:
                score += 0.3
        
        # Check for urgent language
        for keyword in self.suspicious_keywords['urgent_keywords']:
            if keyword in content_lower:
                score += 0.2
        
        # Check for financial scams
        for keyword in self.suspicious_keywords['financial_scam_keywords']:
            if keyword in content_lower:
                score += 0.2
        
        # Check for impersonation
        for keyword in self.suspicious_keywords['impersonation_keywords']:
            if keyword in content_lower or keyword in username_lower:
                score += 0.3
        
        # Check for suspicious links
        suspicious_domains = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', 'bit.ly', 'tinyurl']
        for link in links:
            if any(domain in link for domain in suspicious_domains):
                score += 0.4
        
        # Check for URL shorteners
        url_shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly']
        for link in links:
            if any(shortener in link for shortener in url_shorteners):
                score += 0.2
        
        return min(score, 1.0)  # Cap at 1.0
    
    def get_all_keywords(self):
        """Get all suspicious keywords as a flat list"""
        all_keywords = []
        for category, keywords in self.suspicious_keywords.items():
            all_keywords.extend(keywords)
        return list(set(all_keywords))  # Remove duplicates
    
    def get_tweet_url(self, tweet_element):
        """Extract tweet URL"""
        try:
            link_elements = tweet_element.find_elements(By.CSS_SELECTOR, 'a[href*="/status/"]')
            for link in link_elements:
                href = link.get_attribute('href')
                if '/status/' in href:
                    return href
        except:
            pass
        return ""
    
    def comprehensive_crawl(self):
        """Perform comprehensive crawl of all platforms"""
        print("🚀 Starting comprehensive social media monitoring...")
        
        all_keywords = self.get_all_keywords()
        
        # Crawl all platforms
        twitter_results = self.crawl_twitter(all_keywords)
        facebook_results = self.crawl_facebook(all_keywords)
        instagram_results = self.crawl_instagram(all_keywords)
        
        # Combine all results
        all_results = twitter_results + facebook_results + instagram_results
        
        # Sort by suspicion score (highest first)
        all_results.sort(key=lambda x: x['suspicion_score'], reverse=True)
        
        self.results = all_results
        return all_results
    
    def save_to_excel(self, filename=None):
        """Save results to Excel file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"social_media_monitoring_{timestamp}.xlsx"
        
        # Create DataFrame
        df = pd.DataFrame(self.results)
        
        if not df.empty:
            # Create Excel writer
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                # Main results sheet
                df.to_excel(writer, sheet_name='Suspicious Posts', index=False)
                
                # Summary sheet
                summary_data = {
                    'Platform': df['platform'].value_counts().index,
                    'Count': df['platform'].value_counts().values
                }
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
                
                # High risk posts sheet (score > 0.7)
                high_risk_df = df[df['suspicion_score'] > 0.7]
                high_risk_df.to_excel(writer, sheet_name='High Risk Posts', index=False)
            
            print(f"✅ Results saved to: {filename}")
            return filename
        else:
            print("❌ No results to save")
            return None
    
    def load_previous_results(self, filename):
        """Load previous monitoring results for comparison"""
        try:
            previous_df = pd.read_excel(filename)
            return previous_df
        except Exception as e:
            print(f"❌ Error loading previous results: {e}")
            return None
    
    def close(self):
        """Close the browser driver"""
        if self.driver:
            self.driver.quit()