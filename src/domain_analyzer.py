from urllib.parse import urlparse
import Levenshtein
import re
import tldextract
from datetime import datetime

# Import ICANN API client
try:
    from src.icann_api_client import ICANNApiClient
    ICANN_AVAILABLE = True
except ImportError:
    ICANN_AVAILABLE = False

class DomainAnalyzer:
    def __init__(self, known_banks, icann_api_key=None):
        self.known_banks = known_banks
        self.known_domains = self.extract_known_domains()
        self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'site', 'online']
        
        # Initialize ICANN client if API key provided
        if icann_api_key and ICANN_AVAILABLE:
            try:
                self.icann_client = ICANNApiClient(icann_api_key)
                print("✅ ICANN domain intelligence enabled")
            except Exception as e:
                self.icann_client = None
                print(f"⚠️  Failed to initialize ICANN client: {e}")
        else:
            self.icann_client = None
            if icann_api_key and not ICANN_AVAILABLE:
                print("⚠️  ICANN client not available - make sure icann_api_client.py exists")
    
    def extract_known_domains(self):
        """Extract domains from known bank URLs with full parsing"""
        domains = {}
        
        for bank in self.known_banks:
            parsed_url = urlparse(bank["url"])
            domain = parsed_url.netloc.lower()
            
            # Extract domain components
            extracted = tldextract.extract(domain)
            domains[bank["short_name"]] = {
                'full_domain': domain,
                'subdomain': extracted.subdomain,
                'domain_name': extracted.domain,
                'tld': extracted.suffix
            }
        
        return domains
    
    def extract_domain_components(self, url):
        """Extract components from any URL"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        extracted = tldextract.extract(domain)
        
        return {
            'full_domain': domain,
            'subdomain': extracted.subdomain,
            'domain_name': extracted.domain,
            'tld': extracted.suffix,
            'path': parsed_url.path
        }
    
    def levenshtein_similarity(self, s1, s2):
        """Calculate Levenshtein similarity between two strings"""
        distance = Levenshtein.distance(s1, s2)
        max_len = max(len(s1), len(s2))
        similarity = 1 - (distance / max_len) if max_len > 0 else 0
        return similarity
    
    def calculate_domain_similarity(self, test_domain, bank_domain_info):
        """Calculate multiple similarity metrics for domains"""
        test_extracted = tldextract.extract(test_domain)
        bank_domain = bank_domain_info['full_domain']
        bank_extracted = tldextract.extract(bank_domain)
        
        similarities = {}
        
        # 1. Full domain similarity
        similarities['full_domain'] = self.levenshtein_similarity(
            test_domain, bank_domain
        )
        
        # 2. Domain name similarity (most important)
        similarities['domain_name'] = self.levenshtein_similarity(
            test_extracted.domain, bank_extracted.domain
        )
        
        # 3. Subdomain similarity
        similarities['subdomain'] = self.levenshtein_similarity(
            test_extracted.subdomain, bank_extracted.subdomain
        ) if test_extracted.subdomain and bank_extracted.subdomain else 0
        
        # 4. Common character sequence detection
        test_clean = test_extracted.domain
        bank_clean = bank_extracted.domain
        
        # Find longest common substring
        def longest_common_substring(s1, s2):
            m = [[0] * (1 + len(s2)) for _ in range(1 + len(s1))]
            longest, x_longest = 0, 0
            for x in range(1, 1 + len(s1)):
                for y in range(1, 1 + len(s2)):
                    if s1[x - 1] == s2[y - 1]:
                        m[x][y] = m[x - 1][y - 1] + 1
                        if m[x][y] > longest:
                            longest = m[x][y]
                            x_longest = x
                    else:
                        m[x][y] = 0
            return s1[x_longest - longest: x_longest] if longest > 0 else ""
        
        lcs = longest_common_substring(test_clean, bank_clean)
        similarities['common_substring'] = len(lcs) / max(len(test_clean), len(bank_clean)) if lcs else 0
        
        # Weighted overall similarity
        weights = {
            'domain_name': 0.6,
            'full_domain': 0.2,
            'common_substring': 0.15,
            'subdomain': 0.05
        }
        
        overall_similarity = sum(
            similarities[key] * weights[key] for key in weights
        )
        
        return overall_similarity, similarities
    
    def check_suspicious_patterns(self, domain_components):
        """Check for suspicious domain patterns"""
        warnings = []
        
        # Suspicious TLDs
        if domain_components['tld'] in self.suspicious_tlds:
            warnings.append(f"Suspicious TLD: {domain_components['tld']}")
        
        # Hyphen attacks (e.g., sbi-login.com)
        if '-' in domain_components['domain_name']:
            warnings.append("Contains hyphens (potential hyphen attack)")
        
        # Character substitution (e.g., sb1.com)
        substitutions = {
            'i': ['1', 'l', '!'],
            'o': ['0'],
            's': ['5', '$'],
            'a': ['4', '@'],
            'e': ['3']
        }
        
        # Number sequences (e.g., sbi123.com)
        if re.search(r'\d{3,}', domain_components['domain_name']):
            warnings.append("Contains number sequence")
        
        # Length too long
        if len(domain_components['domain_name']) > 20:
            warnings.append("Unusually long domain name")
        
        return warnings
    
    def analyze_domain(self, test_url):
        """Comprehensive domain analysis with multiple techniques"""
        domain_components = self.extract_domain_components(test_url)
        test_domain = domain_components['full_domain']
        
        similarities = {}
        detailed_analysis = {}
        warnings = self.check_suspicious_patterns(domain_components)
        
        # Get ICANN domain intelligence if available
        icann_data = None
        icann_risk_score = 0
        icann_risk_factors = []
        
        if self.icann_client:
            try:
                icann_data = self.icann_client.get_domain_data(test_domain)
                if icann_data and icann_data.get('raw_data_available'):
                    risk_analysis = icann_data.get('risk_analysis', {})
                    icann_risk_score = risk_analysis.get('risk_score', 0)
                    icann_risk_factors = risk_analysis.get('risk_factors', [])
                    
                    # Add ICANN-based warnings
                    if icann_risk_score > 0.5:
                        warnings.extend(icann_risk_factors)
                    
            except Exception as e:
                print(f"⚠️ ICANN data collection failed for {test_domain}: {e}")
        
        for bank_short_name, bank_domain_info in self.known_domains.items():
            similarity_score, similarity_details = self.calculate_domain_similarity(
                test_domain, bank_domain_info
            )
            
            similarities[bank_short_name] = similarity_score
            detailed_analysis[bank_short_name] = similarity_details
        
        # Find the most similar domain
        max_similarity = 0
        most_similar = None
        
        for bank_short_name, similarity in similarities.items():
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar = bank_short_name
        
        # Combine similarity score with ICANN risk score
        combined_confidence = max_similarity
        if icann_risk_score > 0:
            # Weight ICANN risk at 40% of overall score
            combined_confidence = (max_similarity * 0.6) + (icann_risk_score * 0.4)
        
        return {
            "test_domain": test_domain,
            "domain_components": domain_components,
            "similarities": similarities,
            "detailed_similarities": detailed_analysis,
            "most_similar": most_similar,
            "max_similarity": max_similarity,
            "warnings": warnings,
            "suspicious_score": len(warnings) * 0.1,  # 0.1 per warning
            "icann_data": icann_data,
            "icann_risk_score": icann_risk_score,
            "icann_risk_factors": icann_risk_factors,
            "combined_confidence": combined_confidence,
            "timestamp": datetime.now().isoformat(),
            "analysis_method": "advanced_domain_analysis_with_icann"
        }
    
    def batch_analyze(self, urls):
        """Analyze multiple URLs at once"""
        results = []
        for url in urls:
            results.append(self.analyze_domain(url))
        return results

# Test function
if __name__ == "__main__":
    # Test with sample banks
    test_banks = [
        {"short_name": "sbi", "url": "https://www.onlinesbi.sbi", "name": "State Bank of India"},
        {"short_name": "hdfc", "url": "https://www.hdfcbank.com", "name": "HDFC Bank"},
        {"short_name": "icici", "url": "https://www.icicibank.com", "name": "ICICI Bank"}
    ]
    
    # Test without ICANN
    analyzer = DomainAnalyzer(test_banks)
    
    # Test cases
    test_urls = [
        "https://www.onlinesbi.sbi",  # Legitimate
        "https://sbi-online-login.com",  # Suspicious
        "https://hdfc-secure-banking.com",  # Suspicious
        "https://icici-phishing-site.xyz"  # Very suspicious
    ]
    
    print("Testing Domain Analyzer:")
    print("=" * 50)
    
    for url in test_urls:
        result = analyzer.analyze_domain(url)
        print(f"\nURL: {url}")
        print(f"Most similar: {result['most_similar']} ({result['max_similarity']:.3f})")
        if 'combined_confidence' in result:
            print(f"Combined confidence: {result['combined_confidence']:.3f}")
        print(f"Warnings: {len(result['warnings'])}")
        if result['warnings']:
            for warning in result['warnings']:
                print(f"  ⚠️  {warning}")
        print("-" * 30)