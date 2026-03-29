# src/icann_api_client.py
import requests
import json
import time
import os
from datetime import datetime, timedelta
from urllib.parse import urlparse
import tldextract
import pandas as pd
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class ICANNApiClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://rdap.org/domain/"  # RDAP endpoint
        self.rate_limit_delay = 2  # Increased delay for better reliability
        self.cache = {}
        self.cache_duration = timedelta(hours=24)
        
        # Create session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
    def get_domain_data(self, domain):
        """Get comprehensive domain data using ICANN RDAP"""
        try:
            # Extract clean domain
            clean_domain = self.extract_domain(domain)
            if not clean_domain:
                return self._create_error_response(domain, "Failed to extract domain from URL")
            
            # Check cache first
            if clean_domain in self.cache:
                cached_data = self.cache[clean_domain]
                if datetime.now() - cached_data['cached_at'] < self.cache_duration:
                    return cached_data['data']
            
            print(f"🔍 Fetching ICANN RDAP data for: {clean_domain}")
            
            # Use RDAP protocol with retry logic
            rdap_data = self._fetch_rdap_data_with_retry(clean_domain)
            
            if rdap_data:
                # Add risk analysis
                risk_analysis = self._analyze_domain_risk(rdap_data, clean_domain)
                rdap_data['risk_analysis'] = risk_analysis
                
                # Cache the result
                self.cache[clean_domain] = {
                    'data': rdap_data,
                    'cached_at': datetime.now()
                }
                
                return rdap_data
            else:
                return self._create_error_response(clean_domain, "Failed to fetch domain data")
                
        except Exception as e:
            print(f"❌ Error fetching ICANN data for {domain}: {e}")
            return self._create_error_response(domain, str(e))
    
    def _fetch_rdap_data_with_retry(self, domain):
        """Fetch domain registration data using RDAP with retry logic"""
        if not domain:
            return None
            
        url = f"{self.base_url}{domain}"
        headers = {
            'Accept': 'application/rdap+json',
            'User-Agent': 'PhishingDetectionBot/1.0',
            'Connection': 'close'  # Avoid connection reuse issues
        }
        
        for attempt in range(3):  # Retry up to 3 times
            try:
                print(f"  Attempt {attempt + 1}/3 for: {domain}")
                response = self.session.get(url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_rdap_response(data, domain)
                elif response.status_code == 404:
                    print(f"  ⚠️ Domain not found in RDAP: {domain}")
                    return None
                elif response.status_code == 429:  # Rate limited
                    print(f"  ⚠️ Rate limited, waiting 10 seconds...")
                    time.sleep(10)
                    continue
                else:
                    print(f"  ⚠️ RDAP error {response.status_code} for {domain}")
                    return None
                    
            except requests.exceptions.Timeout:
                print(f"  ⚠️ RDAP timeout for {domain} (attempt {attempt + 1})")
                if attempt < 2:  # Don't sleep after last attempt
                    time.sleep(5)
            except requests.exceptions.ConnectionError as e:
                print(f"  ⚠️ Connection error for {domain} (attempt {attempt + 1}): {e}")
                if attempt < 2:
                    time.sleep(5)
            except Exception as e:
                print(f"  ⚠️ RDAP failed for {domain} (attempt {attempt + 1}): {e}")
                if attempt < 2:
                    time.sleep(5)
        
        print(f"  ❌ All attempts failed for: {domain}")
        return None

    def _fetch_rdap_data(self, domain):
        """Legacy method for backward compatibility"""
        return self._fetch_rdap_data_with_retry(domain)
    
    def extract_domain(self, url):
        """Extract domain from URL - FIXED VERSION"""
        try:
            if not url or not isinstance(url, str):
                return None
                
            if url.startswith(('http://', 'https://')):
                parsed = urlparse(url)
                domain = parsed.netloc
            else:
                domain = url
            
            if not domain:
                return None
            
            # Remove www prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain.lower()
            
        except Exception as e:
            print(f"⚠️ Error extracting domain from {url}: {e}")
            return None
    
    def _parse_rdap_response(self, data, domain):
        """Parse RDAP response into structured format"""
        try:
            # Extract key events
            events = {}
            for event in data.get('events', []):
                event_type = event.get('eventAction')
                event_date = event.get('eventDate')
                if event_type and event_date:
                    events[event_type] = event_date
            
            # Extract registrar information
            registrar = None
            registrar_id = None
            for entity in data.get('entities', []):
                if 'registrar' in entity.get('roles', []):
                    registrar = entity.get('name')
                    registrar_id = entity.get('handle')
                    break
            
            # Extract nameservers
            nameservers = []
            for ns in data.get('nameservers', []):
                if 'ldhName' in ns:
                    nameservers.append(ns['ldhName'])
            
            # Extract status
            statuses = data.get('status', [])
            
            # Extract secure DNS
            secure_dns = data.get('secureDNS', {})
            dnssec = secure_dns.get('delegationSigned', False)
            
            return {
                'domain': domain,
                'events': events,
                'registration_date': events.get('registration'),
                'expiration_date': events.get('expiration'),
                'last_changed_date': events.get('last changed'),
                'last_transfer_date': events.get('transfer'),
                'registrar': registrar,
                'registrar_id': registrar_id,
                'nameservers': nameservers,
                'status': statuses,
                'dnssec': dnssec,
                'data_source': 'ICANN RDAP',
                'port43': data.get('port43'),
                'collected_at': datetime.now().isoformat(),
                'raw_data_available': True
            }
            
        except Exception as e:
            print(f"  ❌ Error parsing RDAP data: {e}")
            return None
    
    def _analyze_domain_risk(self, domain_data, domain):
        """Analyze domain risk based on registration data"""
        risk_score = 0
        risk_factors = []
        
        # 1. Check domain age
        reg_date = domain_data.get('registration_date')
        if reg_date:
            try:
                reg_datetime = datetime.fromisoformat(reg_date.replace('Z', '+00:00'))
                domain_age_days = (datetime.now().replace(tzinfo=reg_datetime.tzinfo) - reg_datetime).days
                
                if domain_age_days < 7:
                    risk_score += 0.6
                    risk_factors.append(f"Very new domain ({domain_age_days} days old)")
                elif domain_age_days < 30:
                    risk_score += 0.4
                    risk_factors.append(f"New domain ({domain_age_days} days old)")
                elif domain_age_days < 90:
                    risk_score += 0.2
                    risk_factors.append(f"Recent domain ({domain_age_days} days old)")
                    
            except Exception as e:
                print(f"  ⚠️ Error calculating domain age: {e}")
        
        # 2. Check expiration
        exp_date = domain_data.get('expiration_date')
        if exp_date:
            try:
                exp_datetime = datetime.fromisoformat(exp_date.replace('Z', '+00:00'))
                days_until_expiry = (exp_datetime - datetime.now().replace(tzinfo=exp_datetime.tzinfo)).days
                
                if days_until_expiry < 7:
                    risk_score += 0.5
                    risk_factors.append(f"Domain expiring very soon ({days_until_expiry} days)")
                elif days_until_expiry < 30:
                    risk_score += 0.3
                    risk_factors.append(f"Domain expiring soon ({days_until_expiry} days)")
                    
            except Exception as e:
                print(f"  ⚠️ Error checking expiration: {e}")
        
        # 3. Check registrar reputation
        registrar = domain_data.get('registrar', '')
        if registrar:
            registrar_lower = registrar.lower()
            suspicious_registrars = [
                'epik', 'namecheap', 'porkbun', 'namesilo', 
                'dynadot', 'internet.bs', 'name.com'
            ]
            if any(susp_reg in registrar_lower for susp_reg in suspicious_registrars):
                risk_score += 0.2
                risk_factors.append(f"Suspicious registrar: {registrar}")
        
        # 4. Check nameservers
        nameservers = domain_data.get('nameservers', [])
        suspicious_ns = [
            'cloudflare', 'freedns', 'no-ip', 'dyndns',
            'changeip', 'dynu', 'duckdns', 'afraid.org'
        ]
        for ns in nameservers:
            if ns:
                ns_lower = ns.lower()
                if any(susp_ns in ns_lower for susp_ns in suspicious_ns):
                    risk_score += 0.3
                    risk_factors.append(f"Suspicious nameserver: {ns}")
                    break
        
        # 5. Check domain status
        statuses = domain_data.get('status', [])
        suspicious_statuses = [
            'clientHold', 'serverHold', 'pendingDelete', 
            'redemptionPeriod', 'clientTransferProhibited'
        ]
        for status in statuses:
            if status in suspicious_statuses:
                risk_score += 0.4
                risk_factors.append(f"Suspicious domain status: {status}")
                break
        
        # 6. Check for DNSSEC (absence can be suspicious)
        if not domain_data.get('dnssec', False):
            risk_score += 0.1
            risk_factors.append("DNSSEC not enabled")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'risk_factors': risk_factors,
            'is_high_risk': risk_score > 0.7,
            'is_medium_risk': 0.4 <= risk_score <= 0.7
        }
    
    def _create_error_response(self, domain, error_msg):
        """Create error response"""
        return {
            'domain': domain,
            'error': error_msg,
            'raw_data_available': False,
            'collected_at': datetime.now().isoformat(),
            'risk_analysis': {
                'risk_score': 0.5,
                'risk_factors': [f"Data unavailable: {error_msg}"],
                'is_high_risk': False,
                'is_medium_risk': True
            }
        }
    
    def batch_analyze_domains(self, domains):
        """Analyze multiple domains with improved rate limiting"""
        results = {}
        total = len(domains)
        
        for i, domain in enumerate(domains, 1):
            print(f"Progress: {i}/{total} - {domain}")
            results[domain] = self.get_domain_data(domain)
            
            # Dynamic rate limiting based on success
            if i < total:  # Don't sleep after last domain
                if results[domain].get('raw_data_available', False):
                    time.sleep(self.rate_limit_delay)  # Normal delay for success
                else:
                    time.sleep(self.rate_limit_delay * 2)  # Longer delay for failures
        
        return results
    
    def save_analysis_to_excel(self, results, filename="icann_domain_analysis.xlsx", append=False):
        """Save ICANN analysis results to Excel with append option"""
        try:
            data = []
            for url, result in results.items():
                risk_analysis = result.get('risk_analysis', {})
                data.append({
                    'Domain': url,
                    'Risk Score': risk_analysis.get('risk_score', 0),
                    'High Risk': risk_analysis.get('is_high_risk', False),
                    'Medium Risk': risk_analysis.get('is_medium_risk', False),
                    'Registration Date': result.get('registration_date'),
                    'Expiration Date': result.get('expiration_date'),
                    'Registrar': result.get('registrar'),
                    'Registrar ID': result.get('registrar_id'),
                    'Nameservers': ', '.join(result.get('nameservers', [])),
                    'Domain Status': ', '.join(result.get('status', [])),
                    'DNSSEC Enabled': result.get('dnssec', False),
                    'Risk Factors': '; '.join(risk_analysis.get('risk_factors', [])),
                    'Data Source': result.get('data_source', 'Unknown'),
                    'Analysis Timestamp': result.get('collected_at')
                })
            
            df = pd.DataFrame(data)
            
            if append and os.path.exists(filename):
                # Append to existing file
                try:
                    # Read existing data
                    existing_df = pd.read_excel(filename, sheet_name='Domain Analysis')
                    combined_df = pd.concat([existing_df, df], ignore_index=True)
                    
                    # Create new file with combined data
                    with pd.ExcelWriter(filename, engine='openpyxl', mode='w') as writer:
                        combined_df.to_excel(writer, sheet_name='Domain Analysis', index=False)
                        
                        # Update high risk domains sheet
                        high_risk_df = combined_df[combined_df['High Risk'] == True]
                        if not high_risk_df.empty:
                            high_risk_df.to_excel(writer, sheet_name='High Risk Domains', index=False)
                        
                        # Update summary sheet
                        summary_data = {
                            'Metric': ['Total Domains', 'High Risk', 'Medium Risk', 'Low Risk', 'Average Risk Score'],
                            'Value': [
                                len(combined_df),
                                len(high_risk_df),
                                len(combined_df[combined_df['Medium Risk'] == True]),
                                len(combined_df[(combined_df['High Risk'] == False) & (combined_df['Medium Risk'] == False)]),
                                combined_df['Risk Score'].mean()
                            ]
                        }
                        summary_df = pd.DataFrame(summary_data)
                        summary_df.to_excel(writer, sheet_name='Summary', index=False)
                    
                    print(f"✅ Appended to existing file: {filename}")
                    
                except Exception as e:
                    print(f"⚠️ Error appending to existing file, creating new: {e}")
                    # Fallback: create new file
                    self._create_new_excel_file(df, filename)
            else:
                # Create new file
                self._create_new_excel_file(df, filename)
            
            return filename
            
        except Exception as e:
            print(f"❌ Error saving ICANN analysis: {e}")
            return None

    def _create_new_excel_file(self, df, filename):
        """Helper method to create a new Excel file"""
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            # Main results sheet
            df.to_excel(writer, sheet_name='Domain Analysis', index=False)
            
            # High risk domains sheet
            high_risk_df = df[df['High Risk'] == True]
            if not high_risk_df.empty:
                high_risk_df.to_excel(writer, sheet_name='High Risk Domains', index=False)
            
            # Summary sheet
            summary_data = {
                'Metric': ['Total Domains', 'High Risk', 'Medium Risk', 'Low Risk', 'Average Risk Score'],
                'Value': [
                    len(df),
                    len(high_risk_df),
                    len(df[df['Medium Risk'] == True]),
                    len(df[(df['High Risk'] == False) & (df['Medium Risk'] == False)]),
                    df['Risk Score'].mean()
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        print(f"✅ Created new file: {filename}")