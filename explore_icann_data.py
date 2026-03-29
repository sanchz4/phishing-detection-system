# explore_icann_data.py
import requests
import json
import pandas as pd
from datetime import datetime
import os
import sys
from urllib.parse import urlparse
import time

class ICANNDataExplorer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_urls = {
            'rdap': 'https://rdap.org/domain/',
            'rdap_bootstraps': 'https://rdap.org/',
            'iana_tlds': 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
            'domain_marketplace': 'https://www.icann.org/resources/pages/domain-name-marketplace-indicators',
            'czds': 'https://czds.icann.org/'  # Centralized Zone Data Service
        }
        self.exploration_results = {}
        
    def explore_all_endpoints(self):
        """Explore all available ICANN data endpoints"""
        print("🔍 Exploring ICANN Data Endpoints...")
        print("=" * 60)
        
        exploration_results = {}
        
        # 1. Test RDAP endpoint
        print("\n1. Testing RDAP Endpoint...")
        rdap_data = self.test_rdap_endpoint()
        exploration_results['rdap'] = rdap_data
        
        # 2. Test RDAP bootstrap services
        print("\n2. Testing RDAP Bootstrap Services...")
        bootstrap_data = self.test_rdap_bootstraps()
        exploration_results['bootstraps'] = bootstrap_data
        
        # 3. Get IANA TLD list
        print("\n3. Fetching IANA TLD List...")
        tld_data = self.get_iana_tld_list()
        exploration_results['tlds'] = tld_data
        
        # 4. Test domain availability
        print("\n4. Testing Domain Availability Checks...")
        domain_tests = self.test_domain_availability()
        exploration_results['domain_tests'] = domain_tests
        
        # 5. Test bulk domain lookup
        print("\n5. Testing Bulk Domain Lookup...")
        bulk_data = self.test_bulk_lookup()
        exploration_results['bulk_lookup'] = bulk_data
        
        return exploration_results
    
    def test_rdap_endpoint(self):
        """Test RDAP endpoint with various domain types"""
        test_domains = [
            'idfcfirstbank.com',  # Popular gTLD
            'example.org',  # Organization
            'example.net',  # Network
            'nic.in',       # Country code
            'example.xyz',  # New gTLD
            'test.tk'       # Free domain
        ]
        
        results = {}
        for domain in test_domains:
            try:
                print(f"  Testing RDAP for: {domain}")
                url = f"{self.base_urls['rdap']}{domain}"
                headers = {
                    'Accept': 'application/rdap+json',
                    'User-Agent': f'ICANNDataExplorer/1.0 (API-Key: {self.api_key})'
                }
                
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    results[domain] = {
                        'status': 'success',
                        'data_available': True,
                        'registrar': data.get('entities', [{}])[0].get('name', 'Unknown') if data.get('entities') else 'Unknown',
                        'registration_date': self._extract_event_date(data, 'registration'),
                        'expiration_date': self._extract_event_date(data, 'expiration'),
                        'nameservers_count': len(data.get('nameservers', [])),
                        'statuses': data.get('status', [])
                    }
                else:
                    results[domain] = {
                        'status': f'error_{response.status_code}',
                        'data_available': False,
                        'error': f'HTTP {response.status_code}'
                    }
                
                # Rate limiting
                time.sleep(0.5)
                
            except Exception as e:
                results[domain] = {
                    'status': 'exception',
                    'data_available': False,
                    'error': str(e)
                }
        
        return results
    
    def test_rdap_bootstraps(self):
        """Test RDAP bootstrap services"""
        try:
            print("  Fetching RDAP bootstrap data...")
            url = self.base_urls['rdap_bootstraps']
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                return {
                    'status': 'success',
                    'bootstrap_available': True,
                    'content_type': response.headers.get('content-type', 'Unknown')
                }
            else:
                return {
                    'status': f'error_{response.status_code}',
                    'bootstrap_available': False
                }
                
        except Exception as e:
            return {
                'status': 'exception',
                'bootstrap_available': False,
                'error': str(e)
            }
    
    def get_iana_tld_list(self):
        """Get the official IANA TLD list"""
        try:
            print("  Downloading IANA TLD list...")
            response = requests.get(self.base_urls['iana_tlds'], timeout=10)
            
            if response.status_code == 200:
                tlds = [line.strip() for line in response.text.split('\n') if line.strip() and not line.startswith('#')]
                return {
                    'status': 'success',
                    'tld_count': len(tlds),
                    'sample_tlds': tlds[:20],  # First 20 TLDs
                    'all_tlds_available': True
                }
            else:
                return {
                    'status': f'error_{response.status_code}',
                    'tld_count': 0,
                    'all_tlds_available': False
                }
                
        except Exception as e:
            return {
                'status': 'exception',
                'tld_count': 0,
                'all_tlds_available': False,
                'error': str(e)
            }
    
    def test_domain_availability(self):
        """Test domain availability checking"""
        test_domains = [
            'this-domain-probably-does-not-exist-12345.com',
            'another-fake-domain-67890.org'
        ]
        
        results = {}
        for domain in test_domains:
            try:
                print(f"  Checking availability for: {domain}")
                url = f"{self.base_urls['rdap']}{domain}"
                headers = {
                    'Accept': 'application/rdap+json',
                    'User-Agent': f'ICANNDataExplorer/1.0 (API-Key: {self.api_key})'
                }
                
                response = requests.get(url, headers=headers, timeout=10)
                
                # 404 means domain not found (likely available)
                # 200 means domain exists
                if response.status_code == 404:
                    results[domain] = {
                        'status': 'available',
                        'exists': False
                    }
                elif response.status_code == 200:
                    results[domain] = {
                        'status': 'registered',
                        'exists': True
                    }
                else:
                    results[domain] = {
                        'status': f'unknown_{response.status_code}',
                        'exists': None
                    }
                
                time.sleep(0.5)
                
            except Exception as e:
                results[domain] = {
                    'status': 'exception',
                    'exists': None,
                    'error': str(e)
                }
        
        return results
    
    def test_bulk_lookup(self):
        """Test bulk domain lookup capabilities"""
        # Test with a small batch
        bulk_domains = [
            'microsoft.com',
            'apple.com',
            'amazon.com',
            'facebook.com',
            'twitter.com'
        ]
        
        results = {}
        success_count = 0
        
        for domain in bulk_domains:
            try:
                url = f"{self.base_urls['rdap']}{domain}"
                headers = {
                    'Accept': 'application/rdap+json',
                    'User-Agent': f'ICANNDataExplorer/1.0 (API-Key: {self.api_key})'
                }
                
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    success_count += 1
                    data = response.json()
                    results[domain] = {
                        'status': 'success',
                        'registrar': data.get('entities', [{}])[0].get('name', 'Unknown') if data.get('entities') else 'Unknown',
                        'registration_date': self._extract_event_date(data, 'registration')
                    }
                else:
                    results[domain] = {
                        'status': f'error_{response.status_code}'
                    }
                
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                results[domain] = {
                    'status': 'exception',
                    'error': str(e)
                }
        
        return {
            'total_domains': len(bulk_domains),
            'successful_lookups': success_count,
            'success_rate': (success_count / len(bulk_domains)) * 100,
            'detailed_results': results
        }
    
    def _extract_event_date(self, data, event_type):
        """Extract specific event date from RDAP data"""
        for event in data.get('events', []):
            if event.get('eventAction') == event_type:
                return event.get('eventDate')
        return None
    
    def generate_exploration_report(self, results, filename="icann_data_exploration_report.xlsx"):
        """Generate comprehensive exploration report"""
        try:
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                # 1. RDAP Test Results
                rdap_data = []
                for domain, info in results['rdap'].items():
                    rdap_data.append({
                        'Domain': domain,
                        'Status': info['status'],
                        'Data Available': info['data_available'],
                        'Registrar': info.get('registrar', 'N/A'),
                        'Registration Date': info.get('registration_date', 'N/A'),
                        'Expiration Date': info.get('expiration_date', 'N/A'),
                        'Nameservers Count': info.get('nameservers_count', 0),
                        'Error': info.get('error', '')
                    })
                
                if rdap_data:
                    pd.DataFrame(rdap_data).to_excel(writer, sheet_name='RDAP Tests', index=False)
                
                # 2. Bootstrap Results
                bootstrap_data = [{
                    'Service': 'RDAP Bootstrap',
                    'Status': results['bootstraps']['status'],
                    'Available': results['bootstraps']['bootstrap_available'],
                    'Error': results['bootstraps'].get('error', '')
                }]
                pd.DataFrame(bootstrap_data).to_excel(writer, sheet_name='Bootstrap Services', index=False)
                
                # 3. TLD Data
                tld_info = results['tlds']
                tld_data = [{
                    'Source': 'IANA',
                    'Status': tld_info['status'],
                    'Total TLDs': tld_info['tld_count'],
                    'Available': tld_info['all_tlds_available'],
                    'Sample TLDs': ', '.join(tld_info.get('sample_tlds', [])[:5])
                }]
                pd.DataFrame(tld_data).to_excel(writer, sheet_name='TLD Information', index=False)
                
                # 4. Domain Availability
                availability_data = []
                for domain, info in results['domain_tests'].items():
                    availability_data.append({
                        'Domain': domain,
                        'Status': info['status'],
                        'Exists': info.get('exists', 'Unknown'),
                        'Error': info.get('error', '')
                    })
                pd.DataFrame(availability_data).to_excel(writer, sheet_name='Domain Availability', index=False)
                
                # 5. Bulk Lookup Results
                bulk_info = results['bulk_lookup']
                bulk_summary = [{
                    'Total Domains': bulk_info['total_domains'],
                    'Successful Lookups': bulk_info['successful_lookups'],
                    'Success Rate (%)': bulk_info['success_rate'],
                    'Status': 'Bulk lookup test completed'
                }]
                pd.DataFrame(bulk_summary).to_excel(writer, sheet_name='Bulk Lookup Summary', index=False)
                
                # 6. Detailed Bulk Results
                detailed_bulk = []
                for domain, info in bulk_info['detailed_results'].items():
                    detailed_bulk.append({
                        'Domain': domain,
                        'Status': info['status'],
                        'Registrar': info.get('registrar', 'N/A'),
                        'Registration Date': info.get('registration_date', 'N/A'),
                        'Error': info.get('error', '')
                    })
                pd.DataFrame(detailed_bulk).to_excel(writer, sheet_name='Bulk Lookup Details', index=False)
                
                # 7. API Capabilities Summary
                capabilities = [
                    {'Feature': 'RDAP Domain Lookup', 'Available': any(r['data_available'] for r in results['rdap'].values())},
                    {'Feature': 'RDAP Bootstraps', 'Available': results['bootstraps']['bootstrap_available']},
                    {'Feature': 'TLD List Access', 'Available': results['tlds']['all_tlds_available']},
                    {'Feature': 'Domain Availability', 'Available': True},  # We tested this
                    {'Feature': 'Bulk Lookups', 'Available': bulk_info['success_rate'] > 50},
                    {'Feature': 'Registration Dates', 'Available': any('registration_date' in r and r['registration_date'] for r in results['rdap'].values())},
                    {'Feature': 'Registrar Information', 'Available': any(r.get('registrar') != 'Unknown' for r in results['rdap'].values())}
                ]
                pd.DataFrame(capabilities).to_excel(writer, sheet_name='API Capabilities', index=False)
            
            print(f"✅ Exploration report saved to: {filename}")
            return filename
            
        except Exception as e:
            print(f"❌ Error generating exploration report: {e}")
            return None
    
    def download_sample_dataset(self, filename="icann_sample_dataset.xlsx"):
        """Download a comprehensive sample dataset"""
        print("\n📥 Downloading Comprehensive Sample Dataset...")
        
        # Get diverse sample of domains
        sample_domains = [
            # Popular domains
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
            # Indian banks (your focus)
            'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'idfcfirstbank.com',
            # Different TLDs
            'example.org', 'example.net', 'example.info', 'example.biz',
            # Country codes
            'google.co.in', 'bbc.co.uk', 'github.io',
            # New gTLDs
            'example.xyz', 'example.top', 'example.club'
        ]
        
        all_data = []
        
        for domain in sample_domains:
            try:
                print(f"  Fetching: {domain}")
                url = f"{self.base_urls['rdap']}{domain}"
                headers = {
                    'Accept': 'application/rdap+json',
                    'User-Agent': f'ICANNDataExplorer/1.0 (API-Key: {self.api_key})'
                }
                
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract key information
                    domain_info = {
                        'Domain': domain,
                        'TLD': f".{domain.split('.')[-1]}",
                        'Status': 'Registered',
                        'Registrar': data.get('entities', [{}])[0].get('name', 'Unknown') if data.get('entities') else 'Unknown',
                        'Registration Date': self._extract_event_date(data, 'registration'),
                        'Expiration Date': self._extract_event_date(data, 'expiration'),
                        'Last Updated': self._extract_event_date(data, 'last changed'),
                        'Nameservers Count': len(data.get('nameservers', [])),
                        'Domain Status': ', '.join(data.get('status', [])),
                        'DNSSEC': data.get('secureDNS', {}).get('delegationSigned', False),
                        'Data Source': 'RDAP',
                        'Query Timestamp': datetime.now().isoformat()
                    }
                    
                    all_data.append(domain_info)
                else:
                    all_data.append({
                        'Domain': domain,
                        'TLD': f".{domain.split('.')[-1]}",
                        'Status': f'Error {response.status_code}',
                        'Registrar': 'N/A',
                        'Registration Date': 'N/A',
                        'Expiration Date': 'N/A',
                        'Last Updated': 'N/A',
                        'Nameservers Count': 0,
                        'Domain Status': 'N/A',
                        'DNSSEC': False,
                        'Data Source': 'RDAP',
                        'Query Timestamp': datetime.now().isoformat()
                    })
                
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                print(f"  ❌ Error fetching {domain}: {e}")
                all_data.append({
                    'Domain': domain,
                    'TLD': f".{domain.split('.')[-1]}" if '.' in domain else 'Unknown',
                    'Status': f'Exception: {str(e)}',
                    'Registrar': 'N/A',
                    'Registration Date': 'N/A',
                    'Expiration Date': 'N/A',
                    'Last Updated': 'N/A',
                    'Nameservers Count': 0,
                    'Domain Status': 'N/A',
                    'DNSSEC': False,
                    'Data Source': 'RDAP',
                    'Query Timestamp': datetime.now().isoformat()
                })
        
        # Save to Excel
        if all_data:
            df = pd.DataFrame(all_data)
            df.to_excel(filename, index=False)
            print(f"✅ Sample dataset saved to: {filename}")
            print(f"📊 Total domains in dataset: {len(all_data)}")
            return filename
        else:
            print("❌ No data collected")
            return None


def main():
    """Main function to explore ICANN data"""
    print("🔍 ICANN Data Exploration Tool")
    print("=" * 50)
    
    # Get API key from config or user input
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            api_key = config.get('icann', {}).get('api_key')
    except:
        api_key = None
    
    if not api_key:
        api_key = input("Enter your ICANN API key: ").strip()
    
    if not api_key:
        print("❌ No API key provided. Exiting.")
        return
    
    # Initialize explorer
    explorer = ICANNDataExplorer(api_key)
    
    try:
        # Explore all endpoints
        results = explorer.explore_all_endpoints()
        
        # Generate exploration report
        report_file = explorer.generate_exploration_report(results)
        
        # Download comprehensive sample dataset
        dataset_file = explorer.download_sample_dataset()
        
        print("\n🎉 EXPLORATION COMPLETED!")
        print("=" * 40)
        print(f"📋 Exploration Report: {report_file}")
        print(f"📊 Sample Dataset: {dataset_file}")
        print("\n📈 Summary of Available Data:")
        
        # Print capabilities summary
        rdap_success = sum(1 for r in results['rdap'].values() if r['data_available'])
        print(f"  ✅ RDAP Domain Lookups: {rdap_success}/{len(results['rdap'])} successful")
        print(f"  ✅ TLD Information: {results['tlds']['tld_count']} TLDs available")
        print(f"  ✅ Bulk Lookups: {results['bulk_lookup']['success_rate']:.1f}% success rate")
        print(f"  ✅ Domain Availability: Tested {len(results['domain_tests'])} domains")
        
    except Exception as e:
        print(f"❌ Exploration failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()