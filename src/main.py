import argparse
import json
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detector import PhishingDetector
from src.utils import save_results, generate_report

# Import social media crawler and ICANN client
try:
    from src.social_media_crawler import SocialMediaCrawler
    SOCIAL_MEDIA_AVAILABLE = True
except ImportError:
    SOCIAL_MEDIA_AVAILABLE = False

try:
    from src.icann_api_client import ICANNApiClient
    ICANN_AVAILABLE = True
except ImportError:
    ICANN_AVAILABLE = False

# Import Domain Discovery
try:
    from src.domain_discovery import DomainDiscovery
    DOMAIN_DISCOVERY_AVAILABLE = True
except ImportError:
    DOMAIN_DISCOVERY_AVAILABLE = False

def load_config(config_path="config.json"):
    """Load configuration from JSON file"""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error loading config: {e}")
        return {}

def main():
    parser = argparse.ArgumentParser(description="Phishing Detection System for Indian Banks")
    
    # Existing arguments
    parser.add_argument("--url", help="Single URL to analyze")
    parser.add_argument("--file", help="File containing URLs to analyze (one per line)")
    parser.add_argument("--crawl", action="store_true", help="Crawl from seed URLs")
    parser.add_argument("--output", default="phishing_results.json", help="Output file for results")
    parser.add_argument("--comprehensive", action="store_true", help="Comprehensive analysis with HTML comparison")
    parser.add_argument("--basic", action="store_true", help="Basic analysis only (no HTML comparison)")
    parser.add_argument("--no-hash", action="store_true", help="Disable perceptual hash analysis")
    parser.add_argument("--social-monitor", action="store_true", help="Monitor social media for phishing content")
    
    # ICANN analysis arguments
    parser.add_argument("--icann-analyze", action="store_true", help="Analyze domains using ICANN data")
    parser.add_argument("--icann-output", help="Output Excel file for ICANN analysis")
    parser.add_argument("--config", default="config.json", help="Config file path")
    parser.add_argument("--append", action="store_true", help="Append to existing Excel file instead of creating new one")
    
    # Domain Discovery arguments
    parser.add_argument("--discover", action="store_true", 
                       help="Proactively discover and analyze potential phishing domains")
    parser.add_argument("--discover-only", action="store_true",
                       help="Only discover domains without analysis (quick scan)")
    parser.add_argument("--quick-discover", action="store_true",
                       help="Quick domain discovery using reliable sources only")
    parser.add_argument("--analyze-discovery", help="Analyze previously discovered domains from CSV file")
    parser.add_argument("--discover-iterations", type=int, default=1,
                       help="Number of discovery iterations (default: 1)")
    parser.add_argument("--discover-risk-threshold", type=int, default=30,
                       help="Risk threshold for discovered domains analysis (default: 30)")
    parser.add_argument("--discover-banks", nargs="+",
                       help="Specific banks to target for discovery (e.g., sbi hdfc icici)")
    parser.add_argument("--discover-analyze-all", action="store_true",
                       help="Analyze all discovered domains, not just high-risk")
    
    args = parser.parse_args()

    # Load config
    config = load_config(args.config)
    
    # Domain Discovery Mode
    if args.discover or args.discover_only or args.quick_discover or args.analyze_discovery:
        if not DOMAIN_DISCOVERY_AVAILABLE:
            print("❌ Domain discovery is not available. Please install required dependencies.")
            print("Required: requests, idna, python-dateutil, pandas, rapidfuzz")
            return
        
        print("🎯 Starting Proactive Domain Discovery Mode")
        print("=" * 60)
        
        # Initialize detector
        detector = PhishingDetector(args.config)
        
        try:
            # Mode 1: Analyze previously discovered domains
            if args.analyze_discovery:
                print(f"📁 Analyzing previously discovered domains from: {args.analyze_discovery}")
                results = detector.analyze_discovered_domains(
                    discovery_file=args.analyze_discovery,
                    risk_threshold=args.discover_risk_threshold
                )
                
                if results:
                    # Save results
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_file = f"discovery_analysis_{timestamp}.json"
                    save_results(results, output_file)
                    
                    # Generate report
                    report_file = f"discovery_analysis_report_{timestamp}.html"
                    generate_report(results, report_file)
                    
                    # Print summary
                    print_discovery_summary(results, "DISCOVERY ANALYSIS")
                    
                else:
                    print("✅ No domains met the risk threshold for analysis.")
            
            # Mode 2: Quick discovery (fast and reliable)
            elif args.quick_discover:
                print("⚡ Starting Quick Domain Discovery...")
                
                # Determine target banks
                target_banks = get_target_banks(args, config)
                
                results, discovery_file = detector.quick_discover_and_analyze(
                    target_banks=target_banks,
                    risk_threshold=args.discover_risk_threshold
                )
                
                if results:
                    # Save results
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_file = f"quick_discovery_{timestamp}.json"
                    save_results(results, output_file)
                    
                    # Generate report
                    report_file = f"quick_discovery_report_{timestamp}.html"
                    generate_report(results, report_file)
                    
                    # Print summary
                    print_discovery_summary(results, "QUICK DISCOVERY")
                    
                    # Show top discoveries
                    show_top_discoveries(results)
                    
                    print(f"💾 Quick discovery results saved to: {discovery_file}")
                else:
                    print("✅ No domains found in quick discovery.")
            
            # Mode 3: Discover only (no analysis)
            elif args.discover_only:
                print("🔍 Discovering domains only (analysis skipped)...")
                
                # Determine target banks
                target_banks = get_target_banks(args, config)
                
                discovered_domains, discovery_file = detector.discover_domains_only(
                    target_banks=target_banks,
                    max_iterations=args.discover_iterations
                )
                
                if discovered_domains:
                    print(f"✅ Discovered {len(discovered_domains)} domains")
                    print(f"💾 Discovery results saved to: {discovery_file}")
                    
                    # Show high-risk domains
                    high_risk = [d for d, meta in discovered_domains.items() 
                               if meta.get('score', 0) >= args.discover_risk_threshold]
                    print(f"🚨 High-risk domains ({len(high_risk)}):")
                    for domain in list(high_risk)[:10]:  # Show top 10
                        print(f"  - {domain}")
                    
                    if len(high_risk) > 10:
                        print(f"  ... and {len(high_risk) - 10} more")
                
                else:
                    print("❌ No domains discovered.")
            
            # Mode 4: Discover and analyze (default comprehensive)
            else:
                print("🔍 Discovering and analyzing domains...")
                
                # Determine target banks
                target_banks = get_target_banks(args, config)
                
                results, discovery_file = detector.discover_and_analyze(
                    target_banks=target_banks,
                    max_iterations=args.discover_iterations,
                    risk_threshold=args.discover_risk_threshold,
                    analyze_all=args.discover_analyze_all
                )
                
                if results:
                    # Save results
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_file = f"proactive_discovery_{timestamp}.json"
                    save_results(results, output_file)
                    
                    # Generate report
                    report_file = f"proactive_discovery_report_{timestamp}.html"
                    generate_report(results, report_file)
                    
                    # Print summary
                    print_discovery_summary(results, "PROACTIVE DISCOVERY")
                    
                    # Show top discoveries
                    show_top_discoveries(results)
                    
                else:
                    print("✅ No high-risk domains discovered in this scan.")
                
        except Exception as e:
            print(f"❌ Error during domain discovery: {e}")
            import traceback
            traceback.print_exc()
        finally:
            detector.close()
        
        return

    # Social Media Monitoring Mode
    if args.social_monitor:
        if not SOCIAL_MEDIA_AVAILABLE:
            print("❌ Social media monitoring is not available. Please install required dependencies.")
            print("Required: pandas, openpyxl")
            return
        
        print("🔍 Starting Social Media Phishing Monitoring...")
        print("=" * 60)
        
        # Initialize social media crawler
        crawler = SocialMediaCrawler(headless=True)
        
        try:
            # Perform comprehensive social media crawl
            results = crawler.comprehensive_crawl()
            
            if results:
                # Save to Excel
                if args.icann_output:
                    excel_filename = args.icann_output
                else:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    excel_filename = f"social_media_monitoring_{timestamp}.xlsx"
                
                crawler.save_to_excel(excel_filename)
                
                # Print summary
                print("\n📊 SOCIAL MEDIA MONITORING SUMMARY:")
                print("=" * 40)
                
                platforms = {}
                for result in results:
                    platform = result['platform']
                    platforms[platform] = platforms.get(platform, 0) + 1
                
                for platform, count in platforms.items():
                    print(f"  {platform}: {count} suspicious posts")
                
                high_risk = len([r for r in results if r['suspicion_score'] > 0.7])
                medium_risk = len([r for r in results if 0.4 <= r['suspicion_score'] <= 0.7])
                low_risk = len([r for r in results if r['suspicion_score'] < 0.4])
                
                print(f"🔴 High risk posts: {high_risk}")
                print(f"🟡 Medium risk posts: {medium_risk}")
                print(f"🟢 Low risk posts: {low_risk}")
                print(f"📈 Total suspicious posts: {len(results)}")
                print(f"💾 Results saved to: {excel_filename}")
                
                # Analyze embedded URLs from social media posts WITH ICANN
                print("\n🔗 Analyzing embedded URLs from social media posts...")
                
                # Initialize detector for URL analysis (will use ICANN if configured)
                detector = PhishingDetector(args.config)
                url_analysis_results = analyze_social_media_urls(detector, results)
                detector.close()
                
                if url_analysis_results:
                    save_results(url_analysis_results, "social_media_url_analysis.json")
                    print(f"  ✅ URL analysis saved to: social_media_url_analysis.json")
                
            else:
                print("✅ No suspicious content found in social media monitoring.")
            
        except Exception as e:
            print(f"❌ Error during social media monitoring: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            crawler.close()
        
        return

    # ICANN Analysis Mode (Standalone)
    if args.icann_analyze:
        if not ICANN_AVAILABLE:
            print("❌ ICANN analysis is not available. Please make sure icann_api_client.py exists.")
            return
            
        print("🔍 Starting ICANN Domain Intelligence Analysis...")
        print("=" * 60)
        
        # Get API key from config
        icann_config = config.get("icann", {})
        api_key = icann_config.get("api_key")
        
        if not api_key:
            print("❌ ICANN API key not found in config.json")
            print("   Please add your API key to config.json:")
            print('   "icann": {')
            print('     "api_key": "YOUR_API_KEY_HERE",')
            print('     "enabled": true')
            print('   }')
            return
        
        # Initialize ICANN client
        icann_client = ICANNApiClient(api_key)
        
        try:
            # Get domains to analyze
            domains = []
            if args.url:
                domains = [args.url]
            elif args.file:
                with open(args.file, 'r') as f:
                    domains = [line.strip() for line in f if line.strip()]
            else:
                print("❌ ICANN analysis requires --url or --file argument")
                return
            
            print(f"Analyzing {len(domains)} domains with ICANN data...")
            
            # Perform analysis
            results = icann_client.batch_analyze_domains(domains)
            
            # Save results with append option
            if args.icann_output:
                excel_filename = args.icann_output
            else:
                if args.append and os.path.exists("icann_domain_analysis.xlsx"):
                    excel_filename = "icann_domain_analysis.xlsx"
                else:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    excel_filename = f"icann_domain_analysis_{timestamp}.xlsx"
            
            # Use the updated save method with append support
            if hasattr(icann_client, 'save_analysis_to_excel_with_append'):
                icann_client.save_analysis_to_excel_with_append(results, excel_filename, append=args.append)
            else:
                # Fallback to original method
                icann_client.save_analysis_to_excel(results, excel_filename)
            
            # Print summary
            print("\n📊 ICANN DOMAIN ANALYSIS SUMMARY:")
            print("=" * 40)
            
            high_risk_count = sum(1 for r in results.values() 
                                if r.get('risk_analysis', {}).get('is_high_risk', False))
            medium_risk_count = sum(1 for r in results.values() 
                                  if r.get('risk_analysis', {}).get('is_medium_risk', False))
            
            print(f"🔴 High risk domains: {high_risk_count}")
            print(f"🟡 Medium risk domains: {medium_risk_count}")
            print(f"🟢 Low risk domains: {len(domains) - high_risk_count - medium_risk_count}")
            print(f"📈 Total domains analyzed: {len(domains)}")
            print(f"💾 Results saved to: {excel_filename}")
            
            # Show high risk domains
            if high_risk_count > 0:
                print("\n🚨 HIGH RISK DOMAINS:")
                for url, result in results.items():
                    risk_analysis = result.get('risk_analysis', {})
                    if risk_analysis.get('is_high_risk', False):
                        print(f"  - {url} (Score: {risk_analysis['risk_score']:.2f})")
                        for factor in risk_analysis.get('risk_factors', [])[:3]:
                            print(f"    ⚠️ {factor}")
            
        except Exception as e:
            print(f"❌ Error during ICANN analysis: {e}")
            import traceback
            traceback.print_exc()
        
        return

    # ===== REGULAR URL ANALYSIS MODE (Basic & Comprehensive) =====
    
    # Initialize detector (will automatically use ICANN if configured)
    print("🚀 Initializing Phishing Detector...")
    detector = PhishingDetector(args.config)

    try:
        comprehensive = not args.basic  # Use comprehensive unless --basic is specified

        # Check if ICANN is being used
        icann_config = config.get("icann", {})
        icann_enabled = icann_config.get("enabled", False) and icann_config.get("api_key")
        
        if icann_enabled:
            print("✅ ICANN domain intelligence integrated into analysis")
        else:
            print("⚠️  ICANN not configured - using standard domain analysis")

        if args.comprehensive:
            # ===== COMPREHENSIVE ANALYSIS MODE =====
            print("🌐 Starting comprehensive analysis with HTML comparison...")
            if args.url:
                # Single URL comprehensive analysis
                print(f"🔍 Comprehensive analysis of: {args.url}")
                result = detector.analyze_url(args.url, comprehensive=True)
                results = [result]
            elif args.file:
                # Multiple URLs comprehensive analysis
                results = []
                with open(args.file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                for url in urls:
                    print(f"🔍 Comprehensive analysis of: {url}")
                    result = detector.analyze_url(url, comprehensive=True)
                    results.append(result)
            else:
                print("❌ Comprehensive analysis requires --url or --file argument")
                detector.close()
                return
        else:
            # ===== REGULAR ANALYSIS MODE =====
            if args.url:
                # Analyze single URL
                analysis_type = "Comprehensive" if comprehensive else "Basic"
                print(f"🔍 {analysis_type} analysis of: {args.url}")
                result = detector.analyze_url(args.url, comprehensive=comprehensive)
                results = [result]
            elif args.file:
                # Analyze multiple URLs from file
                analysis_type = "Comprehensive" if comprehensive else "Basic"
                print(f"📁 {analysis_type} analysis of URLs from: {args.file}")
                with open(args.file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                results = []
                for url in urls:
                    print(f"🔍 {analysis_type} analysis of: {url}")
                    result = detector.analyze_url(url, comprehensive=comprehensive)
                    results.append(result)
            elif args.crawl:
                # Crawl from seed URLs
                print("🌐 Starting web crawling...")
                seed_urls = [
                    "https://www.google.com/search?q=sbi+netbanking+login",
                    "https://www.google.com/search?q=idfc+bank+login",
                    "https://www.google.com/search?q=hdfc+netbanking"
                ]
                results = detector.crawl_and_analyze(seed_urls)
            else:
                print("❌ Please specify a mode: --url, --file, or --crawl")
                print("   Or use --social-monitor for social media monitoring")
                print("   Or use --icann-analyze for ICANN domain analysis")
                print("   Or use --discover for proactive domain discovery")
                print("   Or use --quick-discover for fast domain discovery")
                print("   Use --comprehensive for HTML content analysis")
                print("   Use --basic for faster analysis without HTML comparison")
                detector.close()
                return

        # Save results
        save_results(results, args.output)

        # Generate report
        generate_report(results, "phishing_report.html")
        print(f"✅ Results saved to {args.output}")
        print(f"📊 Report generated: phishing_report.html")

        # Print summary
        phishing_count = sum(1 for r in results if r.get("is_phishing", False))
        suspicious_count = sum(1 for r in results if not r.get("is_phishing", False) and r.get('confidence', 0) > 0.3)
        print(f"📈 Analyzed {len(results)} URLs")
        print(f" - Phishing sites detected: {phishing_count}")
        print(f" - Suspicious sites: {suspicious_count}")
        print(f" - Legitimate sites: {len(results) - phishing_count - suspicious_count}")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        detector.close()


def get_target_banks(args, config):
    """Determine which banks to target for discovery"""
    if args.discover_banks:
        return args.discover_banks
    else:
        return [bank["short_name"] for bank in config.get("known_banks", [])]


def print_discovery_summary(results, mode_name):
    """Print summary for discovery results"""
    phishing_count = sum(1 for r in results if r.get("is_phishing", False))
    suspicious_count = sum(1 for r in results if not r.get("is_phishing", False) and r.get('confidence', 0) > 0.3)
    high_score_count = sum(1 for r in results if r.get('discovery_score', 0) > 50)
    
    print(f"\n📊 {mode_name} RESULTS:")
    print("=" * 40)
    print(f"📈 Domains discovered: {len(results)}")
    print(f"🔴 Phishing sites detected: {phishing_count}")
    print(f"🟡 Suspicious sites: {suspicious_count}")
    print(f"⭐ High discovery score: {high_score_count}")
    print(f"🟢 Legitimate sites: {len(results) - phishing_count - suspicious_count}")


def show_top_discoveries(results):
    """Show top discoveries with high scores"""
    high_score = [r for r in results if r.get('discovery_score', 0) > 50]
    if high_score:
        print(f"\n🚨 HIGH SCORE DISCOVERIES ({len(high_score)}):")
        for result in sorted(high_score, key=lambda x: x.get('discovery_score', 0), reverse=True)[:5]:
            sources = result.get('discovery_sources', [])
            sources_str = ', '.join(sources[:2]) + ('...' if len(sources) > 2 else '')
            print(f"  - {result['url']}")
            print(f"    📊 Score: {result.get('discovery_score', 0)} | "
                  f"🔍 Sources: {sources_str} | "
                  f"🎯 Confidence: {result.get('confidence', 0):.2f}")


def analyze_social_media_urls(detector, social_results):
    """Analyze URLs found in social media posts"""
    url_analysis_results = []
    analyzed_urls = set()
    
    for post in social_results:
        for url in post.get('links', []):
            if url not in analyzed_urls and is_suspicious_url(url):
                try:
                    print(f"  🔗 Analyzing: {url}")
                    analysis_result = detector.analyze_url(url, comprehensive=False)
                    
                    url_result = {
                        'url': url,
                        'source_platform': post['platform'],
                        'source_username': post.get('username', 'Unknown'),
                        'source_content': post.get('content', '')[:200],  # First 200 chars
                        'source_suspicion_score': post.get('suspicion_score', 0),
                        'phishing_analysis': analysis_result,
                        'combined_risk_score': calculate_combined_risk(
                            post.get('suspicion_score', 0), 
                            analysis_result.get('confidence', 0)
                        )
                    }
                    
                    url_analysis_results.append(url_result)
                    analyzed_urls.add(url)
                    
                except Exception as e:
                    print(f"  ❌ Error analyzing {url}: {e}")
    
    return url_analysis_results


def is_suspicious_url(url):
    """Check if URL looks suspicious"""
    suspicious_domains = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    url_shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'shorte.st']
    
    url_lower = url.lower()
    
    # Check for suspicious domains
    if any(domain in url_lower for domain in suspicious_domains):
        return True
    
    # Check for URL shorteners
    if any(shortener in url_lower for shortener in url_shorteners):
        return True
    
    # Check for banking keywords in URL (potential phishing)
    banking_keywords = ['sbi', 'hdfc', 'icici', 'axis', 'idfc', 'bank', 'login', 'secure', 'verify']
    if any(keyword in url_lower for keyword in banking_keywords):
        return True
    
    return False


def calculate_combined_risk(social_score, phishing_confidence):
    """Calculate combined risk score from social media and URL analysis"""
    # Weight social media suspicion higher since it's the source
    return (social_score * 0.6) + (phishing_confidence * 0.4)


if __name__ == "__main__":
    main()
