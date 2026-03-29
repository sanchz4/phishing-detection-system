# automated_monitor.py (ROOT LEVEL)
import schedule
import time
import os
import sys
from datetime import datetime
import pandas as pd

# Add src to path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from social_media_crawler import SocialMediaCrawler
from detector import PhishingDetector

class AutomatedMonitor:
    def __init__(self):
        self.social_crawler = None
        self.detector = None
        self.monitoring_log = []
        
    def initialize_services(self):
        """Initialize the monitoring services"""
        try:
            print("🔄 Initializing monitoring services...")
            self.social_crawler = SocialMediaCrawler(headless=True)
            self.detector = PhishingDetector()
            print("✅ Services initialized successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to initialize services: {e}")
            return False
    
    def cleanup_services(self):
        """Clean up services after monitoring"""
        try:
            if self.social_crawler:
                self.social_crawler.close()
            if self.detector:
                self.detector.close()
            print("🧹 Services cleaned up")
        except Exception as e:
            print(f"⚠️  Error during cleanup: {e}")
    
    def run_social_media_monitoring(self):
        """Run one cycle of social media monitoring"""
        print(f"\n🕒 Starting social media monitoring at {datetime.now()}")
        
        try:
            # Perform social media crawl
            social_results = self.social_crawler.comprehensive_crawl()
            
            if social_results:
                # Save social media results
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                excel_filename = f"data/social_media_monitoring_{timestamp}.xlsx"
                
                # Ensure data directory exists
                os.makedirs('data', exist_ok=True)
                
                self.social_crawler.save_to_excel(excel_filename)
                
                # Analyze embedded URLs
                url_analysis_results = self.analyze_embedded_urls(social_results)
                
                # Save URL analysis
                if url_analysis_results:
                    url_results_file = f"data/url_analysis_{timestamp}.json"
                    self.save_url_analysis(url_analysis_results, url_results_file)
                
                # Log this monitoring session
                self.log_monitoring_session(social_results, url_analysis_results, timestamp)
                
                # Print alert if high risk found
                high_risk_count = len([r for r in social_results if r['suspicion_score'] > 0.7])
                if high_risk_count > 0:
                    print(f"🚨 ALERT: {high_risk_count} HIGH RISK POSTS DETECTED!")
                
                return True
            else:
                print("✅ No suspicious content found in this monitoring cycle")
                return True
                
        except Exception as e:
            print(f"❌ Social media monitoring failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def analyze_embedded_urls(self, social_results):
        """Analyze URLs found in social media posts"""
        print("🔗 Analyzing embedded URLs...")
        url_analysis_results = []
        analyzed_urls = set()
        
        for post in social_results:
            for url in post.get('links', []):
                if url not in analyzed_urls and self.is_suspicious_url(url):
                    try:
                        print(f"  Analyzing: {url}")
                        analysis_result = self.detector.analyze_url(url, comprehensive=False)
                        
                        url_result = {
                            'url': url,
                            'source_platform': post['platform'],
                            'source_username': post.get('username', 'Unknown'),
                            'source_suspicion_score': post.get('suspicion_score', 0),
                            'phishing_analysis': analysis_result,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        url_analysis_results.append(url_result)
                        analyzed_urls.add(url)
                        
                    except Exception as e:
                        print(f"  ❌ Error analyzing {url}: {e}")
        
        return url_analysis_results
    
    def is_suspicious_url(self, url):
        """Check if URL looks suspicious enough to analyze"""
        suspicious_domains = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        url_shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly']
        banking_keywords = ['sbi', 'hdfc', 'icici', 'axis', 'idfc', 'bank', 'login', 'secure']
        
        url_lower = url.lower()
        
        return (any(domain in url_lower for domain in suspicious_domains) or
                any(shortener in url_lower for shortener in url_shorteners) or
                any(keyword in url_lower for keyword in banking_keywords))
    
    def save_url_analysis(self, results, filename):
        """Save URL analysis results to JSON"""
        try:
            # Convert to serializable format
            serializable_results = []
            for result in results:
                serializable_result = result.copy()
                # Handle any non-serializable objects in phishing_analysis
                if 'phishing_analysis' in serializable_result:
                    serializable_result['phishing_analysis'] = self.make_serializable(
                        serializable_result['phishing_analysis']
                    )
                serializable_results.append(serializable_result)
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(serializable_results, f, indent=2, ensure_ascii=False)
            
            print(f"💾 URL analysis saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving URL analysis: {e}")
    
    def make_serializable(self, obj):
        """Convert object to serializable format"""
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        elif isinstance(obj, dict):
            return {k: self.make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.make_serializable(item) for item in obj]
        else:
            return str(obj)
    
    def log_monitoring_session(self, social_results, url_results, timestamp):
        """Log monitoring session details"""
        session_log = {
            'timestamp': timestamp,
            'social_posts_found': len(social_results),
            'urls_analyzed': len(url_results) if url_results else 0,
            'high_risk_posts': len([r for r in social_results if r['suspicion_score'] > 0.7]),
            'platform_breakdown': {}
        }
        
        # Count posts by platform
        for result in social_results:
            platform = result['platform']
            session_log['platform_breakdown'][platform] = session_log['platform_breakdown'].get(platform, 0) + 1
        
        self.monitoring_log.append(session_log)
        
        # Save log to file
        log_file = 'data/monitoring_log.json'
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(self.monitoring_log, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"⚠️  Could not save monitoring log: {e}")
    
    def run_daily_report(self):
        """Generate daily summary report"""
        print("\n📊 Generating daily summary report...")
        
        try:
            # Get today's date
            today = datetime.now().strftime("%Y%m%d")
            
            # Find today's monitoring files
            social_files = [f for f in os.listdir('data') if f.startswith(f'social_media_monitoring_{today}')]
            url_files = [f for f in os.listdir('data') if f.startswith(f'url_analysis_{today}')]
            
            if social_files:
                # Generate daily summary
                daily_summary = self.generate_daily_summary(social_files, url_files)
                
                # Save daily report
                report_file = f"data/daily_report_{today}.json"
                with open(report_file, 'w', encoding='utf-8') as f:
                    json.dump(daily_summary, f, indent=2, ensure_ascii=False)
                
                print(f"📈 Daily report saved: {report_file}")
            
        except Exception as e:
            print(f"❌ Error generating daily report: {e}")
    
    def generate_daily_summary(self, social_files, url_files):
        """Generate summary of today's monitoring"""
        # This would aggregate data from all today's monitoring sessions
        # For now, return basic summary
        return {
            'date': datetime.now().strftime("%Y-%m-%d"),
            'monitoring_sessions': len(social_files),
            'total_suspicious_posts': sum(1 for _ in social_files),  # Simplified
            'total_urls_analyzed': len(url_files),
            'report_generated_at': datetime.now().isoformat()
        }


def main():
    """Main function for automated monitoring"""
    print("🤖 Starting Automated Phishing Monitoring System")
    print("=" * 50)
    print("This will run continuously and monitor social media")
    print("Press Ctrl+C to stop the monitoring")
    print("=" * 50)
    
    monitor = AutomatedMonitor()
    
    # Initialize services
    if not monitor.initialize_services():
        print("❌ Failed to initialize monitoring services. Exiting.")
        return
    
    try:
        # Schedule monitoring tasks
        
        # Run every 2 hours
        schedule.every(2).hours.do(monitor.run_social_media_monitoring)
        
        # Run daily at 8:00 AM
        schedule.every().day.at("08:00").do(monitor.run_daily_report)
        
        # Run immediately on startup
        print("\n🚀 Running initial monitoring...")
        monitor.run_social_media_monitoring()
        
        print("\n⏰ Monitoring schedule active:")
        print("   - Social media monitoring: Every 2 hours")
        print("   - Daily report generation: 8:00 AM daily")
        print("   - Next social media scan: 2 hours from now")
        
        # Keep the script running
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
            
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        monitor.cleanup_services()
        print("✅ Automated monitoring shutdown complete")


if __name__ == "__main__":
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    main()