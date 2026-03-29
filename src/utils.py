import json
from datetime import datetime
import numpy as np

def convert_to_serializable(obj):
    """Convert NumPy types to Python native types for JSON serialization"""
    if isinstance(obj, (np.float32, np.float64)):
        return float(obj)
    elif isinstance(obj, (np.int32, np.int64, np.int16, np.int8)):
        return int(obj)
    elif isinstance(obj, np.bool_):
        return bool(obj)  # Convert NumPy bool to Python bool
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_to_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_serializable(item) for item in obj]
    elif hasattr(obj, '__dict__'):  # Handle objects with __dict__ attribute
        return convert_to_serializable(obj.__dict__)
    else:
        return obj

def save_results(results, filename="phishing_results.json"):
    """Save detection results to JSON file with NumPy type handling"""
    # Convert all NumPy types to Python native types
    serializable_results = convert_to_serializable(results)
    
    with open(filename, 'w') as f:
        json.dump(serializable_results, f, indent=2, default=str)  # Added default=str as backup
    print(f"✅ Results saved to {filename}")

def generate_report(results, filename="phishing_report.html"):
    """Generate an HTML report of findings"""
    # Convert results to serializable format first
    serializable_results = convert_to_serializable(results)
    
    phishing_count = sum(1 for r in serializable_results if r.get('is_phishing', False))
    suspicious_count = sum(1 for r in serializable_results if not r.get('is_phishing', False) and r.get('confidence', 0) > 0.3)
    
    html_content = f"""
    <html>
    <head>
        <title>Phishing Detection Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #2c3e50; }}
            .phishing {{ background-color: #ffebee; padding: 15px; border-radius: 5px; margin-bottom: 15px; }}
            .suspicious {{ background-color: #fff3e0; padding: 15px; border-radius: 5px; margin-bottom: 15px; }}
            .legitimate {{ background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin-bottom: 15px; }}
            .url {{ font-weight: bold; color: #1565c0; }}
            .similarity {{ color: #e65100; }}
            .bank {{ color: #283593; }}
        </style>
    </head>
    <body>
        <h1>Phishing Detection Report</h1>
        <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <h2>Summary</h2>
        <p>Total URLs analyzed: {len(serializable_results)}</p>
        <p>Phishing sites detected: {phishing_count}</p>
        <p>Suspicious sites: {suspicious_count}</p>
        
        <h2>Detailed Results</h2>
    """
    
    for result in serializable_results:
        status_class = "legitimate"
        status_text = "Legitimate"
        
        if result.get('is_phishing', False):
            status_class = "phishing"
            status_text = "PHISHING"
        elif result.get('confidence', 0) > 0.3:
            status_class = "suspicious"
            status_text = "Suspicious"
        
        target_bank = result.get('target_bank_name', 'None')
        confidence = result.get('confidence', 0)
        
        html_content += f"""
        <div class="{status_class}">
            <p class="url">URL: {result['url']}</p>
            <p>Status: <strong>{status_text}</strong></p>
            <p>Target Bank: <span class="bank">{target_bank}</span></p>
            <p>Confidence: <span class="similarity">{confidence:.3f}</span></p>
        </div>
        """
    
    html_content += """
    </body>
    </html>
    """
    
    with open(filename, 'w') as f:
        f.write(html_content)
    
    print(f"✅ Report generated: {filename}")