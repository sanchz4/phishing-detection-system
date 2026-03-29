import os
import json
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from PIL import Image
import io

def capture_bank_screenshots():
    """Capture comprehensive screenshots of known bank sites"""
    print("🔄 Setting up comprehensive bank screenshots for phishing detection...")
    
    # Load config
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    # Setup Chrome driver
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    
    driver = webdriver.Chrome(options=chrome_options)
    
    try:
        # Create screenshots directory if it doesn't exist
        os.makedirs("bank_screenshots", exist_ok=True)
        
        for bank in config["known_banks"]:
            bank_short_name = bank["short_name"]
            bank_name = bank["name"]
            
            print(f"\n📸 Processing {bank_name}...")
            
            # Capture MAIN PAGE screenshot
            main_page_path = f"bank_screenshots/{bank_short_name}_main.png"
            if not os.path.exists(main_page_path):
                print(f"  Capturing main page...")
                try:
                    driver.get(bank["url"])
                    WebDriverWait(driver, 20).until(
                        EC.presence_of_element_located((By.TAG_NAME, "body"))
                    )
                    time.sleep(3)
                    
                    # Scroll to capture important elements
                    try:
                        # Try to find header/logo
                        header_selectors = ["header", "nav", ".header", ".navbar", "#header"]
                        for selector in header_selectors:
                            try:
                                element = driver.find_element(By.CSS_SELECTOR, selector)
                                driver.execute_script("arguments[0].scrollIntoView();", element)
                                break
                            except:
                                continue
                    except:
                        pass
                    
                    screenshot = driver.get_screenshot_as_png()
                    img = Image.open(io.BytesIO(screenshot))
                    img.save(main_page_path)
                    print(f"  ✅ Main page saved: {main_page_path}")
                    
                except Exception as e:
                    print(f"  ❌ Failed to capture main page: {e}")
            
            # Capture LOGIN PAGE screenshot (if available)
            if "login_url" in bank and bank["login_url"]:
                login_page_path = f"bank_screenshots/{bank_short_name}_login.png"
                if not os.path.exists(login_page_path):
                    print(f"  Capturing login page...")
                    try:
                        driver.get(bank["login_url"])
                        WebDriverWait(driver, 20).until(
                            EC.presence_of_element_located((By.TAG_NAME, "body"))
                        )
                        time.sleep(3)
                        
                        # Focus on login form if possible
                        try:
                            login_selectors = [
                                "form", "input[type='password']", "#login", ".login-form",
                                ".auth-form", ".signin-form"
                            ]
                            for selector in login_selectors:
                                try:
                                    element = driver.find_element(By.CSS_SELECTOR, selector)
                                    driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", element)
                                    break
                                except:
                                    continue
                        except:
                            pass
                        
                        screenshot = driver.get_screenshot_as_png()
                        img = Image.open(io.BytesIO(screenshot))
                        img.save(login_page_path)
                        print(f"  ✅ Login page saved: {login_page_path}")
                        
                    except Exception as e:
                        print(f"  ❌ Failed to capture login page: {e}")
            
            # Capture KEY ELEMENTS screenshot (logo, header, etc.)
            elements_path = f"bank_screenshots/{bank_short_name}_elements.png"
            if not os.path.exists(elements_path):
                print(f"  Capturing key elements...")
                try:
                    driver.get(bank["url"])
                    WebDriverWait(driver, 20).until(
                        EC.presence_of_element_located((By.TAG_NAME, "body"))
                    )
                    time.sleep(2)
                    
                    # Try to capture logo and branding
                    try:
                        logo_selectors = [
                            "img[alt*='logo']", "img[src*='logo']", ".logo", "#logo",
                            "img[alt*='bank']", "img[src*='brand']"
                        ]
                        for selector in logo_selectors:
                            try:
                                element = driver.find_element(By.CSS_SELECTOR, selector)
                                driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", element)
                                break
                            except:
                                continue
                    except:
                        pass
                    
                    # Take a tighter screenshot focused on branding
                    screenshot = driver.get_screenshot_as_png()
                    img = Image.open(io.BytesIO(screenshot))
                    
                    # Crop to focus on top section (where logos usually are)
                    width, height = img.size
                    cropped_img = img.crop((0, 0, width, min(height, 400)))  # Top 400px
                    cropped_img.save(elements_path)
                    print(f"  ✅ Key elements saved: {elements_path}")
                    
                except Exception as e:
                    print(f"  ❌ Failed to capture key elements: {e}")
        
        print("\n🎉 Comprehensive screenshot capture completed!")
        
    except Exception as e:
        print(f"❌ Error during setup: {e}")
    
    finally:
        driver.quit()

def check_screenshots():
    """Check if all required screenshots exist"""
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    print("\n📋 Screenshot Status:")
    print("=" * 50)
    
    all_good = True
    for bank in config["known_banks"]:
        bank_short_name = bank["short_name"]
        bank_name = bank["name"]
        
        main_exists = os.path.exists(f"bank_screenshots/{bank_short_name}_main.png")
        login_exists = "login_url" in bank and os.path.exists(f"bank_screenshots/{bank_short_name}_login.png")
        elements_exists = os.path.exists(f"bank_screenshots/{bank_short_name}_elements.png")
        
        status = []
        if main_exists: status.append("Main ✓")
        else: status.append("Main ✗")
        
        if login_exists: status.append("Login ✓") 
        else: status.append("Login ✗")
        
        if elements_exists: status.append("Elements ✓")
        else: status.append("Elements ✗")
        
        print(f"{bank_name}: {', '.join(status)}")
        
        if not (main_exists and (login_exists or not bank.get("login_url")) and elements_exists):
            all_good = False
    
    if all_good:
        print("\n✅ All screenshots are available!")
    else:
        print("\n❌ Some screenshots are missing!")
    
    return all_good

if __name__ == "__main__":
    print("=" * 60)
    print("COMPREHENSIVE BANK SCREENSHOT CAPTURE TOOL")
    print("=" * 60)
    
    # Check if config exists
    if not os.path.exists("config.json"):
        print("❌ config.json not found! Please create it first.")
        exit(1)
    
    # Capture comprehensive screenshots
    capture_bank_screenshots()
    
    # Verify all screenshots were captured
    check_screenshots()
    
    print("\n📋 Next steps:")
    print("1. The system will now use better screenshots for comparison")
    print("2. Run: python -m src.main --url \"https://www.onlinesbi.sbi\"")
    print("3. Check improved results in generated JSON files")