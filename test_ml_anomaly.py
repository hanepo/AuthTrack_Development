"""
Test ML Anomaly Detection
Generate traffic to trigger anomaly alerts

REQUIREMENTS:
- App must be running (python app.py)
- You must be logged in as ADMIN
- Telegram Chat ID configured in your profile (optional, for Telegram alerts)

HOW IT WORKS:
This script downloads large files to generate network traffic spikes.
When traffic exceeds threshold (50 KB minimum or baseline + 3*std), anomaly is detected.

Telegram triggers at: 250 KB minimum OR 5x baseline (whichever is larger)
"""

import requests
import time
import sys

def test_anomaly_detection():
    print("=" * 70)
    print("  ML ANOMALY DETECTION TEST")
    print("=" * 70)
    print()
    print("📋 CHECKLIST:")
    print("  1. ✓ App running on http://127.0.0.1:5000")
    print("  2. ✓ Logged in as ADMIN")
    print("  3. ✓ Dashboard open to see results")
    print("  4. ✓ Telegram Chat ID configured (if you want Telegram alerts)")
    print()
    
    input("Press ENTER when ready to start test...")
    print()
    
    print("=" * 70)
    print("  GENERATING TRAFFIC SPIKES")
    print("=" * 70)
    print()
    
    # Test URLs with different sizes
    test_urls = [
        ("Small (100 KB)", "https://httpbin.org/bytes/102400", "100 KB"),
        ("Medium (500 KB)", "https://httpbin.org/bytes/512000", "500 KB"),
        ("Large (1 MB)", "https://httpbin.org/bytes/1048576", "1 MB"),
        ("Extra Large (2 MB)", "https://httpbin.org/bytes/2097152", "2 MB"),
    ]
    
    for i, (name, url, size) in enumerate(test_urls, 1):
        print(f"[{i}/{len(test_urls)}] Downloading {name} ({size})...")
        try:
            start = time.time()
            response = requests.get(url, timeout=30)
            elapsed = time.time() - start
            
            if response.status_code == 200:
                actual_size = len(response.content) / 1024  # KB
                print(f"     ✓ Downloaded {actual_size:.2f} KB in {elapsed:.2f}s")
                print(f"     → Check dashboard for anomaly detection!")
            else:
                print(f"     ✗ Failed: Status {response.status_code}")
        except Exception as e:
            print(f"     ✗ Error: {e}")
        
        # Wait between downloads
        if i < len(test_urls):
            print(f"     Waiting 5 seconds...")
            time.sleep(5)
        print()
    
    print("=" * 70)
    print("  TEST COMPLETE")
    print("=" * 70)
    print()
    print("📊 WHAT TO CHECK:")
    print("  1. Dashboard → ML Anomaly Detection section")
    print("     - Should show traffic spikes detected")
    print("     - Baseline and Threshold should be visible (not NaN)")
    print()
    print("  2. Terminal logs (app.py):")
    print("     - Look for: 'ML ANOMALIES DETECTED'")
    print("     - Shows spike size, baseline, threshold")
    print()
    print("  3. Telegram (if configured):")
    print("     - Alerts for spikes >= 250 KB OR 5x baseline")
    print()
    print("=" * 70)

def simple_traffic_test():
    """Simpler test using Google's services"""
    print("=" * 70)
    print("  SIMPLE TRAFFIC TEST")
    print("=" * 70)
    print()
    print("This will download files from Google to generate traffic.")
    print()
    
    input("Press ENTER to start...")
    print()
    
    # Download multiple times to create spike
    iterations = 5
    url = "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png"
    
    print(f"Downloading {iterations} times rapidly to create spike...")
    for i in range(iterations):
        try:
            response = requests.get(url)
            size_kb = len(response.content) / 1024
            print(f"  [{i+1}/{iterations}] Downloaded {size_kb:.2f} KB")
        except Exception as e:
            print(f"  [{i+1}/{iterations}] Error: {e}")
    
    print()
    print("✓ Test complete! Check dashboard for anomalies.")
    print()

if __name__ == "__main__":
    print()
    print("Choose test method:")
    print("1. Full Test (generates large traffic spikes)")
    print("2. Simple Test (quick, smaller traffic)")
    print()
    
    choice = input("Enter choice (1 or 2): ").strip()
    print()
    
    if choice == "1":
        test_anomaly_detection()
    elif choice == "2":
        simple_traffic_test()
    else:
        print("Invalid choice. Exiting.")
