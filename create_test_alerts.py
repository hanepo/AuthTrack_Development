"""
Create Test Alerts
Simple script to generate test alerts and verify the alerts system is working
"""

import requests
import time

BASE_URL = "http://127.0.0.1:5000"

print("=" * 70)
print("  CREATE TEST ALERTS")
print("=" * 70)
print()
print("⚠️  IMPORTANT: You must be logged in to the web app first!")
print()
print("Steps:")
print("1. Open http://127.0.0.1:5000 in your browser")
print("2. Login with your account")
print("3. Keep the browser open")
print("4. Run this script")
print()

input("Press ENTER when you're logged in...")
print()

# Create a session to maintain cookies
session = requests.Session()

try:
    # First, try to check if server is running
    print("[1] Checking if server is running...")
    try:
        response = session.get(f"{BASE_URL}/", timeout=3)
        print(f"   ✓ Server is running")
    except requests.exceptions.ConnectionError:
        print("   ✗ Error: Cannot connect to server")
        print("   → Make sure the app is running: python app.py")
        print()
        exit(1)
    
    print()
    print("[2] Creating test alerts...")
    
    # Try to create alerts
    response = session.post(f"{BASE_URL}/api/alerts/test", timeout=5)
    
    # Check response
    if response.status_code == 401 or 'text/html' in response.headers.get('Content-Type', ''):
        print("   ✗ Error: Not logged in or session expired")
        print()
        print("   Please:")
        print("   1. Open browser: http://127.0.0.1:5000")
        print("   2. Login to your account")
        print("   3. Keep browser open")
        print("   4. Run this script again")
        print()
        exit(1)
    
    try:
        data = response.json()
    except:
        print(f"   ✗ Error: Unexpected response (Status {response.status_code})")
        print(f"   Response type: {response.headers.get('Content-Type', 'unknown')}")
        print(f"   Response preview: {response.text[:200]}")
        print()
        print("   → Check if the endpoint exists in app.py")
        exit(1)
    
    if response.status_code == 200:
        if data.get('success'):
            print(f"   ✓ Success! Created {data.get('count', 0)} test alerts")
        else:
            print(f"   ✗ Failed: {data.get('error', 'Unknown error')}")
    else:
        print(f"   ✗ Error: HTTP {response.status_code}")
        print(f"   Response: {data}")
    
    print()
    print("[3] Waiting 2 seconds...")
    time.sleep(2)
    
    # Fetch alerts to verify
    print()
    print("[4] Fetching alerts to verify...")
    response = session.get(f"{BASE_URL}/api/alerts", timeout=5)
    
    if response.status_code == 200:
        try:
            alerts = response.json()
            print(f"   ✓ Found {len(alerts)} total alerts in database")
            
            if alerts:
                print()
                print("   Recent alerts:")
                for i, alert in enumerate(alerts[:5], 1):
                    severity_icon = {
                        'info': 'ℹ️',
                        'warning': '⚠️',
                        'danger': '🚨'
                    }.get(alert.get('severity', 'info'), '•')
                    print(f"   {i}. {severity_icon} {alert.get('message', 'No message')[:60]}...")
        except:
            print("   ✗ Could not parse alerts response")
    else:
        print(f"   ✗ Error fetching alerts: HTTP {response.status_code}")
    
    print()
    print("=" * 70)
    print("  NEXT STEPS")
    print("=" * 70)
    print()
    print("1. Check your dashboard: http://127.0.0.1:5000")
    print("2. Look at 'Recent Alerts' section")
    print("3. Refresh the page if needed")
    print()
    print("If you still don't see alerts:")
    print("  • Check browser console (F12) for errors")
    print("  • Check terminal running app.py for error messages")
    print("  • Look for: '✓ Alert created' messages in terminal")
    print()
    print("=" * 70)

except KeyboardInterrupt:
    print()
    print("   Cancelled by user")
    print()
except Exception as e:
    print()
    print(f"   ✗ Unexpected error: {e}")
    import traceback
    print()
    print("   Full error:")
    traceback.print_exc()
    print()
