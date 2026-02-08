"""
Test Alerts System
Check if alerts are being created and retrieved properly
"""

import requests
import json

BASE_URL = "http://127.0.0.1:5000"

print("=" * 60)
print("  TESTING ALERTS SYSTEM")
print("=" * 60)
print()

# Test 1: Check if we can fetch alerts
print("[1] Testing GET /api/alerts...")
try:
    response = requests.get(f"{BASE_URL}/api/alerts")
    if response.status_code == 200:
        alerts = response.json()
        print(f"   ✓ Status: {response.status_code}")
        print(f"   ✓ Alerts found: {len(alerts)}")
        if alerts:
            print(f"   Latest alert: {alerts[0].get('message', 'No message')}")
        else:
            print("   ⚠️  No alerts in database")
    else:
        print(f"   ✗ Status: {response.status_code}")
        print(f"   Error: {response.text}")
except Exception as e:
    print(f"   ✗ Error: {e}")

print()

# Test 2: Check system stats
print("[2] Testing GET /api/system/stats...")
try:
    response = requests.get(f"{BASE_URL}/api/system/stats")
    if response.status_code == 200:
        stats = response.json()
        print(f"   ✓ Status: {response.status_code}")
        print(f"   Total Alerts: {stats.get('totalAlerts', 0)}")
        print(f"   Today Activity: {stats.get('todayActivity', 0)}")
    else:
        print(f"   ✗ Status: {response.status_code}")
except Exception as e:
    print(f"   ✗ Error: {e}")

print()

# Test 3: Check ML anomalies (might create alerts)
print("[3] Testing GET /api/ml/anomalies...")
try:
    response = requests.get(f"{BASE_URL}/api/ml/anomalies")
    if response.status_code == 200:
        data = response.json()
        print(f"   ✓ Status: {response.status_code}")
        print(f"   Available: {data.get('available')}")
        print(f"   Anomalies: {len(data.get('anomalies', []))}")
        if data.get('anomalies'):
            latest = data['anomalies'][-1]
            print(f"   Latest: {latest.get('value_kb')} KB at {latest.get('time')}")
    else:
        print(f"   ✗ Status: {response.status_code}")
        print(f"   Error: {response.text}")
except Exception as e:
    print(f"   ✗ Error: {e}")

print()
print("=" * 60)
print("  DIAGNOSIS")
print("=" * 60)
print()
print("If alerts = 0:")
print("  → No activities creating alerts")
print("  → Check if ML anomalies detected (should create alerts)")
print("  → Check if blocked attempts (should create alerts)")
print()
print("If you see errors:")
print("  → Firebase connection issue")
print("  → Check FIREBASE_DB_URL in .env")
print()
print("=" * 60)
