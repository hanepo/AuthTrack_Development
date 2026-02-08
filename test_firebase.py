"""
Test Firebase Connection
Quick check if we can write to and read from Firebase
"""

import requests
import os
from dotenv import load_dotenv
from datetime import datetime, timezone

load_dotenv()

FIREBASE_DB_URL = os.getenv('FIREBASE_DB_URL')

print("=" * 70)
print("  FIREBASE CONNECTION TEST")
print("=" * 70)
print()
print(f"Firebase URL: {FIREBASE_DB_URL}")
print()

# Test 1: Write a test alert
print("[1] Writing test alert to Firebase...")
test_alert = {
    'type': 'connection_test',
    'message': 'TEST: Firebase connection test',
    'severity': 'info',
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'read': False
}

try:
    response = requests.post(f"{FIREBASE_DB_URL}/alerts.json", json=test_alert, timeout=5)
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.text[:200]}")
    
    if response.status_code in [200, 201]:
        print("   ✓ Write successful!")
        alert_id = response.json().get('name')
        print(f"   Alert ID: {alert_id}")
    else:
        print("   ✗ Write failed!")
        exit(1)
except Exception as e:
    print(f"   ✗ Error: {e}")
    exit(1)

print()

# Test 2: Read alerts back
print("[2] Reading alerts from Firebase...")
try:
    response = requests.get(f"{FIREBASE_DB_URL}/alerts.json?orderBy=\"timestamp\"&limitToLast=10", timeout=5)
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"   Response type: {type(data)}")
        
        if data:
            if isinstance(data, dict):
                print(f"   ✓ Found {len(data)} alerts")
                print(f"   Alert keys: {list(data.keys())[:5]}")
            else:
                print(f"   Data: {data}")
        else:
            print("   ⚠️  No alerts found (empty response)")
    else:
        print(f"   ✗ Read failed!")
        print(f"   Response: {response.text[:200]}")
except Exception as e:
    print(f"   ✗ Error: {e}")

print()
print("=" * 70)
print("  DIAGNOSIS")
print("=" * 70)
print()
print("If writes succeed but reads return empty:")
print("  → Check Firebase security rules")
print("  → Rules might allow writes but not reads")
print()
print("If both fail:")
print("  → Check FIREBASE_DB_URL in .env")
print("  → Check internet connection")
print("  → Check Firebase project status")
print()
print("=" * 70)
