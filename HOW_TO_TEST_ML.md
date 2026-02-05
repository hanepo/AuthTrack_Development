# 🧪 How to Test ML Anomaly Detection

## 📊 Understanding the Thresholds

### **Dashboard Detection:**
- **Minimum:** 50 KB
- **Dynamic:** baseline + 3 × standard deviation
- **Trigger:** Uses whichever is HIGHER

### **Telegram Alerts:**
- **Minimum:** 250 KB  
- **Dynamic:** 5 × baseline
- **Trigger:** Uses whichever is HIGHER

---

## 🔧 Method 1: Automated Test Script (EASIEST)

### Steps:
```bash
1. Start your app:
   python app.py

2. Login as ADMIN in browser (http://127.0.0.1:5000)

3. Open Dashboard to see results

4. Run test script:
   python test_ml_anomaly.py

5. Choose option:
   - Option 1: Full test (100 KB → 2 MB downloads)
   - Option 2: Quick test (smaller downloads)

6. Watch for anomalies in:
   - Dashboard → ML Anomaly Detection section
   - Terminal logs (shows "ML ANOMALIES DETECTED")
   - Telegram (if Chat ID configured)
```

---

## 🌐 Method 2: Manual Browser Testing

### Generate Traffic by Downloading Large Files:

1. **While app is running**, open these URLs in your browser:

   ```
   Small spike (500 KB):
   https://httpbin.org/bytes/512000

   Medium spike (1 MB):
   https://httpbin.org/bytes/1048576

   Large spike (5 MB):
   https://httpbin.org/bytes/5242880

   Extra large (10 MB):
   https://httpbin.org/bytes/10485760
   ```

2. **Download multiple times** to create bigger spikes

3. **Check Dashboard** after each download

---

## 🎮 Method 3: Video Streaming

### Stream videos to generate sustained traffic:

1. Open YouTube in browser
2. Play HD videos (720p or 1080p)
3. Let it buffer/download
4. Check dashboard periodically

---

## 📱 Method 4: Mobile Device Testing

1. Connect your phone to same network
2. Download large apps from app store
3. Stream Netflix/YouTube
4. Your network monitor should detect the spike

---

## ✅ What to Check After Testing

### 1. **Dashboard (ML Anomaly Detection section):**
```
✓ Shows detected spike: "2866.82 KB at 16:17:29"
✓ Baseline: [actual number] KB (not NaN)
✓ Threshold: [actual number] KB (not NaN)
```

### 2. **Terminal Logs:**
```
ML ANOMALIES DETECTED: 1 anomalies found
  Latest spike: 2866.82 KB at 16:17:29
  Baseline: 2617.703 KB | Std Dev: 7751.628 KB
  Threshold: 25872.587 KB
  ✓ Dashboard alert created
  → Spike is SIGNIFICANT (2866.82 KB >= 13088.52 KB)
  → Sending Telegram alert to admin: xxx
  ✓ Telegram notification sent
```

### 3. **Telegram (if configured):**
```
🚨 Security Alert

Type: Anomaly
Details: Significant traffic spike: 2866.82 KB at 16:17:29
         (baseline: 2617.70 KB)
Time: 2026-02-06 16:17:35
```

---

## 🎯 Quick Test Checklist

Before testing, ensure:
- [ ] App is running (`python app.py`)
- [ ] Logged in as ADMIN
- [ ] Dashboard is open in browser
- [ ] Terminal window visible to see logs
- [ ] (Optional) Telegram Chat ID configured for alerts

---

## 📈 Understanding the Results

### **Example Scenario:**

1. **Baseline:** 100 KB (your normal traffic)
2. **Dashboard threshold:** 50 KB minimum OR (100 + 3×std)
3. **Telegram threshold:** 250 KB minimum OR (100 × 5) = 500 KB

**Test Results:**
- 80 KB spike → No detection (below 50 KB + threshold)
- 250 KB spike → Dashboard ✓, Telegram ✗ (below 500 KB)
- 600 KB spike → Dashboard ✓, Telegram ✓ (above 500 KB)

---

## 🔍 Troubleshooting

### "No anomalies detected"
- Check threshold in terminal logs
- Baseline might be high (download more to exceed threshold)
- Wait 10 seconds between downloads (dashboard polls every 10s)

### "Still showing NaN"
- Run: `git pull origin main` to get latest fix
- Restart app: Stop (Ctrl+C) then `python app.py`

### "Telegram not working"
- Check admin is logged in (shows "Admin logged in" in terminal)
- Verify Telegram Chat ID in profile settings
- Spike must be ≥ 250 KB to trigger Telegram

---

## 💡 Pro Tips

1. **Create bigger spikes:** Download multiple files simultaneously
2. **Test baseline calculation:** Let it run for 10+ samples first
3. **Threshold adjusts:** Based on your network's normal traffic
4. **Check every 10 seconds:** Dashboard auto-refreshes anomalies
5. **Terminal is your friend:** All detection events logged there

---

## 📞 Need Help?

If anomalies still not detecting:
1. Check terminal for errors
2. Verify scikit-learn installed: `pip install scikit-learn`
3. Ensure 10+ traffic samples collected (wait 1-2 minutes after starting)
4. Check that traffic monitoring is active (should see traffic graph updating)
