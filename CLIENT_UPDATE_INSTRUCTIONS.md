# 🔧 FIX UNTUK CLIENT

## MASALAH SOLVED:
✅ NaN di dashboard (Baseline & Threshold)
✅ Website connection refused

---

## CARA UPDATE & RUN (MUDAH):

### Option 1: Guna Batch File (RECOMMENDED)
```cmd
1. Double-click: UPDATE_AND_RUN.bat
   (File ni akan auto pull latest code + start app)

2. Tunggu sampai show:
   * Running on http://127.0.0.1:5000

3. Buka browser: http://127.0.0.1:5000
```

---

### Option 2: Manual
```cmd
1. Pull latest code:
   git pull origin main

2. Start app:
   python app.py

3. Buka browser: http://127.0.0.1:5000
```

---

## ⚠️ IMPORTANT:
- MESTI ada `:5000` dalam URL
- ❌ WRONG: http://127.0.0.1
- ✅ CORRECT: http://127.0.0.1:5000

---

## APA YANG FIXED:

### Before (❌):
```
Baseline: NaN KB | Threshold: NaN KB
```

### After (✅):
```
Baseline: 2617.70 KB | Threshold: 25872.59 KB
```

---

## ROOT CAUSE:
Dashboard guna field lama:
- `baseline / 1024` → undefined → NaN ❌
- `threshold / 1024` → undefined → NaN ❌

Fix: Guna field baru:
- `baseline_kb` (already in KB) ✅
- `threshold_kb` (already in KB) ✅

---

## TEST STEPS:
1. Update code (guna UPDATE_AND_RUN.bat)
2. Login as admin
3. Go to Dashboard
4. Check ML Anomaly Detection section
5. Should show real numbers, NO MORE NaN! 🎯
