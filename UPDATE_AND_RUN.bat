@echo off
echo ============================================
echo   UPDATING AUTHTRACK TO LATEST VERSION
echo ============================================
echo.

echo [1/3] Pulling latest code from GitHub...
git pull origin main

echo.
echo [2/3] Checking for updates...
git log --oneline -3

echo.
echo ============================================
echo   STARTING APPLICATION
echo ============================================
echo.
echo App will start on: http://127.0.0.1:5000
echo.
echo [3/3] Starting Flask app...
python app.py

pause
