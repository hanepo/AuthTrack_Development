# NetMonitoring System - User Guide

## 📖 What is NetMonitoring?

NetMonitoring is a **network monitoring and control system** for Small Office/Home Office (SOHO) environments. It helps you:

- **Monitor** internet traffic and network activity in real-time
- **Control** what websites can be accessed and when
- **Protect** your network from security threats
- **Get alerts** via email and Telegram for important events

---

## 🎯 What Can It Do?

### For Administrators (Parents/Office Managers):

1. **See Who's Online**

   - View all devices connected to your network
   - See what websites they're visiting
   - Monitor internet usage in real-time

2. **Set Website Restrictions**

   - Block specific websites (like social media, games)
   - Set time limits (e.g., no YouTube during work hours 9 AM - 5 PM)
   - Block websites for specific users only

3. **Security Monitoring**

   - Automatic scanning for network threats
   - Detect suspicious DNS activity
   - Find open ports that could be security risks
   - Visual network map showing all connected devices

4. **Get Notifications**

   - Email alerts when someone tries to access blocked sites
   - Telegram messages for security warnings
   - Notifications when new devices connect

5. **Traffic Analysis**
   - See which websites use the most bandwidth
   - AI-powered anomaly detection for unusual traffic
   - View traffic charts and statistics

### For Users (Children/Employees):

1. **View Your Restrictions**

   - See what websites are blocked for you
   - Check your allowed internet hours
   - Understand your access limits

2. **Contact Admin**

   - Send requests to unblock websites
   - Message the administrator directly
   - Request changes to restrictions

3. **View Your Activity**
   - See your own internet usage
   - Monitor your traffic statistics

---

## 🚀 How to Use

### First Time Setup (Admin Only)

1. **Start the System**

   - Open terminal/command prompt
   - Navigate to the project folder
   - Run: `python app.py`
   - Open browser to: `http://127.0.0.1:5000`

2. **Login**

   - Use your email registered in Firebase
   - Enter the 6-digit code sent to your email
   - You're now logged in!

3. **Install Chrome Extension**
   - Go to Chrome Extensions page (`chrome://extensions`)
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `extension` folder from the project
   - The extension will now block restricted websites

### Daily Use

#### Admin Dashboard:

1. **Dashboard** → See overview, system stats, security scanner
2. **Traffic Analysis** → Monitor network activity and traffic
3. **Device Settings** → Set restrictions for users
4. **Logs & Reports** → View blocked attempts and activities
5. **Profile** → Add your Telegram Chat ID for notifications

#### User Dashboard:

1. **Dashboard** → See your statistics
2. **My Traffic** → View your internet usage
3. **My Restrictions** → See what's blocked for you
4. **Contact Admin** → Send messages to administrator
5. **My Profile** → Update your Telegram Chat ID

---

## 🔐 Setting Up Telegram Notifications (Optional)

### Step 1: Create Bot (Admin)

1. Open Telegram app
2. Search for `@BotFather`
3. Send `/newbot` and follow instructions
4. Copy the bot token
5. Add token to `.env` file: `TELEGRAM_BOT_TOKEN=your_token_here`
6. Restart the system

### Step 2: Get Your Chat ID (Everyone)

1. Open Telegram
2. Search for `@userinfobot`
3. Send `/start`
4. Copy your Chat ID (a number like 123456789)

### Step 3: Add to Profile

1. Go to Profile page in the dashboard
2. Paste your Chat ID in "Telegram Chat ID" field
3. Click Save
4. You'll now receive notifications!

---

## 📱 Common Tasks

### Block a Website for a User

1. Go to **Device Settings**
2. Select the user
3. Scroll to "Blocked Websites"
4. Enter website URL (e.g., facebook.com)
5. Click "Add" then "Save Restrictions"

### Set Time Restrictions

1. Go to **Device Settings**
2. Select the user
3. Scroll to "Internet Schedule"
4. Click "Add Schedule"
5. Choose days, time range, and allowed/blocked
6. Click "Save Restrictions"

### Block Website Only at Certain Times

1. Go to **Device Settings**
2. Select the user
3. Scroll to "Website Time Restrictions"
4. Enter website (e.g., youtube.com)
5. Choose days and time range
6. Click "Save Restrictions"

### Run Security Scan

1. Go to **Dashboard**
2. Click "Security Scanner" tab
3. Click "Start Security Scan"
4. Wait for results (shows open ports, DNS issues)

### View Network Map

1. Go to **Dashboard**
2. Scroll to "Network Topology" section
3. See visual map of your network
4. Drag nodes to rearrange

---

## ⚠️ Important Notes

1. **Chrome Extension Required**: The Chrome extension must be installed on each computer/browser you want to monitor and control.

2. **Admin Privileges**: The system needs administrator rights to monitor network traffic.

3. **Email Setup**: Make sure Gmail App Password is configured in `.env` file for 2FA to work.

4. **Telegram**: Each user needs their own Chat ID to receive notifications.

5. **Network**: All devices must be on the same local network to be monitored.

---

## 🆘 Troubleshooting

**Problem: Can't login**

- Check if you entered the correct email
- Check your email for the 6-digit code
- Make sure Gmail App Password is set in `.env`

**Problem: Extension not blocking websites**

- Make sure extension is enabled in Chrome
- Check if restrictions are saved for the correct user
- Try restarting Chrome

**Problem: Not receiving Telegram notifications**

- Make sure you started a chat with your bot first
- Verify Chat ID is correct in your profile
- Check that bot token is set in `.env`

**Problem: No devices showing**

- Make sure packet sniffer is running
- Check if you have admin privileges
- Wait a few seconds for devices to be detected

---

## 📞 Need Help?

If you encounter any issues:

1. Check the terminal/command prompt for error messages
2. Verify all settings in `.env` file
3. Make sure all requirements are installed: `pip install -r requirements.txt`
4. Contact your system administrator

---

**Version:** 1.0  
**Last Updated:** January 13, 2026  
**Developed for:** SOHO Network Monitoring and Control
