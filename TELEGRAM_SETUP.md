# Telegram Bot Setup Guide

This guide will help you set up Telegram notifications for the NetMonitoring system.

---

## 📱 Overview

The NetMonitoring system can send real-time alerts via Telegram for:

- 🚫 Blocked website attempts
- 🔴 High-risk security findings
- ⚠️ DNS hijacking detection
- 📱 New devices connecting to your network
- 🚨 ML-detected traffic anomalies
- 🔒 Failed login attempts

---

## Part 1: Create Your Telegram Bot (Admin Only)

### Step 1: Open Telegram

- Install Telegram on your phone or desktop
- Open the app and search for `@BotFather`

### Step 2: Create a New Bot

1. Start a chat with BotFather
2. Send the command: `/newbot`
3. Follow the prompts:
   - **Bot Name**: Enter a display name (e.g., "NetMonitoring Alert Bot")
   - **Bot Username**: Enter a unique username ending with 'bot' (e.g., "netmonitor_alert_bot")

### Step 3: Save Your Bot Token

BotFather will reply with your bot token. It looks like this:

```
123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567890
```

**IMPORTANT**: Keep this token secure! Anyone with this token can control your bot.

### Step 4: Configure the .env File

1. Open the `.env` file in your NetMonitoring directory
2. Find the line: `TELEGRAM_BOT_TOKEN=your_bot_token_here`
3. Replace `your_bot_token_here` with your actual bot token:

```env
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567890
```

4. Save the file
5. Restart your Flask application for changes to take effect

---

## Part 2: Get Your Chat ID (All Users)

Each user needs their own Telegram Chat ID to receive notifications.

### Method 1: Using @userinfobot (Recommended)

1. Open Telegram
2. Search for `@userinfobot`
3. Start a chat and send `/start`
4. The bot will reply with your user information, including your **Chat ID**
5. Copy the Chat ID (it's a number like: `123456789`)

### Method 2: Using API (Alternative)

1. Start a chat with your NetMonitoring bot
2. Send any message to the bot (e.g., "Hello")
3. Open this URL in your browser (replace `YOUR_BOT_TOKEN`):
   ```
   https://api.telegram.org/botYOUR_BOT_TOKEN/getUpdates
   ```
4. Look for `"chat":{"id":123456789}` in the JSON response
5. That number is your Chat ID

### Step 3: Add Chat ID to Your Profile

1. Log in to NetMonitoring dashboard
2. Go to **Profile** page
3. Find the **Telegram Chat ID** field
4. Paste your Chat ID
5. Click **Save Changes**

### Step 4: Test Notifications

1. Make sure you've started a chat with your bot (sent at least one message)
2. Try triggering an event:
   - Visit a blocked website (if you have restrictions)
   - Run a security scan from the dashboard
   - Wait for ML anomaly detection (if traffic monitoring is active)

You should receive a notification in Telegram!

---

## 🔧 Troubleshooting

### Issue: Not receiving notifications

**Solution 1: Check if you started a chat with the bot**

- You MUST send at least one message to your bot first
- Search for your bot username in Telegram
- Start a chat and send `/start`

**Solution 2: Verify Chat ID is correct**

- Use @userinfobot to double-check your Chat ID
- Make sure there are no spaces or extra characters
- Update your profile with the correct ID

**Solution 3: Check bot token configuration**

- Make sure TELEGRAM_BOT_TOKEN in .env is correct
- Restart your Flask application after changing .env
- Check terminal/console for any Telegram-related errors

### Issue: Bot token is invalid

**Solution:**

- Create a new bot with @BotFather
- Get a new token
- Update TELEGRAM_BOT_TOKEN in .env file
- Restart the application

### Issue: "Telegram bot not available" message

**Solution:**

- Make sure python-telegram-bot is installed: `pip install python-telegram-bot`
- Check that TELEGRAM_BOT_TOKEN is not empty in .env
- Verify your internet connection
- Check if Telegram services are accessible from your network

---

## 📋 Notification Types

### 1. Blocked Website Attempt

```
🚫 Website Blocked

Website: youtube.com
Reason: restricted
Time: 2026-01-13 14:30:00

This website was blocked according to your restrictions.
```

### 2. Security Alert - High Risk

```
🔴 Security Alert

Type: High Risk
Details: High-risk open ports detected on your network
Time: 2026-01-13 14:35:00

Please review your network security settings.
```

### 3. DNS Hijacking Detection

```
⚠️ Security Alert

Type: DNS Hijack
Details: Possible DNS hijacking detected for some domains
Time: 2026-01-13 14:40:00

Please review your network security settings.
```

### 4. New Device Connected

```
📱 New Device Connected

Device: 192.168.1.105 (AA:BB:CC:DD:EE:FF)
Time: 2026-01-13 14:45:00

A new device has connected to your network.
```

### 5. Traffic Anomaly (ML Detection)

```
🚨 Security Alert

Type: Anomaly
Details: Traffic anomaly detected: 15000 bytes at 14:50:00
Time: 2026-01-13 14:50:00

Please review your network security settings.
```

### 6. Failed Login Attempt

```
🔒 Failed Login Attempt

Username: admin@example.com
IP Address: 192.168.1.50
Time: 2026-01-13 14:55:00

Someone attempted to login with incorrect credentials.
```

---

## 🔒 Security Best Practices

1. **Never share your bot token** - Treat it like a password
2. **Keep Chat IDs private** - Each user should only know their own ID
3. **Don't commit .env to version control** - .env is already in .gitignore
4. **Revoke old bots** - If you think your token is compromised, create a new bot
5. **Test in private** - Always test notifications in private chats first

---

## 🆘 Need Help?

If you encounter issues:

1. Check the Flask application logs for error messages
2. Verify all configurations in .env file
3. Make sure python-telegram-bot is properly installed
4. Test basic bot functionality with @BotFather's commands
5. Contact your system administrator

---

## 📚 Additional Resources

- [Telegram Bot API Documentation](https://core.telegram.org/bots/api)
- [python-telegram-bot Documentation](https://docs.python-telegram-bot.org/)
- [BotFather Commands](https://core.telegram.org/bots#6-botfather)

---

**Last Updated**: January 13, 2026  
**NetMonitoring v1.0**
