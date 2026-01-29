# 2FA Email Setup Guide

## Overview

The system now uses email-based 2FA for secure authentication. The verification code is sent to the user's email and is no longer displayed in the interface.

## Setup Instructions

### 1. Configure Email Credentials

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and update with your email credentials:

```
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
```

### 2. Gmail App Password Setup (Recommended)

For Gmail accounts, you need to use an "App Password" instead of your regular password:

1. Go to your Google Account: https://myaccount.google.com/
2. Select "Security" from the left menu
3. Under "How you sign in to Google", select "2-Step Verification" (you must enable this first)
4. At the bottom, select "App passwords"
5. Select "Mail" as the app and "Windows Computer" (or other device)
6. Click "Generate"
7. Copy the 16-character password (no spaces)
8. Use this password in your `.env` file as `EMAIL_PASS`

### 3. Test the Email Function

Start your Flask server:

```bash
python app.py
```

Try logging in - you should receive a 6-digit code via email.

### 4. Security Notes

- ✅ The `.env` file is automatically excluded from git (in `.gitignore`)
- ✅ Never commit your `.env` file to version control
- ✅ The development code display has been removed for security
- ✅ Email credentials are now required - login will fail if not configured

### 5. Troubleshooting

**Error: "Email configuration not set"**

- Make sure `.env` file exists in the project root
- Verify `EMAIL_USER` and `EMAIL_PASS` are set correctly

**Error: "Failed to send verification code"**

- Check if you're using an App Password (not regular password) for Gmail
- Verify your email credentials are correct
- Check if "Less secure app access" is enabled (for non-Gmail)
- Ensure port 587 is not blocked by firewall

**Not receiving emails:**

- Check spam/junk folder
- Verify the email address in your Firebase user account is correct
- Try with a different email provider if Gmail doesn't work

### 6. Email Server Configuration for Other Providers

If not using Gmail, update the SMTP settings in `app.py` (line ~754):

```python
server = smtplib.SMTP('smtp.gmail.com', 587)  # Change to your SMTP server
```

Common SMTP servers:

- Gmail: `smtp.gmail.com:587`
- Outlook: `smtp-mail.outlook.com:587`
- Yahoo: `smtp.mail.yahoo.com:587`
- Office 365: `smtp.office365.com:587`

## Changes Made

1. **Created `.env` file** - Stores email credentials securely
2. **Updated `app.py`** - Loads environment variables, makes email required
3. **Removed dev_code** - No longer displayed in UI or console
4. **Added `.gitignore`** - Prevents committing sensitive files
5. **Created `.env.example`** - Template for easy setup

## Production Deployment

Before deploying to production:

1. Generate a strong random `SECRET_KEY` in `.env`
2. Use environment variables on your hosting platform instead of `.env` file
3. Enable HTTPS/SSL for secure transmission
4. Consider using a dedicated email service (SendGrid, Mailgun, etc.)
