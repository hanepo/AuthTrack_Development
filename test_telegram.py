"""Test Telegram notifications to verify bot is working"""
import os
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

def test_telegram_bot():
    """Test if Telegram bot token is valid"""
    print("=" * 60)
    print("TESTING TELEGRAM BOT CONFIGURATION")
    print("=" * 60)
    
    if not TELEGRAM_BOT_TOKEN:
        print("✗ TELEGRAM_BOT_TOKEN not found in .env file")
        return False
    
    print(f"✓ Bot Token: {TELEGRAM_BOT_TOKEN[:10]}...{TELEGRAM_BOT_TOKEN[-5:]}")
    
    # Test bot connection
    try:
        response = requests.get(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getMe")
        data = response.json()
        
        if data.get('ok'):
            bot_info = data.get('result', {})
            print(f"✓ Bot is ACTIVE: @{bot_info.get('username')}")
            print(f"  Bot Name: {bot_info.get('first_name')}")
            print(f"  Bot ID: {bot_info.get('id')}")
            print("\n" + "=" * 60)
            print("NEXT STEPS:")
            print("=" * 60)
            print("1. Login as ADMIN user to your application")
            print("2. Go to Profile Settings")
            print("3. Enter your Telegram Chat ID")
            print("4. Generate a traffic spike (80+ KB)")
            print("5. Check Telegram for the alert!")
            print("\nHow to get your Chat ID:")
            print(f"1. Start chat with your bot: https://t.me/{bot_info.get('username')}")
            print("2. Send any message to the bot")
            print(f"3. Visit: https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates")
            print("4. Look for 'chat':{'id':12345678} in the response")
            print("=" * 60)
            return True
        else:
            print(f"✗ Bot Error: {data.get('description')}")
            return False
            
    except Exception as e:
        print(f"✗ Connection Error: {e}")
        return False

if __name__ == "__main__":
    test_telegram_bot()
