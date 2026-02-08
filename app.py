"""
AuthTrack - SOHO Network Monitoring System
Uses Chrome Extension for user activity tracking + Real Packet Sniffing
Firebase for authentication and database
Supports Scapy-based packet capture and ML anomaly detection for admins
"""

import os
import random
import requests
import smtplib
import threading
import time
import socket
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, redirect, url_for, request, jsonify, session
from datetime import datetime, timezone, timedelta
from functools import wraps
from dotenv import load_dotenv
import asyncio

# Load environment variables from .env file
load_dotenv()

# Try to import optional dependencies
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("WARNING: psutil not available - system stats disabled. Install with: pip install psutil")

try:
    from telegram import Bot
    from telegram.error import TelegramError
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    print("WARNING: python-telegram-bot not available - Telegram notifications disabled. Install with: pip install python-telegram-bot")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("ERROR: Scapy not available - packet sniffer DISABLED. Install with: pip install scapy")
    print("NOTE: Packet capture requires Administrator/root privileges.")

# Lazy import for ML - only import when needed to speed up startup
ML_AVAILABLE = False
IsolationForest = None
np = None

def init_ml():
    """Initialize ML libraries on first use"""
    global ML_AVAILABLE, IsolationForest, np, anomaly_detector
    if ML_AVAILABLE:
        return True
    try:
        from sklearn.ensemble import IsolationForest as IF
        import numpy as numpy_module
        IsolationForest = IF
        np = numpy_module
        ML_AVAILABLE = True
        anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        print("ML libraries loaded successfully")
        return True
    except ImportError:
        print("WARNING: scikit-learn not available - ML anomaly detection disabled. Install with: pip install scikit-learn")
        return False

# ============================================================
# GLOBAL STATE FOR PACKET SNIFFER
# ============================================================
sniffer_active = False
sniffer_thread = None
traffic_lock = threading.Lock()
protocol_lock = threading.Lock()
device_stats_lock = threading.Lock()

# Traffic history for charts
traffic_history = {
    'labels': [],
    'inbound': [],
    'outbound': []
}
current_traffic = {'inbound': 0, 'outbound': 0}

# Cumulative traffic counters (never reset, tracks all traffic since start)
cumulative_traffic = {
    'inbound': 0,
    'outbound': 0,
    'total': 0
}

# Protocol stats
protocol_stats = defaultdict(int)

# Device traffic stats
device_traffic_stats = defaultdict(int)
known_devices = set()
device_mac_mapping = {}  # IP to MAC address mapping
device_last_seen = {}  # Track when each device was last seen {ip: timestamp}

# Store admin user ID for notifications (set when admin logs in)
admin_user_id = None

# Capture history for frontend
captured_packets = []
max_captured_packets = 100

# ML Anomaly Detection - initialized on first use
anomaly_detector = None

# Security Scanning State
security_scan_results = {
    'port_scan': {'status': 'idle', 'results': [], 'last_scan': None},
    'dns_check': {'status': 'idle', 'results': [], 'last_scan': None},
    'open_ports': {'status': 'idle', 'results': [], 'last_scan': None}
}
security_scan_lock = threading.Lock()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netmonitoring-secret-key-2024'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Firebase Database URL
FIREBASE_DB_URL = os.environ.get('FIREBASE_DB_URL', 'https://netmotinor-default-rtdb.asia-southeast1.firebasedatabase.app')

# Email config for 2FA (required for security)
EMAIL_USER = os.environ.get('EMAIL_USER', '')
EMAIL_PASS = os.environ.get('EMAIL_PASS', '')

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
telegram_bot = None
if TELEGRAM_AVAILABLE and TELEGRAM_BOT_TOKEN and TELEGRAM_BOT_TOKEN != 'your_bot_token_here':
    try:
        telegram_bot = Bot(token=TELEGRAM_BOT_TOKEN)
        print("Telegram bot initialized successfully")
    except Exception as e:
        print(f"Failed to initialize Telegram bot: {e}")
        telegram_bot = None

# ============================================================
# TELEGRAM NOTIFICATION FUNCTIONS
# ============================================================

def send_telegram_notification(chat_id, message, parse_mode='HTML'):
    """Send a Telegram notification asynchronously"""
    if not telegram_bot or not chat_id:
        return False
    
    def send_async():
        try:
            # Create new event loop for this thread
            # Get or create event loop for this thread
            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            # Send message
            loop.run_until_complete(
                telegram_bot.send_message(
                    chat_id=chat_id,
                    text=message,
                    parse_mode=parse_mode
                )
            )
            # Don't close loop - let it stay open for thread
            print(f"Telegram notification sent to {chat_id}")
            return True
        except TelegramError as e:
            print(f"Telegram error: {e}")
            return False
        except Exception as e:
            print(f"Error sending Telegram notification: {e}")
            return False
    
    # Run in background thread
    thread = threading.Thread(target=send_async)
    thread.daemon = True
    thread.start()
    return True

def get_user_telegram_id(user_id):
    """Fetch user's Telegram Chat ID from Firebase"""
    try:
        url = f"{FIREBASE_DB_URL}/users/{user_id}/telegram_chat_id.json"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            chat_id = response.json()
            return chat_id if chat_id else None
        return None
    except Exception as e:
        print(f"Error fetching Telegram ID: {e}")
        return None

def notify_blocked_attempt(user_id, website, reason="restricted"):
    """Notify user about blocked website attempt"""
    chat_id = get_user_telegram_id(user_id)
    if not chat_id:
        return
    
    message = f"""
🚫 <b>Website Blocked</b>

<b>Website:</b> {website}
<b>Reason:</b> {reason}
<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This website was blocked according to your restrictions.
"""
    send_telegram_notification(chat_id, message)

def notify_security_alert(user_id, alert_type, details):
    """Notify user about security alerts"""
    chat_id = get_user_telegram_id(user_id)
    if not chat_id:
        return
    
    emoji_map = {
        'port_scan': '🔍',
        'dns_hijack': '⚠️',
        'anomaly': '🚨',
        'new_device': '📱',
        'high_risk': '🔴'
    }
    
    emoji = emoji_map.get(alert_type, '⚠️')
    
    message = f"""
{emoji} <b>Security Alert</b>

<b>Type:</b> {alert_type.replace('_', ' ').title()}
<b>Details:</b> {details}
<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please review your network security settings.
"""
    send_telegram_notification(chat_id, message)

def notify_new_device(user_id, device_ip, device_mac=None):
    """Notify user about new device connection"""
    chat_id = get_user_telegram_id(user_id)
    if not chat_id:
        return
    
    device_info = f"{device_ip}"
    if device_mac:
        device_info += f" ({device_mac})"
    
    message = f"""
📱 <b>New Device Connected</b>

<b>Device:</b> {device_info}
<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

A new device has connected to your network.
"""
    send_telegram_notification(chat_id, message)

def notify_failed_login(username, ip_address):
    """Notify admin about failed login attempts"""
    # Get admin user ID (typically uid stored in session or hardcoded admin ID)
    admin_id = "admin_user_id"  # You can modify this to get actual admin ID
    chat_id = get_user_telegram_id(admin_id)
    if not chat_id:
        return
    
    message = f"""
🔒 <b>Failed Login Attempt</b>

<b>Username:</b> {username}
<b>IP Address:</b> {ip_address}
<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Someone attempted to login with incorrect credentials.
"""
    send_telegram_notification(chat_id, message)

# ============================================================
# PACKET SNIFFER FUNCTIONS
# ============================================================

def is_private(ip):
    """Check if IP is private (local network)"""
    if ip.startswith('192.168.') or ip.startswith('10.'):
        return True
    if ip.startswith('172.'):
        try:
            second_octet = int(ip.split('.')[1])
            return 16 <= second_octet <= 31
        except:
            pass
    return False

def process_packet(packet):
    """Process captured packet and update stats"""
    global current_traffic, captured_packets, cumulative_traffic
    
    if not IP in packet:
        return
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    pkt_len = len(packet)
    
    # Store MAC address if available for device identification
    if Ether in packet and is_private(src_ip):
        mac = packet[Ether].src
        if src_ip not in device_mac_mapping:
            device_mac_mapping[src_ip] = mac
    
    # Determine direction and update both current and cumulative counters
    with traffic_lock:
        cumulative_traffic['total'] += pkt_len
        if is_private(src_ip) and not is_private(dst_ip):
            current_traffic['outbound'] += pkt_len
            cumulative_traffic['outbound'] += pkt_len
        else:
            current_traffic['inbound'] += pkt_len
            cumulative_traffic['inbound'] += pkt_len
    
    # Determine protocol and extract ports
    proto = "Other"
    src_port = None
    dst_port = None
    service = ""
    dns_query = None
    
    if TCP in packet:
        proto = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        service = get_service_name(dst_port)
    elif UDP in packet:
        proto = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        service = get_service_name(dst_port)
        
        # Check for DNS query
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            service = "DNS"
    elif ICMP in packet:
        proto = "ICMP"
        service = "ICMP"
    
    # Update protocol stats
    with protocol_lock:
        protocol_stats[proto] += 1
    
    # Discover device
    if is_private(src_ip):
        is_new_device = src_ip not in known_devices
        known_devices.add(src_ip)
        device_last_seen[src_ip] = datetime.now()  # Track last activity

        # Notify about new device (only once per device)
        if is_new_device and admin_user_id:
            # Get MAC address if available
            mac = device_mac_mapping.get(src_ip)
            notify_new_device(admin_user_id, src_ip, mac)
    
    # Build packet info with enhanced data
    packet_info = {
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'protocol': proto,
        'source': src_ip,
        'destination': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'service': service,
        'dns_query': dns_query,
        'length': pkt_len
    }
    
    with traffic_lock:
        captured_packets.append(packet_info)
        if len(captured_packets) > max_captured_packets:
            captured_packets.pop(0)

def get_service_name(port):
    """Map common port numbers to service names"""
    services = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS',
        995: 'POP3S', 3306: 'MySQL', 3389: 'RDP', 5000: 'Flask',
        5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
    }
    return services.get(port, f'Port-{port}' if port else '')

def sniffer_worker():
    """Background thread for packet capture - Real mode only"""
    global sniffer_active
    
    if not SCAPY_AVAILABLE:
        print("ERROR: Scapy is not installed. Packet sniffer requires Scapy.")
        print("Install with: pip install scapy")
        sniffer_active = False
        return
    
    print("Starting Real Packet Sniffer...")
    try:
        # Test sniff first
        sniff(count=1, timeout=1, store=0)
        print("Packet capture started successfully!")
        
        while sniffer_active:
            try:
                sniff(prn=process_packet, store=0, timeout=2)
            except Exception as e:
                print(f"Sniffing error: {e}")
                time.sleep(2)
    except Exception as e:
        print(f"ERROR: Failed to start packet capture: {e}")
        print("Make sure you're running as Administrator on Windows or root on Linux.")
        sniffer_active = False

# ============================================================
# SECURITY SCANNING FUNCTIONS
# ============================================================

def scan_common_ports(target_ip, ports=[21, 22, 23, 25, 80, 443, 445, 3389, 8080]):
    """Scan common ports on target IP"""
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        
        if result == 0:
            service = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                80: 'HTTP', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP', 8080: 'HTTP-Alt'
            }.get(port, 'Unknown')
            
            results.append({
                'port': port,
                'service': service,
                'status': 'open',
                'risk': 'high' if port in [21, 23, 445] else 'medium' if port in [22, 3389] else 'low'
            })
    return results

def check_dns_hijacking():
    """Check for DNS hijacking by testing known domains"""
    results = []
    test_domains = [
        ('google.com', ['142.250.', '172.217.', '216.58.', '172.253.', '142.251.']),
        ('facebook.com', ['157.240.', '31.13.', '163.70.', '157.240.', '69.63.']),
        ('cloudflare.com', ['104.16.', '172.64.', '104.17.', '104.18.']),
        ('amazon.com', ['205.251.', '176.32.', '54.', '52.', '13.', '18.', '99.', '98.']),  # Amazon has many IP ranges
        ('microsoft.com', ['20.', '13.', '40.', '104.'])
    ]
    
    for domain, expected_prefixes in test_domains:
        try:
            ip = socket.gethostbyname(domain)
            is_valid = any(ip.startswith(prefix) for prefix in expected_prefixes)
            
            results.append({
                'domain': domain,
                'resolved_ip': ip,
                'status': 'safe' if is_valid else 'suspicious',
                'risk': 'low' if is_valid else 'high'
            })
        except Exception as e:
            results.append({
                'domain': domain,
                'resolved_ip': 'Failed',
                'status': 'error',
                'risk': 'medium',
                'error': str(e)
            })
    
    return results

def scan_local_open_ports():
    """Scan open ports on local machine"""
    results = []
    common_ports = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3306, 3389, 5000, 5432, 8080, 8443]
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        
        if result == 0:
            service = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP',
                135: 'RPC', 139: 'NetBIOS', 443: 'HTTPS', 445: 'SMB',
                3306: 'MySQL', 3389: 'RDP', 5000: 'Flask', 5432: 'PostgreSQL',
                8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
            }.get(port, 'Unknown')
            
            # Assess risk
            high_risk = [21, 23, 135, 139, 445, 3306, 3389, 5432]
            medium_risk = [22, 25, 80, 8080]
            
            results.append({
                'port': port,
                'service': service,
                'status': 'open',
                'risk': 'high' if port in high_risk else 'medium' if port in medium_risk else 'low'
            })
    
    return results

def run_security_scan(scan_type):
    """Background thread to run security scans"""
    global security_scan_results
    
    with security_scan_lock:
        security_scan_results[scan_type]['status'] = 'scanning'
        security_scan_results[scan_type]['results'] = []
    
    try:
        if scan_type == 'port_scan':
            # Scan common devices on local network
            results = []
            base_ip = '192.168.1.'
            for i in [1, 2, 100, 101, 102]:  # Scan router and a few common IPs
                device_results = scan_common_ports(f'{base_ip}{i}')
                if device_results:
                    results.append({
                        'ip': f'{base_ip}{i}',
                        'ports': device_results
                    })
            
            with security_scan_lock:
                security_scan_results['port_scan']['results'] = results
                security_scan_results['port_scan']['status'] = 'complete'
                security_scan_results['port_scan']['last_scan'] = datetime.now().isoformat()
            
            # Send notification and create alert if high-risk ports found
            high_risk_ports = [
                (device.get('ip'), port)
                for device in results
                for port in device.get('ports', [])
                if port.get('risk') == 'high'
            ]
            if high_risk_ports:
                # Create alert for each high-risk port found
                for ip, port in high_risk_ports:
                    create_alert(
                        'high_risk',
                        f"High-risk port {port.get('port')} ({port.get('service', 'Unknown')}) open on {ip}",
                        'danger'
                    )
                if admin_user_id:
                    notify_security_alert(
                        admin_user_id,
                        'high_risk',
                        'High-risk open ports detected on your network'
                    )
        
        elif scan_type == 'dns_check':
            results = check_dns_hijacking()
            with security_scan_lock:
                security_scan_results['dns_check']['results'] = results
                security_scan_results['dns_check']['status'] = 'complete'
                security_scan_results['dns_check']['last_scan'] = datetime.now().isoformat()
            
            # Send notification and create alert if DNS hijacking detected
            suspicious_domains = [r for r in results if r.get('status') == 'suspicious']
            if suspicious_domains:
                for domain in suspicious_domains:
                    create_alert(
                        'dns_hijack',
                        f"Possible DNS hijacking detected for {domain.get('domain')}",
                        'danger'
                    )
                if admin_user_id:
                    notify_security_alert(
                        admin_user_id,
                        'dns_hijack',
                        'Possible DNS hijacking detected for some domains'
                    )
        
        elif scan_type == 'open_ports':
            results = scan_local_open_ports()
            with security_scan_lock:
                security_scan_results['open_ports']['results'] = results
                security_scan_results['open_ports']['status'] = 'complete'
                security_scan_results['open_ports']['last_scan'] = datetime.now().isoformat()

            # Create alerts for high-risk local open ports
            high_risk_local = [21, 23, 135, 139, 445, 3306, 3389, 5432]
            for port_info in results:
                port = port_info.get('port')
                if port in high_risk_local:
                    create_alert(
                        'open_port',
                        f"High-risk local port {port} ({port_info.get('service', 'Unknown')}) is open",
                        'danger'
                    )

    except Exception as e:
        with security_scan_lock:
            security_scan_results[scan_type]['status'] = 'error'
            security_scan_results[scan_type]['error'] = str(e)

# ============================================================
# AUTHENTICATION DECORATORS
# ============================================================

def login_required(f):
    """Require user to be logged in"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Require user to be admin"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        if session.get('user_role') != 'admin':
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ============================================================
# PAGE ROUTES
# ============================================================

@app.route('/')
def index():
    if 'user_email' in session:
        role = session.get('user_role', 'user')
        if role == 'admin':
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    if 'user_email' in session:
        role = session.get('user_role', 'user')
        if role == 'admin':
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('login.html')

@app.route('/signup')
def signup():
    if 'user_email' in session:
        role = session.get('user_role', 'user')
        if role == 'admin':
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('signup.html')

@app.route('/2fa')
def twofa():
    if 'pending_2fa_email' not in session:
        return redirect(url_for('login'))
    
    # Don't pass the code to template for security
    return render_template('2fa.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user_role=session.get('user_role', 'user'))

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('users/dashboard.html', user_role=session.get('user_role', 'user'))

@app.route('/user/traffic')
@login_required
def user_traffic():
    return render_template('users/traffic.html', user_role=session.get('user_role', 'user'))

@app.route('/user/restrictions')
@login_required
def user_restrictions():
    return render_template('users/restrictions.html', user_role=session.get('user_role', 'user'))

@app.route('/user/requests')
@login_required
def user_requests():
    return render_template('users/requests.html', user_role=session.get('user_role', 'user'))

@app.route('/user/profile')
@login_required
def user_profile():
    return render_template('users/profile.html', user_role=session.get('user_role', 'user'))

@app.route('/traffic')
@login_required
def traffic():
    return render_template('traffic_analysis.html', user_role=session.get('user_role', 'user'))

@app.route('/devices')
@login_required
def devices():
    return render_template('device_settings.html', user_role=session.get('user_role', 'user'))

@app.route('/logs')
@login_required
def logs():
    return render_template('logs_reports.html', user_role=session.get('user_role', 'user'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user_role=session.get('user_role', 'user'))

@app.route('/messages')
@login_required
def messages():
    return render_template('messages.html', user_role=session.get('user_role', 'user'))

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    user_email = session.get('user_email')
    
    # Log logout activity
    if user_id:
        now = datetime.now(timezone.utc).isoformat()
        requests.post(
            f"{FIREBASE_DB_URL}/activity_logs.json",
            json={
                'userId': user_id,
                'userEmail': user_email,
                'action': 'logout',
                'details': f'User logged out from web dashboard',
                'timestamp': now
            }
        )
        
        # Mark user as offline
        requests.patch(
            f"{FIREBASE_DB_URL}/users/{user_id}.json",
            json={'online': False}
        )
        
        # Remove from online devices (mark all user's devices as offline)
        resp = requests.get(f"{FIREBASE_DB_URL}/online_devices.json")
        devices = resp.json() or {}
        for device_id, device_data in devices.items():
            if isinstance(device_data, dict) and device_data.get('userId') == user_id:
                requests.patch(
                    f"{FIREBASE_DB_URL}/online_devices/{device_id}.json",
                    json={'status': 'offline', 'lastSeen': now}
                )
    
    session.clear()
    return redirect(url_for('login'))

# ============================================================
# AUTHENTICATION API
# ============================================================

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    """Register a new user and create profile in Firebase DB.

    The Firebase Authentication account is created on the client side.
    This endpoint only creates the corresponding user record in the
    Realtime Database with a default "user" role.
    """
    data = request.json or {}
    email = data.get('email')
    user_id = data.get('userId')
    display_name = data.get('displayName')

    if not email or not user_id:
        return jsonify({'success': False, 'message': 'Missing email or user ID'}), 400

    # Check if user already exists
    existing_resp = requests.get(f"{FIREBASE_DB_URL}/users/{user_id}.json")
    if existing_resp.json() is not None:
        return jsonify({'success': False, 'message': 'User already exists'}), 409

    user_record = {
        'email': email,
        'role': 'user',
        'displayName': display_name,
        'createdAt': datetime.now(timezone.utc).isoformat(),
        'online': False,
        'lastLogin': None
    }

    requests.put(f"{FIREBASE_DB_URL}/users/{user_id}.json", json=user_record)

    return jsonify({'success': True, 'message': 'User registered successfully'})

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Handle login and trigger 2FA"""
    data = request.json
    email = data.get('email')
    user_id = data.get('userId')
    
    if not email or not user_id:
        return jsonify({'success': False, 'message': 'Missing credentials'}), 400
    
    # Get user from Firebase Database
    resp = requests.get(f"{FIREBASE_DB_URL}/users/{user_id}.json")
    user_data = resp.json()
    
    # If user doesn't exist in database but exists in Firebase Auth, create them
    if not user_data:
        # Auto-create user in database
        now = datetime.now(timezone.utc).isoformat()
        user_data = {
            'email': email,
            'role': 'user',  # Default role
            'createdAt': now,
            'online': False,
            'telegram_chat_id': None
        }
        requests.put(f"{FIREBASE_DB_URL}/users/{user_id}.json", json=user_data)
        print(f"Auto-created user in database: {email}")
    
    # Verify email matches
    if user_data.get('email') != email:
        # Send notification about failed login attempt
        ip_address = request.remote_addr
        notify_failed_login(email, ip_address)

        # Create alert in dashboard
        create_alert(
            'login_failed',
            f"Failed login attempt for {email} from IP: {ip_address}",
            'danger'
        )

        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Generate 2FA code
    code = str(random.randint(100000, 999999))
    
    # Store pending 2FA
    session['pending_2fa_email'] = email
    session['pending_2fa_user_id'] = user_id
    session['pending_2fa_code'] = code
    session['pending_2fa_role'] = user_data.get('role', 'user')
    
    # Send 2FA code via email (required)
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({
            'success': False, 
            'message': 'Email configuration not set. Please contact administrator.'
        }), 500
    
    try:
        send_2fa_email(email, code)
    except Exception as e:
        error_str = str(e)
        print(f"Email error: {e}")
        
        # Provide helpful error messages
        if 'Application-specific password required' in error_str or '534' in error_str:
            message = 'Gmail App Password required. Please configure a Google App Password in .env file. See 2FA_EMAIL_SETUP.md for instructions.'
        elif 'authentication failed' in error_str.lower():
            message = 'Email authentication failed. Please check EMAIL_USER and EMAIL_PASS in .env file.'
        else:
            message = f'Failed to send verification code: {error_str}'
        
        return jsonify({
            'success': False, 
            'message': message
        }), 500
    
    return jsonify({
        'success': True, 
        'message': 'Verification code sent to your email'
    })

@app.route('/api/auth/verify-2fa', methods=['POST'])
def api_verify_2fa():
    """Verify 2FA code"""
    global admin_user_id
    
    data = request.json
    code = data.get('code')
    
    if not session.get('pending_2fa_code'):
        return jsonify({'success': False, 'message': 'No pending verification'}), 400
    
    if code != session.get('pending_2fa_code'):
        return jsonify({'success': False, 'message': 'Invalid code'}), 400
    
    # Complete login
    session['user_email'] = session.pop('pending_2fa_email')
    session['user_id'] = session.pop('pending_2fa_user_id')
    session['user_role'] = session.pop('pending_2fa_role')
    session.pop('pending_2fa_code', None)
    
    user_id = session['user_id']
    user_email = session['user_email']
    user_role = session['user_role']
    now = datetime.now(timezone.utc).isoformat()
    
    # Store admin user ID for notifications (if admin)
    global admin_user_id
    if user_role == 'admin':
        admin_user_id = user_id
        print(f"✓ Admin logged in - Telegram notifications enabled for user: {user_id}")
    
    # Update user last login
    requests.patch(
        f"{FIREBASE_DB_URL}/users/{user_id}.json",
        json={'lastLogin': now, 'online': True}
    )
    
    # Add to online devices
    device_id = f"web_{user_id}_{int(datetime.now().timestamp())}"
    requests.put(
        f"{FIREBASE_DB_URL}/online_devices/{device_id}.json",
        json={
            'userId': user_id,
            'email': user_email,
            'deviceId': device_id,
            'lastSeen': now,
            'status': 'online',
            'loginTime': now
        }
    )
    
    # Log login activity
    requests.post(
        f"{FIREBASE_DB_URL}/activity_logs.json",
        json={
            'userId': user_id,
            'userEmail': user_email,
            'action': 'login',
            'details': f'User logged in from web dashboard',
            'timestamp': now
        }
    )
    
    # Redirect based on role
    role = session.get('user_role', 'user')
    redirect_url = '/dashboard' if role == 'admin' else '/user/dashboard'
    
    return jsonify({'success': True, 'redirect': redirect_url})

@app.route('/api/auth/session')
def api_session():
    """Get current session info"""
    if 'user_email' not in session:
        return jsonify({'loggedIn': False})
    
    return jsonify({
        'loggedIn': True,
        'email': session.get('user_email'),
        'userId': session.get('user_id'),
        'role': session.get('user_role')
    })

@app.route('/api/auth/heartbeat', methods=['POST'])
@login_required
def api_heartbeat():
    """Update user's online status - called periodically by client"""
    user_id = session.get('user_id')
    user_email = session.get('user_email')
    now = datetime.now(timezone.utc).isoformat()
    
    # Update all user's devices
    resp = requests.get(f"{FIREBASE_DB_URL}/online_devices.json")
    devices = resp.json() or {}
    
    device_found = False
    for device_id, device_data in devices.items():
        if isinstance(device_data, dict) and device_data.get('userId') == user_id:
            requests.patch(
                f"{FIREBASE_DB_URL}/online_devices/{device_id}.json",
                json={'lastSeen': now, 'status': 'online'}
            )
            device_found = True
    
    # If no device found, create one
    if not device_found:
        device_id = f"web_{user_id}_{int(datetime.now().timestamp())}"
        requests.put(
            f"{FIREBASE_DB_URL}/online_devices/{device_id}.json",
            json={
                'userId': user_id,
                'email': user_email,
                'deviceId': device_id,
                'lastSeen': now,
                'status': 'online',
                'loginTime': now
            }
        )
    
    return jsonify({'success': True})

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def api_change_password():
    """Change user password - redirects to Firebase password reset"""
    return jsonify({
        'success': False, 
        'message': 'To change your password, please use the "Forgot Password" link on the login page. You will receive a password reset email from Firebase.'
    }), 200

def send_2fa_email(to_email, code):
    """Send 2FA code via email"""
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = to_email
    msg['Subject'] = 'AuthTrack - Verification Code'
    
    body = f"""
    Your verification code is: {code}
    
    This code expires in 5 minutes.
    If you didn't request this, please ignore this email.
    """
    msg.attach(MIMEText(body, 'plain'))
    
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_USER, EMAIL_PASS)
    server.send_message(msg)
    server.quit()

# ============================================================
# USER MANAGEMENT API
# ============================================================

@app.route('/api/users')
@login_required
def api_get_users():
    """Get all users (admin only for full list)"""
    resp = requests.get(f"{FIREBASE_DB_URL}/users.json")
    users_data = resp.json() or {}
    
    users = []
    for uid, data in users_data.items():
        user = {
            'id': uid,
            'email': data.get('email'),
            'role': data.get('role', 'user'),
            'online': data.get('online', False),
            'lastLogin': data.get('lastLogin')
        }
        # Only admin can see all users, regular users only see themselves
        if session.get('user_role') == 'admin' or uid == session.get('user_id'):
            users.append(user)
    
    return jsonify(users)

@app.route('/api/users/<user_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def api_user(user_id):
    """Get, update, or delete user"""
    # Users can only modify their own profile, admin can modify anyone
    if session.get('user_role') != 'admin' and user_id != session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    if request.method == 'GET':
        resp = requests.get(f"{FIREBASE_DB_URL}/users/{user_id}.json")
        return jsonify(resp.json())
    
    elif request.method == 'PUT':
        data = request.json
        # Only admin can change role
        if 'role' in data and session.get('user_role') != 'admin':
            del data['role']
        
        requests.patch(f"{FIREBASE_DB_URL}/users/{user_id}.json", json=data)
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        if session.get('user_role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        requests.delete(f"{FIREBASE_DB_URL}/users/{user_id}.json")
        return jsonify({'success': True})

@app.route('/api/users/<user_id>/password', methods=['PUT'])
@login_required
def api_update_user_password(user_id):
    """Change password - handled by Firebase Auth on frontend"""
    # This is a placeholder - actual password change happens via Firebase Auth
    return jsonify({'success': True, 'message': 'Use Firebase Auth to change password'})

# ============================================================
# DEVICE MANAGEMENT API
# ============================================================

@app.route('/api/devices')
@login_required
def api_get_devices():
    """Get all devices"""
    resp = requests.get(f"{FIREBASE_DB_URL}/devices.json")
    devices_data = resp.json() or {}
    
    devices = []
    for did, data in devices_data.items():
        data['id'] = did
        devices.append(data)
    
    return jsonify(devices)

@app.route('/api/devices', methods=['POST'])
@admin_required
def api_add_device():
    """Add a new device"""
    data = request.json
    data['addedAt'] = datetime.now(timezone.utc).isoformat()
    data['addedBy'] = session.get('user_email')
    
    resp = requests.post(f"{FIREBASE_DB_URL}/devices.json", json=data)
    result = resp.json()
    
    return jsonify({'success': True, 'id': result.get('name')})

@app.route('/api/devices/<device_id>', methods=['PUT', 'DELETE'])
@admin_required
def api_device(device_id):
    """Update or delete device"""
    if request.method == 'PUT':
        data = request.json
        requests.patch(f"{FIREBASE_DB_URL}/devices/{device_id}.json", json=data)
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        requests.delete(f"{FIREBASE_DB_URL}/devices/{device_id}.json")
        return jsonify({'success': True})

@app.route('/api/devices/<device_id>/block', methods=['POST'])
@admin_required
def api_block_device(device_id):
    """Block/unblock a device"""
    data = request.json
    blocked = data.get('blocked', True)
    
    requests.patch(
        f"{FIREBASE_DB_URL}/devices/{device_id}.json",
        json={'blocked': blocked, 'blockedAt': datetime.now(timezone.utc).isoformat() if blocked else None}
    )
    
    # Log alert
    if blocked:
        create_alert('device_blocked', f"Device {device_id} was blocked", 'warning')
    
    return jsonify({'success': True})

# ============================================================
# TIME RESTRICTIONS API
# ============================================================

@app.route('/api/restrictions')
@login_required
def api_get_restrictions():
    """Get time-based restrictions"""
    user_id = request.args.get('userId', session.get('user_id'))
    
    # Users can only see their own restrictions unless admin
    if session.get('user_role') != 'admin' and user_id != session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    resp = requests.get(f"{FIREBASE_DB_URL}/restrictions/{user_id}.json")
    return jsonify(resp.json() or {})

@app.route('/api/restrictions/<user_id>', methods=['PUT'])
@admin_required
def api_set_restrictions(user_id):
    """Set time-based restrictions for a user"""
    data = request.json
    """
    Expected format:
    {
        "internet": {
            "enabled": true,
            "schedule": [
                {"day": "weekday", "startTime": "09:00", "endTime": "17:00", "allowed": true},
                {"day": "weekend", "startTime": "00:00", "endTime": "23:59", "allowed": false}
            ]
        },
        "websites": {
            "facebook.com": {
                "blocked": true,
                "schedule": [{"day": "all", "startTime": "09:00", "endTime": "17:00"}]
            }
        }
    }
    """
    requests.put(f"{FIREBASE_DB_URL}/restrictions/{user_id}.json", json=data)
    return jsonify({'success': True})

# ============================================================
# URL/DOMAIN BLOCKING API
# ============================================================

@app.route('/api/blocked-sites')
@login_required
def api_get_blocked_sites():
    """Get blocked sites for a user"""
    user_id = request.args.get('userId', session.get('user_id'))
    
    resp = requests.get(f"{FIREBASE_DB_URL}/blocked_sites/{user_id}.json")
    return jsonify(resp.json() or [])

@app.route('/api/blocked-sites/<user_id>', methods=['PUT'])
@admin_required
def api_set_blocked_sites(user_id):
    """Set blocked sites for a user"""
    data = request.json  # List of domains
    requests.put(f"{FIREBASE_DB_URL}/blocked_sites/{user_id}.json", json=data)
    return jsonify({'success': True})

@app.route('/api/global-blocked-sites')
@login_required
def api_get_global_blocked():
    """Get globally blocked sites"""
    resp = requests.get(f"{FIREBASE_DB_URL}/global_blocked_sites.json")
    return jsonify(resp.json() or [])

@app.route('/api/global-blocked-sites', methods=['PUT'])
@admin_required
def api_set_global_blocked():
    """Set globally blocked sites"""
    data = request.json
    requests.put(f"{FIREBASE_DB_URL}/global_blocked_sites.json", json=data)
    return jsonify({'success': True})

# ============================================================
# TRAFFIC & ACTIVITY API (from Chrome Extension)
# ============================================================

@app.route('/api/activity', methods=['POST'])
def api_log_activity():
    """Log user activity from Chrome extension"""
    data = request.json
    
    url = data.get('url', '')
    title = data.get('title', '')
    action = data.get('action', 'visit')
    
    # Create readable details
    details = f"{title} - {url}" if title and url else (url or title or 'No details')
    if len(details) > 100:
        details = details[:97] + '...'
    
    activity = {
        'userId': data.get('userId'),
        'userEmail': data.get('userEmail'),
        'url': url,
        'title': title,
        'action': action,
        'details': details,
        'timestamp': data.get('timestamp', datetime.now(timezone.utc).isoformat())
    }
    
    # Store in Firebase
    requests.post(f"{FIREBASE_DB_URL}/activity_logs.json", json=activity)
    
    # Check for suspicious activity
    check_suspicious_activity(activity)
    
    return jsonify({'success': True})

@app.route('/api/activity')
@login_required
def api_get_activity():
    """Get activity logs"""
    user_id = request.args.get('userId')
    limit = int(request.args.get('limit', 100))
    
    # Fetch all activity logs (Firebase orderBy requires indexing, so we'll sort in Python)
    resp = requests.get(f"{FIREBASE_DB_URL}/activity_logs.json")
    data = resp.json() or {}
    
    activities = []
    for key, val in data.items():
        # Skip malformed entries
        if not isinstance(val, dict):
            continue
        # Filter by user if specified and not admin
        if user_id and val.get('userId') != user_id:
            continue
        if session.get('user_role') != 'admin' and val.get('userId') != session.get('user_id'):
            continue
        val['id'] = key
        activities.append(val)
    
    # Sort by timestamp desc
    activities.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify(activities[:limit])

@app.route('/api/traffic/realtime')
@login_required
def api_realtime_traffic():
    """Get real-time traffic data"""
    # Get recent activity
    resp = requests.get(f"{FIREBASE_DB_URL}/activity_logs.json")
    data = resp.json() or {}
    
    traffic = []
    for key, val in data.items():
        if not isinstance(val, dict):
            continue
        traffic.append({
            'user': val.get('userEmail', 'Unknown'),
            'url': val.get('url'),
            'action': val.get('action'),
            'timestamp': val.get('timestamp')
        })
    
    # Sort and return last 50
    traffic.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify(traffic[:50])

# ============================================================
# EXTENSION API (for Chrome Extension)
# ============================================================

@app.route('/api/extension/verify', methods=['POST'])
def api_extension_verify():
    """Verify user for Chrome extension"""
    data = request.json
    email = data.get('email')
    user_id = data.get('userId')
    
    resp = requests.get(f"{FIREBASE_DB_URL}/users/{user_id}.json")
    user_data = resp.json()
    
    if not user_data or user_data.get('email') != email:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    return jsonify({'success': True, 'role': user_data.get('role', 'user')})

@app.route('/api/extension/register-device', methods=['POST'])
def api_register_device():
    """Register browser as online device"""
    data = request.json
    user_id = data.get('userId')
    user_email = data.get('userEmail')
    browser = data.get('browser', 'Chrome')
    device_id = data.get('deviceId')  # Unique per browser instance
    
    if not user_id or not device_id:
        return jsonify({'error': 'Missing parameters'}), 400
    
    # Register/update online device
    device_data = {
        'userId': user_id,
        'userEmail': user_email,
        'browser': browser,
        'type': 'browser',
        'status': 'online',
        'lastSeen': datetime.now(timezone.utc).isoformat(),
        'registeredAt': datetime.now(timezone.utc).isoformat()
    }
    
    requests.put(f"{FIREBASE_DB_URL}/online_devices/{device_id}.json", json=device_data)
    return jsonify({'success': True})

@app.route('/api/extension/heartbeat', methods=['POST'])
def api_extension_heartbeat():
    """Update device last seen timestamp"""
    data = request.json
    device_id = data.get('deviceId')
    
    if not device_id:
        return jsonify({'error': 'Missing deviceId'}), 400
    
    # Update last seen
    requests.patch(f"{FIREBASE_DB_URL}/online_devices/{device_id}.json", json={
        'lastSeen': datetime.now(timezone.utc).isoformat(),
        'status': 'online'
    })
    
    return jsonify({'success': True})

@app.route('/api/extension/rules')
def api_extension_rules():
    """Get blocking rules for extension"""
    user_id = request.args.get('userId')
    
    if not user_id:
        return jsonify({'blocked_sites': [], 'restrictions': {}})
    
    # Get user-specific blocked sites
    resp1 = requests.get(f"{FIREBASE_DB_URL}/blocked_sites/{user_id}.json")
    user_blocked = resp1.json() or []
    
    # Get global blocked sites
    resp2 = requests.get(f"{FIREBASE_DB_URL}/global_blocked_sites.json")
    global_blocked = resp2.json() or []
    
    # Get restrictions
    resp3 = requests.get(f"{FIREBASE_DB_URL}/restrictions/{user_id}.json")
    restrictions = resp3.json() or {}
    
    return jsonify({
        'blocked_sites': list(set(user_blocked + global_blocked)),
        'restrictions': restrictions
    })

@app.route('/api/online-devices')
@login_required
def api_get_online_devices():
    """Get online devices (browsers with active sessions)"""
    resp = requests.get(f"{FIREBASE_DB_URL}/online_devices.json")
    devices = resp.json() or {}
    
    now = datetime.now(timezone.utc)
    online_devices = {}
    
    for device_id, data in devices.items():
        if not isinstance(data, dict):
            continue
            
        # Check if device is still online (within last 2 minutes)
        last_seen_str = data.get('lastSeen')
        if last_seen_str:
            try:
                last_seen = datetime.fromisoformat(last_seen_str.replace('Z', '+00:00'))
                time_diff = (now - last_seen).total_seconds()
                
                # Mark offline if no heartbeat for 2 minutes
                if time_diff > 120:
                    data['status'] = 'offline'
                    # Update in Firebase
                    requests.patch(f"{FIREBASE_DB_URL}/online_devices/{device_id}.json", json={'status': 'offline'})
                else:
                    data['status'] = 'online'
                    # Only include online devices in response
                    data['deviceId'] = device_id
                    online_devices[device_id] = data
            except:
                data['status'] = 'unknown'
    
    return jsonify(online_devices)

# ============================================================
# MESSAGES / DM API
# ============================================================

@app.route('/api/messages')
@login_required
def api_get_messages():
    """Get messages for user"""
    resp = requests.get(f"{FIREBASE_DB_URL}/messages.json")
    data = resp.json() or {}
    
    messages = []
    for key, val in data.items():
        # Show messages where user is sender or recipient (or admin sees all)
        if session.get('user_role') == 'admin' or \
           val.get('fromUserId') == session.get('user_id') or \
           val.get('toUserId') == session.get('user_id') or \
           val.get('toUserId') == 'admin':
            val['id'] = key
            messages.append(val)
    
    messages.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify(messages)

@app.route('/api/messages', methods=['POST'])
@login_required
def api_send_message():
    """Send a message/request"""
    data = request.json
    
    message = {
        'fromUserId': session.get('user_id'),
        'fromEmail': session.get('user_email'),
        'toUserId': data.get('toUserId', 'admin'),
        'subject': data.get('subject'),
        'content': data.get('content'),
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'read': False,
        'type': data.get('type', 'request')  # request, reply
    }
    
    resp = requests.post(f"{FIREBASE_DB_URL}/messages.json", json=message)
    return jsonify({'success': True, 'id': resp.json().get('name')})

@app.route('/api/messages/<msg_id>', methods=['PUT', 'DELETE'])
@login_required
def api_message(msg_id):
    """Update or delete message"""
    if request.method == 'PUT':
        data = request.json
        requests.patch(f"{FIREBASE_DB_URL}/messages/{msg_id}.json", json=data)
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        requests.delete(f"{FIREBASE_DB_URL}/messages/{msg_id}.json")
        return jsonify({'success': True})

@app.route('/api/messages/unread-count')
@login_required
def api_unread_count():
    """Get unread message count"""
    resp = requests.get(f"{FIREBASE_DB_URL}/messages.json")
    data = resp.json() or {}
    
    count = 0
    for key, val in data.items():
        if not val.get('read'):
            if session.get('user_role') == 'admin' and val.get('toUserId') == 'admin':
                count += 1
            elif val.get('toUserId') == session.get('user_id'):
                count += 1
    
    return jsonify({'count': count})

# ============================================================
# ALERTS API
# ============================================================

@app.route('/api/alerts')
@login_required
def api_get_alerts():
    """Get alerts"""
    try:
        resp = requests.get(f"{FIREBASE_DB_URL}/alerts.json?orderBy=\"timestamp\"&limitToLast=50")
        data = resp.json()

        if not data or not isinstance(data, dict):
            return jsonify([])

        alerts = []
        for key, val in data.items():
            if not isinstance(val, dict):
                continue
            val['id'] = key
            alerts.append(val)

        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return jsonify(alerts)
    except Exception as e:
        print(f"Error fetching alerts: {e}")
        return jsonify([])

@app.route('/api/alerts/test', methods=['POST'])
@login_required
def api_create_test_alerts():
    """Create test alerts to verify system is working"""
    try:
        # Create multiple test alerts with different severities
        test_alerts = [
            {
                'type': 'test_info',
                'message': '✓ Test Alert: Information level - System is working correctly',
                'severity': 'info'
            },
            {
                'type': 'test_warning',
                'message': '⚠️ Test Alert: Warning level - Unusual activity detected',
                'severity': 'warning'
            },
            {
                'type': 'test_danger',
                'message': '🚨 Test Alert: Danger level - Critical security event simulated',
                'severity': 'danger'
            },
            {
                'type': 'ml_test',
                'message': '📊 Test ML Anomaly: Traffic spike of 2500 KB detected (baseline: 150 KB)',
                'severity': 'danger'
            }
        ]
        
        created_count = 0
        for alert_data in test_alerts:
            result = create_alert(alert_data['type'], alert_data['message'], alert_data['severity'])
            if result:
                created_count += 1
        
        return jsonify({
            'success': True,
            'message': f'Created {created_count} test alerts',
            'count': created_count
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def create_alert(alert_type, message, severity='info'):
    """Create a new alert"""
    try:
        alert = {
            'type': alert_type,
            'message': message,
            'severity': severity,  # info, warning, danger
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'read': False
        }
        response = requests.post(f"{FIREBASE_DB_URL}/alerts.json", json=alert, timeout=5)
        if response.status_code in [200, 201]:
            print(f"✓ Alert created: {message[:60]}...")
            return True
        else:
            print(f"✗ Failed to create alert: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Error creating alert: {e}")
        return False

def check_suspicious_activity(activity):
    """Check for suspicious patterns and create alerts"""
    # Example: Too many blocked attempts
    url = activity.get('url', '')
    action = activity.get('action', '')
    
    if action == 'blocked':
        create_alert(
            'blocked_access',
            f"User {activity.get('userEmail')} attempted to access blocked site: {url}",
            'warning'
        )

# ============================================================
# STATS API
# ============================================================

@app.route('/api/stats')
@login_required
def api_stats():
    """Get dashboard statistics"""
    # Get users count
    users_resp = requests.get(f"{FIREBASE_DB_URL}/users.json")
    users_data = users_resp.json() or {}
    
    # Count online users from online_devices (with heartbeat check)
    online_devices_resp = requests.get(f"{FIREBASE_DB_URL}/online_devices.json")
    online_devices_data = online_devices_resp.json() or {}
    
    now = datetime.now(timezone.utc)
    actually_online_users = set()
    
    for device_id, device_data in online_devices_data.items():
        if not isinstance(device_data, dict):
            continue
        last_seen_str = device_data.get('lastSeen')
        user_id = device_data.get('userId')
        
        if last_seen_str and user_id:
            try:
                last_seen = datetime.fromisoformat(last_seen_str.replace('Z', '+00:00'))
                time_diff = (now - last_seen).total_seconds()
                
                # User is online if heartbeat within 2 minutes
                if time_diff <= 120:
                    actually_online_users.add(user_id)
            except:
                pass
    
    online_users = len(actually_online_users)
    
    # Get devices count
    devices_resp = requests.get(f"{FIREBASE_DB_URL}/devices.json")
    devices_data = devices_resp.json() or {}
    blocked_devices = sum(1 for d in devices_data.values() if d.get('blocked'))
    
    # Get alerts count
    alerts_resp = requests.get(f"{FIREBASE_DB_URL}/alerts.json")
    alerts_data = alerts_resp.json() or {}
    unread_alerts = sum(1 for a in alerts_data.values() if not a.get('read'))
    
    # Get activity count (recent activities - last 24 hours)
    activity_resp = requests.get(f"{FIREBASE_DB_URL}/activity_logs.json?orderBy=\"timestamp\"&limitToLast=100")
    activity_data = activity_resp.json() or {}
    
    # Count activities from last 24 hours
    now_utc = datetime.now(timezone.utc)
    cutoff_time = now_utc - timedelta(hours=24)
    
    recent_activity = 0
    for activity in activity_data.values():
        if isinstance(activity, dict):
            timestamp_str = activity.get('timestamp', '')
            if timestamp_str:
                try:
                    activity_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    if activity_time >= cutoff_time:
                        recent_activity += 1
                except:
                    pass
    
    return jsonify({
        'totalUsers': len(users_data),
        'onlineUsers': online_users,
        'totalDevices': len(devices_data),
        'blockedDevices': blocked_devices,
        'unreadAlerts': unread_alerts,
        'todayActivity': recent_activity  # Last 24 hours instead of just today
    })

@app.route('/api/active-users')
@login_required
def api_active_users():
    """Get list of active/online users"""
    # Get all users
    resp = requests.get(f"{FIREBASE_DB_URL}/users.json")
    users_data = resp.json() or {}
    
    # Get online devices to check actual heartbeat status
    devices_resp = requests.get(f"{FIREBASE_DB_URL}/online_devices.json")
    devices = devices_resp.json() or {}
    
    now = datetime.now(timezone.utc)
    actually_online_users = set()
    
    # Check which users have online devices (heartbeat within 2 minutes)
    for device_id, device_data in devices.items():
        if not isinstance(device_data, dict):
            continue
            
        last_seen_str = device_data.get('lastSeen')
        user_id = device_data.get('userId')
        
        if last_seen_str and user_id:
            try:
                last_seen = datetime.fromisoformat(last_seen_str.replace('Z', '+00:00'))
                time_diff = (now - last_seen).total_seconds()
                
                # User is online if heartbeat within 2 minutes
                if time_diff <= 120:
                    actually_online_users.add(user_id)
            except:
                pass
    
    # Build active users list and update their online status
    active = []
    for uid, data in users_data.items():
        is_actually_online = uid in actually_online_users
        
        # Update user's online status if it's wrong
        if data.get('online') != is_actually_online:
            requests.patch(
                f"{FIREBASE_DB_URL}/users/{uid}.json",
                json={'online': is_actually_online}
            )
        
        if is_actually_online:
            active.append({
                'id': uid,
                'email': data.get('email'),
                'lastLogin': data.get('lastLogin')
            })
    
    return jsonify(active)

# ============================================================
# SNIFFER & NETWORK MONITORING API
# ============================================================

@app.route('/api/sniffer/start', methods=['POST'])
@admin_required
def api_start_sniffer():
    """Start the packet sniffer"""
    global sniffer_active, sniffer_thread
    
    if not sniffer_active:
        sniffer_active = True
        sniffer_thread = threading.Thread(target=sniffer_worker, daemon=True)
        sniffer_thread.start()
        return jsonify({'success': True, 'message': 'Packet sniffer started'})
    
    return jsonify({'success': True, 'message': 'Sniffer already running'})

@app.route('/api/sniffer/stop', methods=['POST'])
@admin_required
def api_stop_sniffer():
    """Stop the packet sniffer"""
    global sniffer_active
    sniffer_active = False
    return jsonify({'success': True, 'message': 'Packet sniffer stopped'})

@app.route('/api/sniffer/status')
@admin_required
def api_sniffer_status():
    """Get sniffer status - Real mode only"""
    return jsonify({
        'active': sniffer_active,
        'scapy_available': SCAPY_AVAILABLE,
        'mode': 'real'
    })

@app.route('/api/sniffer/logs')
@admin_required
def api_sniffer_logs():
    """Get captured packets"""
    with traffic_lock:
        packets = list(captured_packets[-50:])  # Last 50 packets
    
    with protocol_lock:
        stats = dict(protocol_stats)
    
    # Find top protocol
    top_protocol = max(stats, key=stats.get) if stats else '-'
    
    return jsonify({
        'packets': packets,
        'total_captured': len(captured_packets),
        'protocol_stats': stats,
        'top_protocol': top_protocol
    })

@app.route('/api/network/packets')
@login_required
def api_network_packets():
    """Get captured packets (accessible by all users)"""
    global captured_packets
    
    with traffic_lock:
        # Return last 100 packets
        packets = list(captured_packets[-100:])
    
    return jsonify({
        'packets': packets,
        'total': len(captured_packets)
    })

@app.route('/api/system/stats')
@login_required
def api_system_stats():
    """Get system CPU, memory, disk stats - Real mode only"""
    if not PSUTIL_AVAILABLE:
        return jsonify({
            'error': 'psutil not installed',
            'cpu': 0,
            'memory': 0,
            'disk': 0
        })
    
    return jsonify({
        'cpu': psutil.cpu_percent(interval=0.1),
        'memory': psutil.virtual_memory().percent,
        'disk': psutil.disk_usage('/').percent
    })

@app.route('/api/network/stats')
@login_required
def api_network_stats():
    """Get network statistics (packets, bytes, connections)"""
    global captured_packets, cumulative_traffic
    
    with traffic_lock:
        total_packets = len(captured_packets)
        
        # Count unique connections (unique src-dst pairs)
        connections = set()
        for p in captured_packets:
            src = p.get('source', '')
            dst = p.get('destination', '')
            if src and dst:
                connections.add(f"{src}-{dst}")
        
        active_connections = len(connections)
    
    return jsonify({
        'total_packets': total_packets,
        'total_bytes': cumulative_traffic['total'],
        'inbound_bytes': cumulative_traffic['inbound'],
        'outbound_bytes': cumulative_traffic['outbound'],
        'active_connections': active_connections
    })

@app.route('/api/activity/logs')
@login_required
def api_activity_logs():
    """Get activity logs formatted for display"""
    try:
        resp = requests.get(f"{FIREBASE_DB_URL}/activity_logs.json")
        data = resp.json() or {}
        
        logs = []
        for key, val in data.items():
            if not isinstance(val, dict):
                continue
            # Filter by user role
            if session.get('user_role') != 'admin' and val.get('userId') != session.get('user_id'):
                continue
            logs.append({
                'id': key,
                'action': val.get('action', 'unknown'),
                'details': val.get('details', ''),
                'timestamp': val.get('timestamp', ''),
                'userEmail': val.get('userEmail', '')
            })
        
        # Sort by timestamp desc
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return jsonify({'logs': logs[:50]})
    except Exception as e:
        return jsonify({'logs': [], 'error': str(e)})

@app.route('/api/network/traffic')
@admin_required
def api_network_traffic():
    """Get network traffic data for charts"""
    global traffic_history, current_traffic
    
    with traffic_lock:
        # Update history
        now = datetime.now().strftime('%H:%M:%S')
        traffic_history['labels'].append(now)
        traffic_history['inbound'].append(current_traffic['inbound'] / 1024)  # KB
        traffic_history['outbound'].append(current_traffic['outbound'] / 1024)  # KB
        
        # Keep last 30 points
        if len(traffic_history['labels']) > 30:
            traffic_history['labels'].pop(0)
            traffic_history['inbound'].pop(0)
            traffic_history['outbound'].pop(0)
        
        # Reset current
        current_traffic = {'inbound': 0, 'outbound': 0}
    
    return jsonify(traffic_history)

def get_mac_vendor(mac):
    """Get device manufacturer from MAC address OUI"""
    if not mac or len(mac) < 8:
        return None
    
    # Extract OUI (first 3 octets)
    oui = mac[:8].upper().replace(':', '').replace('-', '')[:6]
    
    # Common OUI to vendor mapping
    vendors = {
        '000000': 'Xerox',
        '00005E': 'IANA',
        '0000C0': 'Western Digital',
        '001122': 'CIMSYS',
        '001B63': 'Apple',
        '001C42': 'Parallels',
        '00224D': 'Cisco Valet',
        '0050F2': 'Microsoft',
        '005056': 'VMware',
        '00C0FF': 'Intel',
        '080027': 'VirtualBox',
        '0C8BFD': 'Apple',
        '101122': 'Apple',
        '14109F': 'Apple',
        '1C91': 'Apple',
        '204E7F': 'Apple',
        '287F12': 'Apple',
        '28E02C': 'Apple',
        '2CF0A2': 'Apple',
        '34AB37': 'Apple',
        '3C0754': 'Apple',
        '40A6D9': 'Apple',
        '48A195': 'Apple',
        '50EDD2': 'Apple',
        '5855CA': 'Apple',
        '605A6D': 'Apple',
        '647033': 'Apple',
        '68A86D': 'Apple',
        '6C4008': 'Apple',
        '6C709F': 'Apple',
        '78A3E4': 'Apple',
        '7CF05F': 'Apple',
        '848506': 'Apple',
        '8866': 'Apple',
        '8C8590': 'Apple',
        '90B931': 'Apple',
        '9CE063': 'Apple',
        'A886DD': 'Apple',
        'B853AC': 'Apple',
        'C42C03': 'Apple',
        'C82A14': 'Apple',
        'D023DB': 'Apple',
        'D4909': 'Apple',
        'E0B52D': 'Apple',
        'E4CE8F': 'Apple',
        'E88D28': 'Apple',
        'F0DBE2': 'Apple',
        'F4F951': 'Apple',
        'F81EDF': 'Apple',
        '000C29': 'VMware',
        '0050BA': 'D-Link',
        '001D7E': 'Cisco',
        '0019E3': 'D-Link',
        '001B2F': 'Belkin',
        '001E58': 'D-Link',
        '002191': 'Belkin',
        '002275': 'D-Link',
        '002419': 'TP-Link',
        '00E04C': 'Realtek',
        '38C986': 'TP-Link',
        '506313': 'TP-Link',
        '5C5981': 'TP-Link',
        '74DA38': 'TP-Link',
        '98DE': 'TP-Link',
        'A42BB0': 'TP-Link',
        'B0487A': 'TP-Link',
        'C46E1F': 'TP-Link',
        'E894F6': 'TP-Link',
        'F4F26D': 'TP-Link',
        '001E2A': 'Cisco',
        '001EF7': 'Samsung',
        '4C0B6': 'Intel',
        '2C4D54': 'Samsung',
        '342387': 'Samsung',
        '5C0A5B': 'Samsung',
        '685D43': 'Samsung',
        '786A89': 'Samsung',
        '88329B': 'Samsung',
        'A4F933': 'Samsung',
        'C8D7B0': 'Samsung',
        'E8E5D6': 'Samsung',
        '48F17F': 'Xiaomi',
        '4C497D': 'Xiaomi',
        '74235': 'Xiaomi',
        'A4DA22': 'Xiaomi',
        'F8A45F': 'Xiaomi',
    }
    
    return vendors.get(oui[:6])

def detect_device_type(hostname, ip, mac=None):
    """Detect device type based on hostname, IP, and MAC"""
    hostname_lower = hostname.lower()
    
    # Get manufacturer from MAC if available
    vendor = get_mac_vendor(mac) if mac else None
    
    # Apple devices
    if vendor == 'Apple' or any(x in hostname_lower for x in ['iphone', 'ipad', 'macbook', 'imac', 'mac-']):
        if 'iphone' in hostname_lower or 'ipad' in hostname_lower:
            return {'type': 'mobile', 'icon': 'fa-mobile-screen-button', 'label': f'iPhone/iPad', 'vendor': 'Apple'}
        elif 'macbook' in hostname_lower:
            return {'type': 'laptop', 'icon': 'fa-laptop', 'label': 'MacBook', 'vendor': 'Apple'}
        else:
            return {'type': 'desktop', 'icon': 'fa-desktop', 'label': 'Mac', 'vendor': 'Apple'}
    
    # Samsung devices
    if vendor == 'Samsung' or 'samsung' in hostname_lower:
        return {'type': 'mobile', 'icon': 'fa-mobile-screen-button', 'label': 'Samsung Phone', 'vendor': 'Samsung'}
    
    # Xiaomi devices  
    if vendor == 'Xiaomi' or 'xiaomi' in hostname_lower or 'redmi' in hostname_lower:
        return {'type': 'mobile', 'icon': 'fa-mobile-screen-button', 'label': 'Xiaomi Phone', 'vendor': 'Xiaomi'}
    
    # TP-Link devices (routers/access points)
    if vendor == 'TP-Link' or 'tp-link' in hostname_lower or 'tplink' in hostname_lower:
        return {'type': 'router', 'icon': 'fa-wifi', 'label': 'TP-Link Router', 'vendor': 'TP-Link'}
    
    # D-Link devices
    if vendor == 'D-Link' or 'd-link' in hostname_lower:
        return {'type': 'router', 'icon': 'fa-wifi', 'label': 'D-Link Device', 'vendor': 'D-Link'}
    
    # Router detection
    if ip.endswith('.1') or 'router' in hostname_lower or 'gateway' in hostname_lower:
        return {'type': 'router', 'icon': 'fa-router', 'label': 'Router', 'vendor': vendor}
    
    # Desktop/PC detection
    if 'desktop' in hostname_lower or 'pc-' in hostname_lower or 'workstation' in hostname_lower:
        return {'type': 'desktop', 'icon': 'fa-desktop', 'label': 'Desktop PC', 'vendor': vendor}
    
    # Laptop detection
    if 'laptop' in hostname_lower or 'notebook' in hostname_lower:
        return {'type': 'laptop', 'icon': 'fa-laptop', 'label': 'Laptop', 'vendor': vendor}
    
    # Mobile detection
    if any(x in hostname_lower for x in ['android', 'mobile', 'phone', 'huawei', 'oppo', 'vivo']):
        return {'type': 'mobile', 'icon': 'fa-mobile-screen-button', 'label': 'Mobile Phone', 'vendor': vendor}
    
    # Smart TV detection
    if any(x in hostname_lower for x in ['tv', 'roku', 'chromecast', 'firestick', 'appletv']):
        return {'type': 'tv', 'icon': 'fa-tv', 'label': 'Smart TV', 'vendor': vendor}
    
    # Printer detection
    if 'printer' in hostname_lower or 'print' in hostname_lower:
        return {'type': 'printer', 'icon': 'fa-print', 'label': 'Printer', 'vendor': vendor}
    
    # Server detection
    if 'server' in hostname_lower or 'srv' in hostname_lower:
        return {'type': 'server', 'icon': 'fa-server', 'label': 'Server', 'vendor': vendor}
    
    # IoT/Smart Home detection
    if any(x in hostname_lower for x in ['nest', 'alexa', 'echo', 'smart', 'iot', 'camera', 'sensor']):
        return {'type': 'iot', 'icon': 'fa-house-signal', 'label': 'IoT Device', 'vendor': vendor}
    
    # Quick port scan for service detection
    try:
        # Check common ports to determine device type
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        
        # Check SSH (22) - likely server or Linux device
        if sock.connect_ex((ip, 22)) == 0:
            sock.close()
            return {'type': 'server', 'icon': 'fa-server', 'label': 'Linux/Server', 'vendor': vendor}
        sock.close()
        
        # Check RDP (3389) - Windows desktop
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        if sock.connect_ex((ip, 3389)) == 0:
            sock.close()
            return {'type': 'desktop', 'icon': 'fa-desktop', 'label': 'Windows PC', 'vendor': vendor}
        sock.close()
    except:
        pass
    
    # Default to generic computer with vendor if known
    label = f'{vendor} Device' if vendor else 'Computer'
    return {'type': 'computer', 'icon': 'fa-laptop', 'label': label, 'vendor': vendor}

@app.route('/api/network/devices')
@admin_required
def api_network_devices():
    """Get discovered network devices with type detection"""
    devices = []
    now = datetime.now()
    stale_threshold = 300  # 5 minutes in seconds

    # Create a thread-safe copy to avoid "Set changed size during iteration" error
    device_ips = list(known_devices)

    # Auto-cleanup: remove stale devices
    for ip in device_ips:
        last_seen = device_last_seen.get(ip)
        if last_seen:
            age = (now - last_seen).total_seconds()
            if age > stale_threshold:
                # Remove stale device
                known_devices.discard(ip)
                device_last_seen.pop(ip, None)
                device_mac_mapping.pop(ip, None)
                device_traffic_stats.pop(ip, None)
                continue

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = f"Device-{ip.replace('.', '-')}"

        # Get MAC address if available
        mac = device_mac_mapping.get(ip)

        # Detect device type with MAC for better accuracy
        device_info = detect_device_type(hostname, ip, mac)

        # Determine status based on last seen
        last_seen = device_last_seen.get(ip)
        if last_seen:
            age = (now - last_seen).total_seconds()
            status = 'Online' if age < 60 else 'Idle'
        else:
            status = 'Unknown'

        devices.append({
            'ip': ip,
            'hostname': hostname,
            'status': status,
            'traffic': device_traffic_stats.get(ip, 0),
            'type': device_info['type'],
            'icon': device_info['icon'],
            'label': device_info['label'],
            'vendor': device_info.get('vendor'),
            'mac': mac
        })

    return jsonify(devices)

@app.route('/api/network/topology')
@admin_required
def api_network_topology():
    """Get network topology data"""
    now = datetime.now()
    stale_threshold = 300  # 5 minutes

    # Build simple topology: Internet -> Router -> Devices
    topology = {
        'nodes': [
            {'id': 'internet', 'label': 'Internet', 'type': 'internet'},
            {'id': 'router', 'label': 'Router', 'type': 'router'}
        ],
        'links': [
            {'source': 'internet', 'target': 'router'}
        ]
    }

    # Add discovered devices (only active ones)
    for ip in list(known_devices):
        # Check if device is stale
        last_seen = device_last_seen.get(ip)
        if last_seen:
            age = (now - last_seen).total_seconds()
            if age > stale_threshold:
                # Remove stale device
                known_devices.discard(ip)
                device_last_seen.pop(ip, None)
                device_mac_mapping.pop(ip, None)
                device_traffic_stats.pop(ip, None)
                continue

        topology['nodes'].append({
            'id': ip,
            'label': ip,
            'type': 'device'
        })
        topology['links'].append({
            'source': 'router',
            'target': ip
        })

    return jsonify(topology)

@app.route('/api/ml/anomalies')
@login_required
def api_ml_anomalies():
    """Detect anomalies using ML (traffic values stored in KB)"""
    global anomaly_detector

    # Initialize ML on first use
    if not init_ml():
        return jsonify({'available': False, 'anomalies': [], 'message': 'ML not available'})

    with traffic_lock:
        # Need enough points to learn baseline
        if len(traffic_history['inbound']) < 10:
            return jsonify({'available': True, 'anomalies': [], 'message': 'Not enough data (need 10+ samples)'})

        # IMPORTANT: traffic_history['inbound'] is in KB (because /api/network/traffic divides by 1024)
        # Ensure we have valid numeric data
        try:
            # First convert to 1D array for filtering
            data_1d = np.array(traffic_history['inbound'], dtype=float)
            
            # Check for NaN or invalid values
            if np.any(np.isnan(data_1d)) or np.any(np.isinf(data_1d)):
                print("WARNING: Invalid data detected in traffic history (NaN or Inf)")
                # Remove NaN/Inf values
                valid_mask = ~(np.isnan(data_1d) | np.isinf(data_1d))
                data_1d = data_1d[valid_mask]
                
                if len(data_1d) < 10:
                    return jsonify({'available': True, 'anomalies': [], 'message': 'Not enough valid data'})
            
            # Calculate baseline and std from clean 1D data
            baseline_kb = float(np.mean(data_1d))
            std_kb = float(np.std(data_1d))
            
            # Now reshape for ML model
            data = data_1d.reshape(-1, 1)
            
        except Exception as e:
            print(f"ERROR: Failed to prepare data: {e}")
            return jsonify({'available': True, 'anomalies': [], 'error': f'Data preparation error: {str(e)}'})

    try:
        # Prevent NaN values
        if np.isnan(baseline_kb) or np.isnan(std_kb):
            print(f"WARNING: NaN detected - baseline: {baseline_kb}, std: {std_kb}")
            return jsonify({'available': True, 'anomalies': [], 'message': 'Invalid baseline calculation'})

        # --- Thresholds (KB) ---
        # Dynamic threshold: baseline + 3*std (more robust than baseline*3 when baseline is small)
        dynamic_threshold_kb = baseline_kb + (3 * std_kb)

        # Absolute threshold: 50 KB (reasonable minimum for spike detection)
        # Changed from 0.6 KB to 50 KB based on client's examples
        absolute_threshold_kb = 50.0

        # Final threshold: choose the higher one to reduce false positives
        threshold_kb = max(dynamic_threshold_kb, absolute_threshold_kb)

        # Fit & predict (Isolation Forest)
        predictions = anomaly_detector.fit_predict(data)

        anomalies = []
        for i, pred in enumerate(predictions):
            # Safety check for index bounds
            if i >= len(traffic_history['inbound']):
                break
                
            value_kb = float(traffic_history['inbound'][i])
            
            # Skip invalid values
            if np.isnan(value_kb) or np.isinf(value_kb):
                continue
            
            if pred == -1 and value_kb >= threshold_kb:
                anomalies.append({
                    'time': traffic_history['labels'][i],
                    'value_kb': round(value_kb, 3),
                    'type': 'traffic_spike',
                    'baseline_kb': round(baseline_kb, 3),
                    'threshold_kb': round(threshold_kb, 3)
                })

        # Debug logging
        if anomalies:
            print(f"\n{'='*60}")
            print(f"ML ANOMALIES DETECTED: {len(anomalies)} anomalies found")
            latest = anomalies[-1]
            print(f"  Latest spike: {latest['value_kb']} KB at {latest['time']}")
            print(f"  Baseline: {baseline_kb:.3f} KB | Std Dev: {std_kb:.3f} KB")
            print(f"  Threshold: {threshold_kb:.3f} KB")
            print(f"{'='*60}\n")

        # If anomalies found, create ONE alert for latest (avoid dashboard spam)
        if anomalies:
            latest = anomalies[-1]

            # Create dashboard alert (always)
            create_alert(
                'ml_anomaly',
                f"Traffic spike detected: {latest['value_kb']} KB (baseline: {latest['baseline_kb']} KB, threshold: {latest['threshold_kb']} KB)",
                'danger'
            )
            print(f"  ✓ Dashboard alert created")

            # Telegram only for significant spikes (avoid spam)
            # Significant = 250 KB minimum OR 5x baseline (whichever is larger)
            # This prevents spam for small networks with low baseline
            significant_kb = max(250.0, baseline_kb * 5)

            if latest['value_kb'] >= significant_kb:
                print(f"  → Spike is SIGNIFICANT ({latest['value_kb']} KB >= {significant_kb:.2f} KB)")
                
                # Send to current logged-in user (not just admin)
                current_user_id = session.get('user_id')
                if current_user_id:
                    print(f"  → Sending Telegram alert to user: {current_user_id}")
                    try:
                        notify_security_alert(
                            current_user_id,
                            'anomaly',
                            f"Significant traffic spike: {latest['value_kb']} KB at {latest['time']} (baseline: {round(baseline_kb,3)} KB)"
                        )
                        print(f"  ✓ Telegram notification sent")
                    except Exception as e:
                        print(f"  ✗ Telegram notification failed: {e}")
                else:
                    print(f"  ✗ No user logged in - Telegram notification skipped")
            else:
                print(f"  → Spike below significant threshold ({latest['value_kb']} KB < {significant_kb:.2f} KB) - Telegram skipped")

        return jsonify({
            'available': True,
            'anomalies': anomalies[-5:],  # last 5
            'status': 'monitoring',
            'baseline_kb': round(baseline_kb, 3),
            'std_kb': round(std_kb, 3),
            'threshold_kb': round(threshold_kb, 3)
        })

    except Exception as e:
        print(f"ERROR in ML anomaly detection: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'available': True, 'anomalies': [], 'error': str(e)})

@app.route('/api/reset-network-data', methods=['POST'])
@admin_required
def api_reset_network_data():
    """Reset all network monitoring data"""
    global traffic_history, current_traffic, protocol_stats, device_traffic_stats, known_devices, captured_packets
    
    with traffic_lock:
        traffic_history = {'labels': [], 'inbound': [], 'outbound': []}
        current_traffic = {'inbound': 0, 'outbound': 0}
        captured_packets = []
    
    with protocol_lock:
        protocol_stats.clear()
    
    with device_stats_lock:
        device_traffic_stats.clear()

    known_devices.clear()
    device_last_seen.clear()
    device_mac_mapping.clear()

    return jsonify({'success': True, 'message': 'Network data reset'})

# ============================================================
# SECURITY SCANNING API
# ============================================================

@app.route('/api/security/scan', methods=['POST'])
@login_required
def start_security_scan():
    """Start a security scan"""
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    scan_type = data.get('type')  # port_scan, dns_check, open_ports
    
    if scan_type not in ['port_scan', 'dns_check', 'open_ports']:
        return jsonify({'error': 'Invalid scan type'}), 400
    
    # Check if already scanning
    with security_scan_lock:
        if security_scan_results[scan_type]['status'] == 'scanning':
            return jsonify({'error': 'Scan already in progress'}), 400
    
    # Start scan in background
    thread = threading.Thread(target=run_security_scan, args=(scan_type,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': f'{scan_type} started'})

@app.route('/api/security/results')
@login_required
def get_security_results():
    """Get security scan results"""
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    with security_scan_lock:
        return jsonify(security_scan_results)

@app.route('/api/security/results/<scan_type>')
@login_required
def get_security_result(scan_type):
    """Get specific security scan result"""
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    if scan_type not in security_scan_results:
        return jsonify({'error': 'Invalid scan type'}), 400
    
    with security_scan_lock:
        return jsonify(security_scan_results[scan_type])

# ============================================================
# RUN SERVER
# ============================================================

def cleanup_stale_online_status():
    """Clean up stale online status on server startup"""
    print("  Cleaning up stale online status...")
    try:
        # Get all online devices
        devices_resp = requests.get(f"{FIREBASE_DB_URL}/online_devices.json")
        devices_data = devices_resp.json() or {}
        
        now = datetime.now(timezone.utc)
        stale_count = 0
        
        for device_id, device_data in devices_data.items():
            if not isinstance(device_data, dict):
                continue
                
            last_seen_str = device_data.get('lastSeen')
            if last_seen_str:
                try:
                    last_seen = datetime.fromisoformat(last_seen_str.replace('Z', '+00:00'))
                    time_diff = (now - last_seen).total_seconds()
                    
                    # If no heartbeat for more than 2 minutes, mark as offline
                    if time_diff > 120:
                        requests.patch(
                            f"{FIREBASE_DB_URL}/online_devices/{device_id}.json",
                            json={'status': 'offline'}
                        )
                        stale_count += 1
                except:
                    pass
        
        # Also mark all users as offline in users table
        users_resp = requests.get(f"{FIREBASE_DB_URL}/users.json")
        users_data = users_resp.json() or {}
        
        for user_id, user_data in users_data.items():
            if isinstance(user_data, dict) and user_data.get('online'):
                requests.patch(
                    f"{FIREBASE_DB_URL}/users/{user_id}.json",
                    json={'online': False}
                )
        
        print(f"  Cleaned up {stale_count} stale devices")
    except Exception as e:
        print(f"  Cleanup error: {e}")

if __name__ == '__main__':
    print("\n" + "="*50)
    print("  AuthTrack - SOHO Network Monitor")
    print("="*50)
    print(f"  Server: http://127.0.0.1:5000")
    print(f"  Firebase: Connected")
    print("="*50 + "\n")
    
    # Test ML initialization
    if init_ml():
        print("  ML Anomaly Detection: ✓ Ready (scikit-learn loaded)")
    else:
        print("  ML Anomaly Detection: ✗ Disabled (run: pip install scikit-learn)")
    print("="*50 + "\n")
    
    # Cleanup stale online status
    cleanup_stale_online_status()
    print("="*50 + "\n")
    
    # Auto-start packet sniffer in background
    if SCAPY_AVAILABLE:
        sniffer_active = True
        sniffer_thread = threading.Thread(target=sniffer_worker, daemon=True)
        sniffer_thread.start()
        print("  Packet Sniffer: Started automatically")
        print("="*50 + "\n")
    else:
        print("  WARNING: Scapy not available. Install with: pip install scapy")
        print("="*50 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
