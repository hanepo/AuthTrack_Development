// AuthTrack - Popup Script
const SERVER_URL = 'http://127.0.0.1:5000';

document.addEventListener('DOMContentLoaded', () => {
  checkStatus();
  
  document.getElementById('loginBtn').addEventListener('click', login);
  document.getElementById('logoutBtn').addEventListener('click', logout);
  document.getElementById('refreshBtn').addEventListener('click', refreshRules);
  
  // Enter key to submit
  document.getElementById('userId').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') login();
  });
});

function checkStatus() {
  chrome.runtime.sendMessage({ action: 'getStatus' }, (response) => {
    if (response && response.isLoggedIn) {
      showStatusView(response.userEmail, response.blockedCount);
      updateRestrictionStatus();
    } else {
      showLoginView();
    }
  });
}

function showLoginView() {
  document.getElementById('loginView').style.display = 'flex';
  document.getElementById('statusView').style.display = 'none';
}

function showStatusView(email, blockedCount) {
  document.getElementById('loginView').style.display = 'none';
  document.getElementById('statusView').style.display = 'block';
  document.getElementById('displayEmail').textContent = email;
  document.getElementById('blockedCount').textContent = blockedCount || 0;
}

function showError(msg) {
  const errorEl = document.getElementById('errorMsg');
  errorEl.textContent = msg;
  errorEl.style.display = 'block';
}

function hideError() {
  document.getElementById('errorMsg').style.display = 'none';
}

async function login() {
  hideError();
  
  const email = document.getElementById('email').value.trim();
  const userId = document.getElementById('userId').value.trim();
  
  if (!email) {
    showError('Please enter your email');
    return;
  }
  
  if (!userId) {
    showError('Please enter your User ID');
    return;
  }
  
  try {
    // Verify with server
    const response = await fetch(`${SERVER_URL}/api/extension/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, userId })
    });
    
    if (response.ok) {
      // Save session in background script
      chrome.runtime.sendMessage({ 
        action: 'login', 
        email: email, 
        userId: userId 
      }, (response) => {
        if (response && response.success) {
          checkStatus();
        }
      });
    } else {
      const data = await response.json();
      showError(data.message || 'Failed to connect');
    }
  } catch (error) {
    showError('Cannot connect to server. Is AuthTrack running?');
  }
}

function logout() {
  chrome.runtime.sendMessage({ action: 'logout' }, () => {
    showLoginView();
  });
}

function refreshRules() {
  document.getElementById('refreshBtn').textContent = '⏳ Refreshing...';
  chrome.runtime.sendMessage({ action: 'refreshRules' }, (response) => {
    document.getElementById('refreshBtn').textContent = '🔄 Refresh Rules';
    updateRestrictionStatus();
    if (response && response.success) {
      // Show brief success indication
      document.getElementById('blockedCount').textContent = response.blockedCount || 0;
    }
  });
}

function updateRestrictionStatus() {
  chrome.runtime.sendMessage({ action: 'getRestrictionStatus' }, (response) => {
    const statusEl = document.getElementById('restrictionStatus');
    if (response && response.enabled) {
      const schedules = response.schedules || [];
      if (schedules.length > 0) {
        statusEl.innerHTML = schedules.map(s => {
          const allowed = s.allowed ? '✓ Allowed' : '🚫 Blocked';
          return `${allowed}<br>Days: ${s.day}, ${s.startTime} - ${s.endTime}`;
        }).join('<br>');
      } else {
        statusEl.textContent = '✓ Enabled, No schedules';
      }
    } else {
      statusEl.textContent = '✓ No restrictions';
    }
  });
}
