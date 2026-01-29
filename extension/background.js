// NetMonitoring - Background Service Worker
const SERVER_URL = 'http://127.0.0.1:5000';

// State
let userEmail = null;
let userId = null;
let isLoggedIn = false;
let blockedSites = [];
let restrictions = {};
let deviceId = null; // Unique device ID for this browser instance

// ============================================================
// INITIALIZATION
// ============================================================

// Generate or retrieve unique device ID
async function getDeviceId() {
  const data = await chrome.storage.local.get(['deviceId']);
  if (data.deviceId) {
    return data.deviceId;
  }
  
  // Generate new device ID
  const newId = 'browser_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
  await chrome.storage.local.set({ deviceId: newId });
  return newId;
}

// ============================================================
// INITIALIZATION
// ============================================================

chrome.runtime.onInstalled.addListener(() => {
  console.log('NetMonitoring extension installed');
  initializeExtension();
});

chrome.runtime.onStartup.addListener(() => {
  initializeExtension();
});

async function initializeExtension() {
  deviceId = await getDeviceId();
  await loadSession();
}

// Load session from storage
async function loadSession() {
  const data = await chrome.storage.local.get(['userEmail', 'userId', 'isLoggedIn']);
  userEmail = data.userEmail || null;
  userId = data.userId || null;
  isLoggedIn = data.isLoggedIn || false;
  
  if (isLoggedIn && userId) {
    await registerDevice();
    fetchRules();
    startHeartbeat();
  }
}

// Save session
async function saveSession(email, uid) {
  userEmail = email;
  userId = uid;
  isLoggedIn = true;
  
  await chrome.storage.local.set({ 
    userEmail: email, 
    userId: uid, 
    isLoggedIn: true 
  });
  
  await registerDevice();
  fetchRules();
  startHeartbeat();
}

// Register this browser as an online device
async function registerDevice() {
  if (!userId || !deviceId) return;
  
  try {
    await fetch(`${SERVER_URL}/api/extension/register-device`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: userId,
        userEmail: userEmail,
        browser: 'Chrome',
        deviceId: deviceId
      })
    });
    console.log('Device registered:', deviceId);
  } catch (error) {
    console.error('Error registering device:', error);
  }
}

// Send heartbeat to server
async function sendHeartbeat() {
  if (!deviceId || !isLoggedIn) return;
  
  try {
    await fetch(`${SERVER_URL}/api/extension/heartbeat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId: deviceId })
    });
  } catch (error) {
    console.error('Heartbeat error:', error);
  }
}

// Clear session (logout)
async function clearSession() {
  // Mark device as offline before clearing
  if (deviceId) {
    try {
      await fetch(`${SERVER_URL}/api/extension/heartbeat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceId: deviceId, status: 'offline' })
      });
    } catch (e) {}
  }
  
  userEmail = null;
  userId = null;
  isLoggedIn = false;
  blockedSites = [];
  restrictions = {};
  
  await chrome.storage.local.remove(['userEmail', 'userId', 'isLoggedIn']);
  chrome.alarms.clear('refreshRules');
  chrome.alarms.clear('heartbeat');
}

// ============================================================
// RULES & BLOCKING
// ============================================================

async function fetchRules() {
  if (!userId) return;
  
  try {
    const response = await fetch(`${SERVER_URL}/api/extension/rules?userId=${userId}`);
    if (response.ok) {
      const data = await response.json();
      blockedSites = data.blocked_sites || [];
      restrictions = data.restrictions || {};
      console.log('Rules updated:', { 
        blockedSites, 
        restrictions,
        internetEnabled: restrictions?.internet?.enabled,
        scheduleCount: restrictions?.internet?.schedule?.length || 0
      });
    }
  } catch (error) {
    console.error('Error fetching rules:', error);
  }
}

// Check if URL should be blocked
function shouldBlock(url) {
  if (!url || !isLoggedIn) return false;
  
  // Skip extension pages and chrome URLs
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    return false;
  }
  
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    
    console.log('Checking URL:', url, 'Hostname:', hostname);
    
    // Check blocked sites
    for (const blocked of blockedSites) {
      const blockedLower = blocked.toLowerCase();
      if (hostname === blockedLower || 
          hostname.endsWith('.' + blockedLower) ||
          hostname.includes(blockedLower)) {
        console.log('BLOCKED by site list:', blocked);
        return true;
      }
    }
    
    // Check time-based restrictions
    if (restrictions.internet && restrictions.internet.enabled) {
      console.log('Internet restrictions enabled');
      
      const now = new Date();
      const currentTime = now.toTimeString().slice(0, 5); // HH:MM
      const dayOfWeek = now.getDay(); // 0 = Sunday
      const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
      
      console.log('Current time:', currentTime, 'Day:', dayOfWeek, 'Is weekend:', isWeekend);
      
      for (const schedule of (restrictions.internet.schedule || [])) {
        console.log('Checking schedule:', schedule);
        
        let matchDay = false;
        
        if (schedule.day === 'all') matchDay = true;
        else if (schedule.day === 'weekday' && !isWeekend) matchDay = true;
        else if (schedule.day === 'weekend' && isWeekend) matchDay = true;
        
        console.log('Day match:', matchDay);
        
        if (matchDay) {
          let inTimeRange = false;
          
          // Special case: if start and end times are the same, it means 24 hours
          if (schedule.startTime === schedule.endTime) {
            inTimeRange = true; // All day
            console.log('All day block (start === end)');
          } else if (schedule.startTime < schedule.endTime) {
            // Normal case: e.g., 09:00 to 17:00
            inTimeRange = currentTime >= schedule.startTime && currentTime <= schedule.endTime;
            console.log('Normal range check:', currentTime, '>=', schedule.startTime, '&&', currentTime, '<=', schedule.endTime, '=', inTimeRange);
          } else {
            // Overnight case: e.g., 22:00 to 06:00 (crosses midnight)
            inTimeRange = currentTime >= schedule.startTime || currentTime <= schedule.endTime;
            console.log('Overnight range check:', currentTime, '>=', schedule.startTime, '||', currentTime, '<=', schedule.endTime, '=', inTimeRange);
          }
          
          console.log('In time range:', inTimeRange, 'Allowed:', schedule.allowed);
          
          // If "allowed" is false, internet is blocked during this time
          if (inTimeRange && !schedule.allowed) {
            console.log('BLOCKED by time restriction!');
            return true; // Block
          }
        }
      }
    }
    
    // Check website-specific restrictions
    if (restrictions.websites) {
      console.log('Checking website-specific restrictions');
      
      for (const [website, config] of Object.entries(restrictions.websites)) {
        const websiteLower = website.toLowerCase();
        
        // Check if current URL matches this website
        if (hostname === websiteLower || 
            hostname.endsWith('.' + websiteLower) ||
            hostname.includes(websiteLower)) {
          
          console.log('Found website restriction for:', website, config);
          
          if (config.blocked && config.schedule && config.schedule.length > 0) {
            const now = new Date();
            const currentTime = now.toTimeString().slice(0, 5);
            const dayOfWeek = now.getDay();
            const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
            
            for (const schedule of config.schedule) {
              let matchDay = false;
              
              if (schedule.day === 'all') matchDay = true;
              else if (schedule.day === 'weekday' && !isWeekend) matchDay = true;
              else if (schedule.day === 'weekend' && isWeekend) matchDay = true;
              
              if (matchDay) {
                let inTimeRange = false;
                
                if (schedule.startTime === schedule.endTime) {
                  inTimeRange = true;
                } else if (schedule.startTime < schedule.endTime) {
                  inTimeRange = currentTime >= schedule.startTime && currentTime <= schedule.endTime;
                } else {
                  inTimeRange = currentTime >= schedule.startTime || currentTime <= schedule.endTime;
                }
                
                if (inTimeRange) {
                  console.log('BLOCKED by website-specific restriction:', website);
                  return true;
                }
              }
            }
          }
        }
      }
    }
    
    console.log('Not blocked');
  } catch (e) {
    console.error('Error checking block:', e);
  }
  
  return false;
}

// ============================================================
// ACTIVITY TRACKING
// ============================================================

async function reportActivity(url, title, action = 'visit') {
  if (!isLoggedIn || !userId) return;
  
  // Skip non-http URLs
  if (!url || !url.startsWith('http')) return;
  
  try {
    await fetch(`${SERVER_URL}/api/activity`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: userId,
        userEmail: userEmail,
        url: url,
        title: title || 'Unknown',
        action: action,
        timestamp: new Date().toISOString()
      })
    });
  } catch (error) {
    console.error('Error reporting activity:', error);
  }
}

// ============================================================
// TAB MONITORING
// ============================================================

// Monitor tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!isLoggedIn || changeInfo.status !== 'complete' || !tab.url) return;
  
  if (shouldBlock(tab.url)) {
    // Redirect to blocked page
    chrome.tabs.update(tabId, { 
      url: chrome.runtime.getURL('blocked.html') 
    });
    reportActivity(tab.url, tab.title, 'blocked');
  } else {
    reportActivity(tab.url, tab.title, 'visit');
  }
});

// Monitor tab activation
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  if (!isLoggedIn) return;
  
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && !shouldBlock(tab.url)) {
      reportActivity(tab.url, tab.title, 'focus');
    }
  } catch (e) {}
});

// ============================================================
// HEARTBEAT (Refresh rules periodically + Send heartbeat)
// ============================================================

function startHeartbeat() {
  // Refresh rules every 1 minute
  chrome.alarms.create('refreshRules', { periodInMinutes: 1 });
  // Send heartbeat every 30 seconds
  chrome.alarms.create('heartbeat', { periodInMinutes: 0.5 });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'refreshRules') {
    fetchRules();
  } else if (alarm.name === 'heartbeat') {
    sendHeartbeat();
  }
});

// ============================================================
// MESSAGE HANDLING (from popup)
// ============================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case 'login':
      saveSession(message.email, message.userId);
      sendResponse({ success: true });
      break;
      
    case 'logout':
      clearSession();
      sendResponse({ success: true });
      break;
      
    case 'getStatus':
      sendResponse({
        isLoggedIn: isLoggedIn,
        userEmail: userEmail,
        blockedCount: blockedSites.length
      });
      break;
      
    case 'refreshRules':
      fetchRules().then(() => {
        sendResponse({ 
          success: true, 
          blockedCount: blockedSites.length 
        });
      });
      return true; // Async response
      
    case 'getRestrictionStatus':
      sendResponse({
        enabled: restrictions?.internet?.enabled || false,
        schedules: restrictions?.internet?.schedule || []
      });
      break;
  }
  
  return true; // Keep message channel open for async response
});

// Initialize on load
loadSession();
