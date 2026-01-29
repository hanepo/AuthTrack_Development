# NetMonitoring Project - TODO List

**Last Updated:** January 13, 2026  
**Project Status:** 75% Complete

---

## 🔴 HIGH PRIORITY (Critical for Report Requirements)

### 1. Security Scanning Module - Frontend UI Integration

**Status:** ⚠️ PARTIALLY DONE (Backend complete, frontend missing)  
**Estimated Time:** 4-6 hours

- [ ] Create Security Scanner page/tab in dashboard
- [ ] Add UI for Port Scan results display
  - [ ] Show scanned devices with open ports
  - [ ] Display port number, service name, and risk level
  - [ ] Add color coding (red=high risk, yellow=medium, green=low)
- [ ] Add UI for DNS Hijacking Check results
  - [ ] Display tested domains and resolved IPs
  - [ ] Show status indicators (safe/suspicious/error)
- [ ] Add UI for Open Ports Monitoring
  - [ ] List all open ports on local machine
  - [ ] Show service names and risk assessment
- [ ] Add "Start Scan" buttons for each scan type
- [ ] Show scan status (idle/scanning/complete)
- [ ] Display last scan timestamp
- [ ] Add auto-refresh option for scan results

**Files to modify:**

- `templates/dashboard.html` - Add security scanner tab
- Create new JS module for security scanner UI
- Add API calls to `/api/security/scan` and `/api/security/results`

---

### 2. Network Topology Visualization

**Status:** ⚠️ PARTIALLY DONE (Backend API exists, visualization missing)  
**Estimated Time:** 6-8 hours

- [ ] Install D3.js or vis.js library
- [ ] Create network topology visualization component
- [ ] Fetch data from `/api/network/topology` endpoint
- [ ] Render nodes:
  - [ ] Internet node (cloud icon)
  - [ ] Router node (router icon)
  - [ ] Device nodes (laptop/phone icons)
- [ ] Draw connections/links between nodes
- [ ] Add interactive features:
  - [ ] Hover to show device details
  - [ ] Click to highlight device traffic
  - [ ] Drag nodes to rearrange layout
- [ ] Add legend explaining node types
- [ ] Add refresh button to update topology
- [ ] Style with dark theme to match dashboard

**Files to create/modify:**

- Create `static/js/network-topology.js`
- Update `templates/traffic_analysis.html` or create new topology page
- Add CSS styling for topology visualization

---

### 3. Telegram Bot Notifications

**Status:** ❌ NOT IMPLEMENTED (Email framework exists)  
**Estimated Time:** 3-4 hours

- [ ] Create Telegram Bot via BotFather
- [ ] Get Bot Token and store in environment variable
- [ ] Install `python-telegram-bot` library
- [ ] Implement Telegram notification function in `app.py`
- [ ] Add user Telegram Chat ID to Firebase user profile
- [ ] Create settings page for users to register their Telegram ID
- [ ] Send notifications for:
  - [ ] Blocked website attempts
  - [ ] Security alerts
  - [ ] New device connections
  - [ ] High bandwidth usage
  - [ ] Failed login attempts
- [ ] Add notification preferences (enable/disable per alert type)
- [ ] Test notification delivery

**Files to modify:**

- `app.py` - Add Telegram bot integration
- `requirements.txt` - Add `python-telegram-bot`
- `templates/profile.html` - Add Telegram ID field
- Update alert system to use Telegram

---

## 🟡 MEDIUM PRIORITY (Improvement & Completeness)

### 4. Email Notification System Configuration

**Status:** ⚠️ PARTIALLY DONE (Framework exists but hardcoded)  
**Estimated Time:** 2 hours

- [ ] Move email credentials to environment variables
- [ ] Remove hardcoded credentials from `app.py`
- [ ] Create `.env.example` file with template
- [ ] Add configuration instructions in README
- [ ] Test email delivery for 2FA codes
- [ ] Add email templates (HTML formatting)
- [ ] Implement error handling for failed email sends

**Files to modify:**

- `app.py` - Update email configuration
- Create `.env.example`
- Update documentation

---

### 5. ML Anomaly Detection Enhancement

**Status:** ⚠️ BASIC IMPLEMENTATION (Needs improvement)  
**Estimated Time:** 6-8 hours

- [ ] Collect more training data for ML model
- [ ] Implement periodic model retraining
- [ ] Add more features for detection:
  - [ ] Packet size distribution
  - [ ] Protocol patterns
  - [ ] Time-based patterns
  - [ ] Device-specific baselines
- [ ] Tune IsolationForest parameters (contamination rate)
- [ ] Add anomaly classification (type of anomaly)
- [ ] Create alerts for detected anomalies
- [ ] Add ML model performance metrics
- [ ] Save/load trained model (pickle)
- [ ] Add UI to display anomaly detection results

**Files to modify:**

- `app.py` - Enhance ML detection logic
- Add new endpoint for anomaly history
- Update dashboard to show ML insights

---

### 6. Squid Proxy Integration (Optional)

**Status:** ❌ NOT IMPLEMENTED (Chrome Extension used instead)  
**Estimated Time:** 8-10 hours  
**Note:** This is optional since Chrome Extension achieves the same goal

- [ ] Install Squid Proxy server
- [ ] Configure Squid for transparent proxying
- [ ] Set up ACL (Access Control Lists) for blocking
- [ ] Integrate Squid logs with system
- [ ] Sync blocking rules between Squid and Chrome Extension
- [ ] Add Squid status monitoring
- [ ] Document Squid installation steps

**Decision needed:** Keep Chrome Extension approach or add Squid?  
**Recommendation:** Chrome Extension is more user-friendly for SOHO, keep as is.

---

## 🟢 LOW PRIORITY (Documentation & Polish)

### 7. System Documentation

**Status:** ❌ INCOMPLETE  
**Estimated Time:** 6-8 hours

#### 7.1 User Manual

- [ ] Create `docs/USER_MANUAL.md`
- [ ] Document all features with screenshots
- [ ] Add step-by-step guides:
  - [ ] Installation guide
  - [ ] First-time setup
  - [ ] User registration
  - [ ] Chrome extension installation
  - [ ] Setting up blocking rules
  - [ ] Viewing traffic logs
  - [ ] Managing devices
  - [ ] Receiving notifications
- [ ] Add troubleshooting section
- [ ] Create FAQ section

#### 7.2 Deployment Guide

- [ ] Create `docs/DEPLOYMENT.md`
- [ ] Document system requirements
- [ ] Installation steps (Windows/Linux)
- [ ] Python environment setup
- [ ] Firebase configuration
- [ ] Chrome extension loading
- [ ] Port configuration (5000)
- [ ] Security best practices
- [ ] Backup and restore procedures

#### 7.3 API Documentation

- [ ] Create `docs/API.md`
- [ ] Document all API endpoints:
  - [ ] Authentication endpoints
  - [ ] User management endpoints
  - [ ] Device management endpoints
  - [ ] Traffic monitoring endpoints
  - [ ] Security scanning endpoints
  - [ ] Alert endpoints
- [ ] Include request/response examples
- [ ] Add authentication requirements
- [ ] Document error codes

#### 7.4 Developer Guide

- [ ] Create `docs/DEVELOPER.md`
- [ ] Document code structure
- [ ] Explain module architecture
- [ ] Add comments to complex functions
- [ ] Document database schema
- [ ] Contribution guidelines

---

## 🔧 TECHNICAL IMPROVEMENTS (Nice to Have)

### 8. Testing Infrastructure

**Status:** ❌ NOT IMPLEMENTED  
**Estimated Time:** 8-10 hours

- [ ] Set up pytest framework
- [ ] Create unit tests for:
  - [ ] Authentication functions
  - [ ] Packet sniffing logic
  - [ ] Security scanning functions
  - [ ] Alert system
- [ ] Create integration tests
- [ ] Add test coverage reporting
- [ ] Set up CI/CD pipeline (GitHub Actions)

---

### 9. Security Enhancements

**Status:** ⚠️ NEEDS IMPROVEMENT  
**Estimated Time:** 4-6 hours

- [ ] Remove hardcoded credentials
- [ ] Implement rate limiting on API endpoints
- [ ] Add CSRF protection
- [ ] Enable HTTPS (SSL/TLS)
- [ ] Implement password strength requirements
- [ ] Add account lockout after failed attempts
- [ ] Sanitize all user inputs
- [ ] Add security headers (CORS, CSP)
- [ ] Implement audit logging

---

### 10. Performance Optimization

**Status:** ⚠️ NEEDS IMPROVEMENT  
**Estimated Time:** 4-6 hours

- [ ] Optimize database queries
- [ ] Add caching for frequently accessed data
- [ ] Implement pagination for large datasets
- [ ] Optimize packet capture performance
- [ ] Add database indexing
- [ ] Compress API responses
- [ ] Lazy load dashboard components

---

### 11. Additional Features (Future Enhancement)

**Status:** ❌ NOT PLANNED  
**Estimated Time:** Variable

- [ ] Dark/Light theme toggle
- [ ] Export reports (PDF/CSV)
- [ ] Advanced filtering in logs
- [ ] User activity heatmap
- [ ] Bandwidth usage graphs per device
- [ ] Mobile app for monitoring
- [ ] Multi-language support
- [ ] Scheduled reports via email
- [ ] Integration with other security tools

---

## 📋 COMPLETION CHECKLIST

### Before Project Submission:

- [ ] All HIGH PRIORITY items completed
- [ ] User Manual created
- [ ] Deployment Guide created
- [ ] API Documentation created
- [ ] Code commented and cleaned
- [ ] Remove all hardcoded credentials
- [ ] Test all features end-to-end
- [ ] Create demo video/presentation
- [ ] Prepare project report updates
- [ ] Final code review

### Minimum Viable Product (MVP):

- [x] Authentication with 2FA ✅
- [x] Website logging ✅
- [x] URL/Domain blocking ✅
- [x] Packet sniffing ✅
- [x] Admin dashboard ✅
- [x] Chrome extension ✅
- [ ] Security scanner UI
- [ ] Network topology visualization
- [ ] Telegram notifications
- [ ] User documentation

---

## 📊 PROGRESS TRACKER

**Overall Completion:** 75%

| Category          | Status      | Progress |
| ----------------- | ----------- | -------- |
| Core Features     | ✅ Complete | 100%     |
| Security Scanning | ⚠️ Partial  | 80%      |
| Visualization     | ⚠️ Partial  | 40%      |
| Notifications     | ⚠️ Partial  | 50%      |
| Documentation     | ❌ Missing  | 10%      |
| Testing           | ❌ Missing  | 0%       |

**Next Sprint Focus:**

1. Security Scanner UI (HIGH)
2. Network Topology Visualization (HIGH)
3. Telegram Bot Integration (HIGH)

---

## 📝 NOTES

### Development Environment Setup Reminders:

```bash
# Install additional dependencies
pip install python-telegram-bot python-dotenv

# For network topology visualization
# Add to templates: <script src="https://d3js.org/d3.v7.min.js"></script>
```

### Testing Checklist:

- [ ] Test on Windows
- [ ] Test on Linux
- [ ] Test with multiple browsers
- [ ] Test with multiple concurrent users
- [ ] Test security scanning features
- [ ] Test notification delivery
- [ ] Test Chrome extension on multiple sites

### Known Issues to Fix:

- Email credentials hardcoded (SECURITY RISK)
- No error handling for Firebase connection failures
- Packet sniffer requires admin privileges (document this)
- Chrome extension needs manual installation (create installation guide)

---

**Estimated Total Time to Complete HIGH PRIORITY Items:** 13-18 hours  
**Estimated Total Time to Complete All Items:** 50-70 hours

**Recommendation:** Focus on HIGH PRIORITY items first to meet report requirements, then tackle MEDIUM and LOW priority items as time permits.
