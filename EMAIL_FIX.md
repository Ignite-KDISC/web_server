# Email Issue Fix - SMTP Port 587 Blocked

## 🔍 Root Cause Identified
**SMTP Port 587 is blocked by firewall/network**, causing 30-second email timeouts.

## ✅ Fixes Applied

### 1. **Reduced Email Timeout** (30s → 5s)
- Emails now fail fast instead of hanging
- Site responds immediately even if email fails
- **Location:** `/opt/web_server/main.go` line 1851

### 2. **Improved Systemd Auto-Restart**
- Changed from `Restart=on-failure` to `Restart=always`
- Added `StartLimitBurst=5` and `StartLimitIntervalSec=60s`
- Service will restart within 5 seconds if it crashes
- **Location:** `/etc/systemd/system/igniet-backend.service`

### 3. **Email Already Asynchronous**
- ✅ Email sending runs in goroutine (line 665)
- ✅ HTTP response returns immediately
- ✅ User doesn't wait for email to complete

## 🔧 How to Fix SMTP Firewall Issue

### Option 1: Contact Network Admin (Recommended)
Ask your IT/Network team to **unblock outbound port 587** (Gmail SMTP).

### Option 2: Check UFW Firewall
```bash
# Check firewall status
sudo ufw status

# Allow outbound SMTP (if UFW is active)
sudo ufw allow out 587/tcp
```

### Option 3: Check iptables
```bash
# Check if iptables is blocking
sudo iptables -L OUTPUT -n -v | grep 587

# Allow port 587 if blocked
sudo iptables -A OUTPUT -p tcp --dport 587 -j ACCEPT
sudo iptables-save
```

### Option 4: Test SMTP Connection
```bash
# Test if port 587 is reachable
timeout 3 bash -c 'cat < /dev/null > /dev/tcp/smtp.gmail.com/587' && echo "✅ SMTP reachable" || echo "❌ SMTP blocked"

# Alternative test with telnet
telnet smtp.gmail.com 587
# (Should connect if port is open)
```

### Option 5: Use Alternative SMTP Port
If port 587 is permanently blocked, try port 465 (SSL) or 2525:

Edit `/opt/web_server/.env`:
```bash
SMTP_PORT=465  # or 2525
```

Then restart:
```bash
sudo systemctl restart igniet-backend.service
```

## 📊 Current Status
✅ **Backend:** Running with auto-restart enabled  
✅ **Frontend:** Running in Docker  
✅ **Site:** Fully functional (emails pending firewall fix)  
⚠️ **Email:** Timing out after 5 seconds (port 587 blocked)

## 🔍 Monitor Logs
```bash
# Watch backend live logs
sudo journalctl -u igniet-backend.service -f

# Watch frontend logs
sudo docker logs -f igniet-frontend

# Watch nginx access
sudo tail -f /var/log/nginx/igniet-frontend-access.log
```

## 📞 Next Steps
1. **Contact network admin** to unblock port 587
2. **Test email** after firewall is fixed
3. **Monitor logs** for any issues

## 🎯 Why Site Works Despite Email Failure
- Email sending is **asynchronous** (non-blocking)
- HTTP response returns **before** email is sent
- Email timeout only affects background goroutine
- Service auto-restarts on any crash

---
**Last Updated:** February 13, 2026  
**Status:** ✅ Site functional | ⚠️ Email blocked by firewall
