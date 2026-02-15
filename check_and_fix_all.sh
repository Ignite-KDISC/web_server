#!/bin/bash
# Complete status check and restart if needed

echo "=== CHECKING ALL SERVICES ==="
echo ""

echo "1. Backend Service:"
systemctl is-active igniet-backend.service && echo "✅ Running" || echo "❌ Stopped"

echo ""
echo "2. Frontend Container:"
docker ps | grep -q igniet-frontend && echo "✅ Running" || echo "❌ Stopped"

echo ""
echo "3. Ports:"
ss -tlnp | grep :8080 && echo "✅ Port 8080 listening" || echo "❌ Port 8080 not listening"
ss -tlnp | grep :3000 && echo "✅ Port 3000 listening" || echo "❌ Port 3000 not listening"
ss -tlnp | grep :443 && echo "✅ Port 443 listening" || echo "❌ Port 443 not listening"

echo ""
echo "4. Service Tests:"
curl -s -o /dev/null -w "Frontend (3000): %{http_code}\n" http://localhost:3000/
curl -s -o /dev/null -w "Backend (8080): %{http_code}\n" http://localhost:8080/health
curl -s -o /dev/null -w "Nginx HTTP (80): %{http_code}\n" http://localhost/
curl -sk -o /dev/null -w "Nginx HTTPS (443): %{http_code}\n" https://localhost/

echo ""
echo "=== RESTARTING SERVICES IF NEEDED ==="
echo ""

# Check and restart backend
if ! systemctl is-active igniet-backend.service > /dev/null; then
    echo "Restarting backend..."
    systemctl restart igniet-backend.service
    sleep 3
fi

# Check and restart frontend
if ! docker ps | grep -q igniet-frontend; then
    echo "Restarting frontend..."
    cd /data/web_client && ./start_frontend.sh
    sleep 5
fi

echo ""
echo "=== FINAL STATUS ==="
systemctl is-active igniet-backend.service && echo "✅ Backend: Running" || echo "❌ Backend: Failed"
docker ps | grep -q igniet-frontend && echo "✅ Frontend: Running" || echo "❌ Frontend: Failed"

echo ""
echo "=== TEST THE WEBSITE ==="
echo "Correct URL: https://igniet.kdisc.kerala.gov.in (note the 't')"
echo ""
curl -sk https://localhost/ | head -20 | grep -q "DOCTYPE\|html" && echo "✅ Website is serving HTML" || echo "⚠️ Website may not be responding"

echo ""
echo "=== RECENT ERRORS ==="
journalctl -u igniet-backend.service --since "5 minutes ago" --no-pager | grep -i error | tail -5 || echo "No errors"
