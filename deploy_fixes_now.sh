#!/bin/bash
# Complete fix deployment script
# Run with: sudo bash /opt/web_server/deploy_fixes_now.sh

set -e

echo "=================================="
echo "  IGNIET Backend Fix Deployment"
echo "=================================="
echo ""

cd /opt/web_server

echo "📋 Step 1: Check current service status"
echo "----------------------------------------"
systemctl status igniet-backend.service --no-pager -l | head -10 || true
echo ""

echo "📋 Step 2: Stop any duplicate services"
echo "----------------------------------------"
systemctl stop web_server.service 2>/dev/null || echo "web_server.service not running"
systemctl disable web_server.service 2>/dev/null || echo "web_server.service already disabled"

# Kill any rogue processes
pkill -9 web_server 2>/dev/null || echo "No rogue processes found"
sleep 2
echo ""

echo "🔨 Step 3: Rebuild backend with fixes"
echo "----------------------------------------"
go build -o web_server main.go
if [ $? -eq 0 ]; then
    echo "✅ Build successful"
else
    echo "❌ Build failed!"
    exit 1
fi
echo ""

echo "♻️  Step 4: Restart igniet-backend service"
echo "----------------------------------------"
systemctl restart igniet-backend.service
sleep 3
echo ""

echo "✅ Step 5: Verify service is running"
echo "----------------------------------------"
systemctl status igniet-backend.service --no-pager | head -15
echo ""

echo "🧪 Step 6: Test the fixed endpoint"
echo "----------------------------------------"
# Get a fresh admin token first
echo "Logging in to get fresh token..."
LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:8080/api/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"ignietkdisc@gmail.com","password":"password@123"}')

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token // empty')

if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    echo "✅ Login successful, testing endpoint..."
    echo ""
    
    TEST_RESPONSE=$(curl -s "http://localhost:8080/api/admin/problem-statement?id=1" \
      -H "Authorization: Bearer $TOKEN")
    
    if echo "$TEST_RESPONSE" | jq -e '.success == true' > /dev/null 2>&1; then
        echo "✅ ENDPOINT WORKING! Response:"
        echo "$TEST_RESPONSE" | jq '.'
    else
        echo "⚠️  Endpoint response:"
        echo "$TEST_RESPONSE"
    fi
else
    echo "❌ Could not get admin token. Login response:"
    echo "$LOGIN_RESPONSE" | jq '.' 2>/dev/null || echo "$LOGIN_RESPONSE"
fi
echo ""

echo "📧 Step 7: Check email configuration"
echo "----------------------------------------"
journalctl -u igniet-backend.service -n 30 --no-pager | grep -i "email\|smtp" | tail -5
echo ""

echo "🔍 Step 8: Check for any recent errors"
echo "----------------------------------------"
journalctl -u igniet-backend.service --since "2 minutes ago" --no-pager | grep -i "error" | tail -10 || echo "No errors found"
echo ""

echo "=================================="
echo "  Deployment Complete!"
echo "=================================="
echo ""
echo "Service Status:"
systemctl is-active igniet-backend.service && echo "✅ Backend: RUNNING" || echo "❌ Backend: STOPPED"
docker ps | grep -q igniet-frontend && echo "✅ Frontend: RUNNING" || echo "⚠️  Frontend: Check status"
echo ""
echo "Next steps:"
echo "1. Test the website: https://igniet.kdisc.kerala.gov.in"
echo "2. Try accessing: https://igniet.kdisc.kerala.gov.in/admin/problem/1"
echo "3. Monitor logs: sudo journalctl -u igniet-backend.service -f"
echo ""
