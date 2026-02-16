#!/bin/bash
# Quick debug script - shows current state and any errors
# Run with: sudo bash /opt/web_server/quick_debug.sh

echo "=== Current Service Status ==="
systemctl is-active igniet-backend.service && echo "✅ igniet-backend: RUNNING" || echo "❌ igniet-backend: STOPPED"
systemctl is-active web_server.service 2>/dev/null && echo "⚠️  web_server: RUNNING (SHOULD BE DISABLED!)" || echo "✅ web_server: disabled"

echo ""
echo "=== Port 8080 Status ==="
ss -tlnp | grep :8080 || echo "Nothing listening on port 8080"

echo ""
echo "=== Last 20 Backend Logs ==="
journalctl -u igniet-backend.service -n 20 --no-pager

echo ""
echo "=== Recent Errors (last 5 minutes) ==="
journalctl -u igniet-backend.service --since "5 minutes ago" --no-pager | grep -i "error\|fatal\|panic" || echo "No errors found"

echo ""
echo "=== Email Configuration ==="
journalctl -u igniet-backend.service -n 100 --no-pager | grep -i "email config" | tail -3

echo ""
echo "=== Test Endpoint ==="
curl -s "http://localhost:8080/health" | jq '.' || echo "Backend not responding"
