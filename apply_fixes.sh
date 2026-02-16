#!/bin/bash
# Quick rebuild and restart script for backend
set -e

echo "🔨 Building backend..."
cd /opt/web_server
go build -o web_server main.go

echo "♻️  Restarting service..."
sudo systemctl restart igniet-backend.service

echo "⏱️  Waiting for service to start..."
sleep 3

echo "✅ Service status:"
sudo systemctl status igniet-backend.service --no-pager | head -15

echo ""
echo "🧪 Testing fixed endpoint..."
response=$(curl -s "http://localhost:8080/api/admin/problem-statement?id=1" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbl9pZCI6MSwiZW1haWwiOiJpZ25pZXRrZGlzY0BnbWFpbC5jb20iLCJleHAiOjE3NzEwNTQ2ODAsInJvbGUiOiJBRE1JTiJ9.fDIeDMZ0eQPsv7EQxa-xG_QJS5t172KGlqc1fxp_bSQ" 2>&1)

if echo "$response" | grep -q '"success":true'; then
    echo "✅ Endpoint working! Response:"  
    echo "$response" | jq '.'
else
    echo "⚠️  Response:"
    echo "$response"
fi

echo ""
echo "📧 Email configuration check:"
sudo journalctl -u igniet-backend.service -n 20 --no-pager | grep -i "email" | tail -2

echo ""
echo "Done! Backend has been restarted with fixes."
