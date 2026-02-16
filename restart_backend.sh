#!/bin/bash
set -e

cd /opt/web_server

echo "Building backend..."
go build -o web_server main.go

echo "Restarting service..."
systemctl restart igniet-backend.service

sleep 2

echo "Checking service status..."
systemctl status igniet-backend.service --no-pager | head -15

echo ""
echo "Testing endpoint..."
curl -s "http://localhost:8080/api/admin/problem-statement?id=1" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbl9pZCI6MSwiZW1haWwiOiJpZ25pZXRrZGlzY0BnbWFpbC5jb20iLCJleHAiOjE3NzEwNTQ2ODAsInJvbGUiOiJBRE1JTiJ9.fDIeDMZ0eQPsv7EQxa-xG_QJS5t172KGlqc1fxp_bSQ" | jq

echo ""
echo "✅ Backend restarted and tested!"
