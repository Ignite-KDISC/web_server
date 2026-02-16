#!/bin/bash
# IGNIET Services Debugging Script
# This script provides comprehensive status checks for all services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   IGNIET Services Debug Report${NC}"
echo -e "${BLUE}========================================${NC}\n"

# 1. Check Systemd Services
echo -e "${YELLOW}[1] Systemd Services Status${NC}"
echo "----------------------------"
if systemctl is-active --quiet igniet-backend.service; then
    echo -e "Backend Service: ${GREEN}✓ Running${NC}"
    systemctl status igniet-backend.service --no-pager -l | grep -E "Active|Main PID|Memory|CPU" | sed 's/^/  /'
else
    echo -e "Backend Service: ${RED}✗ Not Running${NC}"
fi

# Check for duplicate services
if systemctl list-units --all | grep -q "web_server.service"; then
    echo -e "Duplicate Service: ${RED}⚠ web_server.service found (should be disabled)${NC}"
    systemctl status web_server.service --no-pager -l | grep -E "Active|Loaded" | sed 's/^/  /'
fi
echo ""

# 2. Check Docker Containers
echo -e "${YELLOW}[2] Docker Containers${NC}"
echo "----------------------------"
if docker ps | grep -q igniet-frontend; then
    echo -e "Frontend Container: ${GREEN}✓ Running${NC}"
    docker ps --filter name=igniet-frontend --format "  ID: {{.ID}}\n  Status: {{.Status}}\n  Ports: {{.Ports}}"
else
    echo -e "Frontend Container: ${RED}✗ Not Running${NC}"
fi
echo ""

# 3. Check Port Listeners
echo -e "${YELLOW}[3] Port Listeners${NC}"
echo "----------------------------"
ports=(80 443 3000 8080)
for port in "${ports[@]}"; do
    if ss -tlnp | grep -q ":$port"; then
        process=$(ss -tlnp | grep ":$port" | head -1 | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")
        echo -e "Port $port: ${GREEN}✓ Active${NC} ($process)"
    else
        echo -e "Port $port: ${RED}✗ Not listening${NC}"
    fi
done
echo ""

# 4. Test Local Services
echo -e "${YELLOW}[4] Service Health Checks${NC}"
echo "----------------------------"

# Test backend directly
if backend_health=$(curl -s http://localhost:8080/health 2>&1); then
    if echo "$backend_health" | jq -e '.status == "ok"' > /dev/null 2>&1; then
        echo -e "Backend (port 8080): ${GREEN}✓ Healthy${NC}"
        echo "$backend_health" | jq -r '  "  Status: \(.status)\n  Database: \(.database.connected)\n  Message: \(.database.message)"' 2>/dev/null || echo "  Response received"
    else
        echo -e "Backend (port 8080): ${YELLOW}⚠ Running but unhealthy${NC}"
        echo "$backend_health" | head -c 200
    fi
else
    echo -e "Backend (port 8080): ${RED}✗ Not responding${NC}"
fi

# Test frontend directly
if curl -s -o /dev/null -w '' --max-time 3 http://localhost:3000/ 2>&1; then
    http_code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/)
    if [ "$http_code" = "200" ]; then
        echo -e "Frontend (port 3000): ${GREEN}✓ Responding (HTTP $http_code)${NC}"
    else
        echo -e "Frontend (port 3000): ${YELLOW}⚠ Responding with HTTP $http_code${NC}"
    fi
else
    echo -e "Frontend (port 3000): ${RED}✗ Not responding${NC}"
fi
echo ""

# 5. Test Nginx Proxying
echo -e "${YELLOW}[5] Nginx Proxy Tests${NC}"
echo "----------------------------"

# Check nginx config
if nginx -t 2>&1 | grep -q "successful"; then
    echo -e "Nginx Config: ${GREEN}✓ Valid${NC}"
else
    echo -e "Nginx Config: ${RED}✗ Invalid${NC}"
    nginx -t 2>&1 | sed 's/^/  /'
fi

# Test nginx proxying
frontend_code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost/)
if [ "$frontend_code" = "200" ]; then
    echo -e "Nginx → Frontend: ${GREEN}✓ HTTP $frontend_code${NC}"
else
    echo -e "Nginx → Frontend: ${YELLOW}⚠ HTTP $frontend_code${NC}"
fi

api_code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost/api/problem-statements)
if [ "$api_code" = "200" ] || [ "$api_code" = "405" ]; then
    echo -e "Nginx → Backend API: ${GREEN}✓ HTTP $api_code${NC} (405 = Method Not Allowed is OK for GET)"
else
    echo -e "Nginx → Backend API: ${YELLOW}⚠ HTTP $api_code${NC}"
fi
echo ""

# 6. Check SSL/TLS
echo -e "${YELLOW}[6] SSL/TLS Configuration${NC}"
echo "----------------------------"
if [ -d /etc/letsencrypt/live/igniet.kdisc.kerala.gov.in ]; then
    echo -e "SSL Certificates: ${GREEN}✓ Present${NC}"
    cert_path="/etc/letsencrypt/live/igniet.kdisc.kerala.gov.in"
    if [ -f "$cert_path/fullchain.pem" ]; then
        expiry=$(openssl x509 -in "$cert_path/fullchain.pem" -noout -enddate | cut -d= -f2)
        echo "  Expires: $expiry"
    fi
else
    echo -e "SSL Certificates: ${YELLOW}⚠ Not found${NC}"
fi

if ss -tlnp | grep -q ":443"; then
    echo -e "HTTPS Port (443): ${GREEN}✓ Listening${NC}"
else
    echo -e "HTTPS Port (443): ${RED}✗ Not listening${NC}"
fi
echo ""

# 7. Check Logs for Errors
echo -e "${YELLOW}[7] Recent Error Check${NC}"
echo "----------------------------"

# Backend logs
backend_errors=$(journalctl -u igniet-backend.service -n 20 --no-pager 2>/dev/null | grep -i "error\|failed\|fatal" | wc -l)
if [ "$backend_errors" -eq 0 ]; then
    echo -e "Backend Logs: ${GREEN}✓ No recent errors${NC}"
else
    echo -e "Backend Logs: ${YELLOW}⚠ $backend_errors error(s) in last 20 lines${NC}"
    journalctl -u igniet-backend.service -n 5 --no-pager | grep -i "error\|failed\|fatal" | sed 's/^/  /' || true
fi

# Frontend logs
frontend_errors=$(docker logs igniet-frontend --tail 20 2>&1 | grep -i "error\|failed\|fatal" | wc -l)
if [ "$frontend_errors" -eq 0 ]; then
    echo -e "Frontend Logs: ${GREEN}✓ No recent errors${NC}"
else
    echo -e "Frontend Logs: ${YELLOW}⚠ $frontend_errors error(s) in last 20 lines${NC}"
    docker logs igniet-frontend --tail 5 2>&1 | grep -i "error\|failed\|fatal" | sed 's/^/  /' || true
fi

# Nginx error log
nginx_errors=$(tail -20 /var/log/nginx/igniet-frontend-error.log 2>/dev/null | grep -v "^\s*$" | wc -l)
if [ "$nginx_errors" -eq 0 ]; then
    echo -e "Nginx Logs: ${GREEN}✓ No recent errors${NC}"
else
    echo -e "Nginx Logs: ${YELLOW}⚠ $nginx_errors error(s) in last 20 lines${NC}"
    tail -5 /var/log/nginx/igniet-frontend-error.log | sed 's/^/  /' || true
fi
echo ""

# 8. Resource Usage
echo -e "${YELLOW}[8] Resource Usage${NC}"
echo "----------------------------"
backend_pid=$(systemctl show igniet-backend.service -p MainPID | cut -d= -f2)
if [ "$backend_pid" != "0" ] && [ -n "$backend_pid" ]; then
    backend_mem=$(ps -p "$backend_pid" -o rss= 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
    backend_cpu=$(ps -p "$backend_pid" -o %cpu= 2>/dev/null)
    echo "Backend: Memory: ${backend_mem}, CPU: ${backend_cpu}%"
fi

frontend_stats=$(docker stats igniet-frontend --no-stream --format "Memory: {{.MemUsage}}, CPU: {{.CPUPerc}}" 2>/dev/null)
if [ -n "$frontend_stats" ]; then
    echo "Frontend: $frontend_stats"
fi
echo ""

# 9. Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Summary${NC}"
echo -e "${BLUE}========================================${NC}"

all_good=true

# Check critical services
if ! systemctl is-active --quiet igniet-backend.service; then
    echo -e "${RED}✗ Backend service is not running${NC}"
    all_good=false
fi

if ! docker ps | grep -q igniet-frontend; then
    echo -e "${RED}✗ Frontend container is not running${NC}"
    all_good=false
fi

if ! ss -tlnp | grep -q ":8080"; then
    echo -e "${RED}✗ Backend port 8080 is not listening${NC}"
    all_good=false
fi

if ! ss -tlnp | grep -q ":3000"; then
    echo -e "${RED}✗ Frontend port 3000 is not listening${NC}"
    all_good=false
fi

if ! ss -tlnp | grep -q ":443"; then
    echo -e "${YELLOW}⚠ HTTPS port 443 is not listening${NC}"
    all_good=false
fi

if $all_good; then
    echo -e "\n${GREEN}✓ All services are operational!${NC}\n"
    echo "Website should be accessible at:"
    echo "  https://igniet.kdisc.kerala.gov.in"
else
    echo -e "\n${RED}⚠ Some issues detected. Review the sections above.${NC}\n"
    echo "Common fixes:"
    echo "  - Restart backend: sudo systemctl restart igniet-backend.service"
    echo "  - Restart frontend: cd /data/web_client && sudo ./start_frontend.sh"
    echo "  - View backend logs: sudo journalctl -u igniet-backend.service -f"
    echo "  - View frontend logs: sudo docker logs igniet-frontend -f"
fi

echo ""
echo "For more help, see: /opt/web_server/DEPLOYMENT_UPDATE.md"
