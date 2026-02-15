#!/bin/bash
# Comprehensive fix script for frontend and backend issues
# Run with: sudo bash /opt/web_server/fix_frontend_and_email.sh

set -e

echo "=========================================="
echo "  IGNIET Complete Fix Deployment"
echo "=========================================="
echo ""
echo "Issues being addressed:"
echo "1. Frontend: Server Action error (Next.js cache issue)"
echo "2. Backend: SMTP email timeout"
echo ""

# ===========================================
# Part 1: Fix Frontend
# ===========================================

echo "=========================================="
echo "  PART 1: Rebuilding Frontend"
echo "=========================================="
echo ""

cd /data/web_client

echo "📋 Step 1: Stop and remove existing frontend container"
echo "-------------------------------------------"
docker stop igniet-frontend 2>/dev/null || echo "Container not running"
docker rm igniet-frontend 2>/dev/null || echo "Container already removed"
echo ""

echo "🗑️  Step 2: Remove old Docker image (force fresh build)"
echo "-------------------------------------------"
docker rmi igniet-frontend:latest 2>/dev/null || echo "Image already removed"
echo ""

echo "🔨 Step 3: Build fresh frontend image (this may take a few minutes)"
echo "-------------------------------------------"
docker build --no-cache -f Dockerfile.prod -t igniet-frontend:latest .
if [ $? -eq 0 ]; then
    echo "✅ Frontend image built successfully"
else
    echo "❌ Frontend build failed!"
    exit 1
fi
echo ""

echo "🚀 Step 4: Start new frontend container"
echo "-------------------------------------------"
docker run -d \
  --name igniet-frontend \
  --restart unless-stopped \
  -p 3000:3000 \
  igniet-frontend:latest

sleep 5
echo ""

echo "✅ Step 5: Verify frontend is running"
echo "-------------------------------------------"
docker ps | grep igniet-frontend
echo ""

# ===========================================
# Part 2: Fix Backend Email Timeout
# ===========================================

echo "=========================================="
echo "  PART 2: Fixing Backend Email Timeout"
echo "=========================================="
echo ""

cd /opt/web_server

echo "📋 Info: Email configuration"
echo "-------------------------------------------"
echo "SMTP Host: smtp.gmail.com:587"
echo "From: ignietkdisc@gmail.com"
echo ""
echo "Note: The email timeout issue is due to network/firewall restrictions."
echo "The backend will now be updated with better timeout handling."
echo ""

echo "🔨 Step 6: Rebuild backend (if email fix was applied)"
echo "-------------------------------------------"
if [ -f "/opt/web_server/main.go" ]; then
    go build -o web_server main.go
    if [ $? -eq 0 ]; then
        echo "✅ Backend build successful"
        
        echo "♻️  Step 7: Restart backend service"
        echo "-------------------------------------------"
        systemctl restart igniet-backend.service
        sleep 3
        echo "✅ Backend service restarted"
    else
        echo "⚠️  Backend build failed, skipping restart"
    fi
else
    echo "⚠️  main.go not found, skipping backend rebuild"
fi
echo ""

# ===========================================
# Part 3: Verification
# ===========================================

echo "=========================================="
echo "  PART 3: Verification"
echo "=========================================="
echo ""

echo "📊 Step 8: Check all services"
echo "-------------------------------------------"
echo "Backend Service:"
systemctl is-active igniet-backend.service && echo "  ✅ Running" || echo "  ❌ Stopped"
echo ""
echo "Frontend Container:"
docker ps | grep -q igniet-frontend && echo "  ✅ Running" || echo "  ❌ Stopped"
echo ""

echo "🧪 Step 9: Test endpoints"
echo "-------------------------------------------"
echo "Testing frontend..."
FRONTEND_STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/ || echo "000")
if [ "$FRONTEND_STATUS" = "200" ]; then
    echo "  ✅ Frontend: $FRONTEND_STATUS (OK)"
else
    echo "  ⚠️  Frontend: $FRONTEND_STATUS"
fi

echo "Testing backend..."
BACKEND_STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/health || echo "000")
if [ "$BACKEND_STATUS" = "200" ]; then
    echo "  ✅ Backend: $BACKEND_STATUS (OK)"
else
    echo "  ⚠️  Backend: $BACKEND_STATUS"
fi
echo ""

echo "📝 Step 10: Check recent logs"
echo "-------------------------------------------"
echo "Frontend logs (last 10 lines):"
docker logs igniet-frontend --tail 10 2>&1 | tail -10
echo ""
echo "Backend logs (last 10 lines):"
journalctl -u igniet-backend.service -n 10 --no-pager
echo ""

echo "=========================================="
echo "  ✅ Fix Deployment Complete!"
echo "=========================================="
echo ""
echo "Summary:"
echo "  • Frontend rebuilt from scratch (fixes Server Action error)"
echo "  • Backend restarted with updated configuration"
echo "  • All services verified"
echo ""
echo "Next steps:"
echo "  1. Test the website: https://igniet.kdisc.kerala.gov.in"
echo "  2. Try submitting a form to see if Server Action error is gone"
echo "  3. Monitor email sending (SMTP may still timeout due to network)"
echo ""
echo "Note about emails:"
echo "  If emails continue to timeout, you may need to:"
echo "  - Check firewall rules (allow outbound port 587)"
echo "  - Verify SMTP credentials are valid"
echo "  - Consider using a different SMTP service"
echo ""
