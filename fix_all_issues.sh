#!/bin/bash
# Complete fix for database migration and service restart
set -e

echo "========================================="
echo "  FIXING DATABASE AND SERVICES"
echo "========================================="
echo ""

# Fix 1: Add missing column to database
echo "📊 Step 1: Adding missing 'assigned_reviewer' column"
echo "---------------------------------------------"
cd /opt/web_server
PGPASSWORD=ignitepass psql -h 10.5.140.242 -U igniteuser -d ignite <<EOF
-- Add assigned_reviewer column if it doesn't exist
ALTER TABLE problem_statements ADD COLUMN IF NOT EXISTS assigned_reviewer VARCHAR(255);

-- Create index
CREATE INDEX IF NOT EXISTS idx_assigned_reviewer ON problem_statements(assigned_reviewer);

-- Verify column exists
\d problem_statements
EOF

if [ $? -eq 0 ]; then
    echo "✅ Database column added successfully"
else
    echo "❌ Database migration failed"
    exit 1
fi
echo ""

# Fix 2: Rebuild backend with NULL field fixes
echo "🔨 Step 2: Rebuilding backend"
echo "---------------------------------------------"
cd /opt/web_server
go build -o web_server main.go
if [ $? -eq 0 ]; then
    echo "✅ Backend built successfully"
else
    echo "❌ Build failed"
    exit 1
fi
echo ""

# Fix 3: Restart backend service
echo "♻️  Step 3: Restarting backend service"
echo "---------------------------------------------"
systemctl restart igniet-backend.service
sleep 3
systemctl status igniet-backend.service --no-pager | head -15
echo ""

# Fix 4: Check and restart frontend if needed
echo "🌐 Step 4: Checking frontend container"
echo "---------------------------------------------"
if docker ps | grep -q igniet-frontend; then
    echo "✅ Frontend container is running"
else
    echo "⚠️  Frontend container not running. Restarting..."
    cd /data/web_client
    ./start_frontend.sh
fi
echo ""

# Fix 5: Test backend endpoint
echo "🧪 Step 5: Testing backend endpoint"
echo "---------------------------------------------"
LOGIN=$(curl -s -X POST "http://localhost:8080/api/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"ignietkdisc@gmail.com","password":"password@123"}')

TOKEN=$(echo "$LOGIN" | jq -r '.token // empty')

if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    echo "✅ Admin login successful"
    
    TEST=$(curl -s "http://localhost:8080/api/admin/problem-statement?id=1" \
      -H "Authorization: Bearer $TOKEN")
    
    if echo "$TEST" | jq -e '.success == true' > /dev/null 2>&1; then
        echo "✅ Problem statement endpoint working!"
        echo "$TEST" | jq '.problem_statement | {id, reference_id, title, submission_status}'
    else
        echo "⚠️  Response:"
        echo "$TEST"
    fi
else
    echo "❌ Login failed"
fi
echo ""

# Fix 6: Test frontend
echo "🌐 Step 6: Testing frontend"
echo "---------------------------------------------"
FRONTEND_STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/)
if [ "$FRONTEND_STATUS" = "200" ]; then
    echo "✅ Frontend responding on port 3000"
else
    echo "⚠️  Frontend returned HTTP $FRONTEND_STATUS"
fi

NGINX_STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://localhost/)
if [ "$NGINX_STATUS" = "200" ]; then
    echo "✅ Nginx routing working"
else
    echo "⚠️  Nginx returned HTTP $NGINX_STATUS"
fi
echo ""

# Summary
echo "========================================="
echo "  FIX SUMMARY"
echo "========================================="
echo ""
systemctl is-active igniet-backend.service && echo "✅ Backend: RUNNING" || echo "❌ Backend: STOPPED"
docker ps | grep -q igniet-frontend && echo "✅ Frontend: RUNNING" || echo "❌ Frontend: STOPPED"
ss -tlnp | grep -q ":443" && echo "✅ HTTPS: Listening" || echo "⚠️  HTTPS: Not listening"
echo ""
echo "Test the website:"
echo "  https://igniet.kdisc.kerala.gov.in"
echo "  https://igniet.kdisc.kerala.gov.in/admin/login"
echo ""
echo "Monitor logs:"
echo "  sudo journalctl -u igniet-backend.service -f"
echo "  sudo docker logs igniet-frontend -f"
echo ""
