# IGNIET Quick Debugging Guide

## One-Line Health Check

```bash
sudo /opt/web_server/debug_services.sh
```

This comprehensive script checks all services and provides a detailed status report.

## Quick Service Commands

### Backend Service
```bash
# Status
sudo systemctl status igniet-backend.service

# Restart
sudo systemctl restart igniet-backend.service

# Live logs
sudo journalctl -u igniet-backend.service -f

# Last 50 log lines
sudo journalctl -u igniet-backend.service -n 50 --no-pager
```

### Frontend Container
```bash
# Status
sudo docker ps | grep igniet-frontend

# Restart (rebuild & redeploy)
cd /data/web_client && sudo ./start_frontend.sh

# Live logs
sudo docker logs igniet-frontend -f

# Last 50 log lines
sudo docker logs igniet-frontend --tail 50
```

### Nginx
```bash
# Test config
sudo nginx -t

# Reload config (without downtime)
sudo systemctl reload nginx

# Restart nginx
sudo systemctl restart nginx

# Live error logs
sudo tail -f /var/log/nginx/igniet-frontend-error.log

# Live access logs
sudo tail -f /var/log/nginx/igniet-frontend-access.log
```

## Quick Port Checks

```bash
# Check what's listening on ports
sudo ss -tlnp | grep -E ":(80|443|3000|8080)"

# Find what's using port 8080
sudo ss -tlnp | grep :8080

# Kill process on port 8080 (if stuck)
sudo pkill -9 web_server && sudo systemctl restart igniet-backend.service
```

## Service Test Commands

```bash
# Test backend health
curl http://localhost:8080/health | jq

# Test frontend
curl -I http://localhost:3000/

# Test through nginx (HTTP)
curl -I http://localhost/

# Test API through nginx
curl -X POST http://localhost/api/problem-statements \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

## Common Issues & Fixes

### Issue: Port 8080 already in use
```bash
# Find and kill the conflicting process
sudo pkill -9 web_server
sudo systemctl restart igniet-backend.service

# If there's a duplicate service
sudo systemctl stop web_server.service
sudo systemctl disable web_server.service
sudo systemctl restart igniet-backend.service
```

### Issue: Frontend not responding
```bash
# Check if container is running
sudo docker ps | grep igniet-frontend

# If not running, restart it
cd /data/web_client && sudo ./start_frontend.sh

# Check logs for errors
sudo docker logs igniet-frontend --tail 100
```

### Issue: Mixed Content Errors (HTTP/HTTPS)
```bash
# Ensure .env.production uses HTTPS
cat /data/web_client/.env.production
# Should show: NEXT_PUBLIC_API_URL=https://igniet.kdisc.kerala.gov.in

# If incorrect, fix and rebuild
cd /data/web_client
echo "NEXT_PUBLIC_API_URL=https://igniet.kdisc.kerala.gov.in" | sudo tee .env.production
sudo ./start_frontend.sh
```

### Issue: Nginx 502 Bad Gateway
```bash
# Check if backend is running
sudo systemctl status igniet-backend.service

# Check if frontend is running
sudo docker ps | grep igniet-frontend

# Restart both
sudo systemctl restart igniet-backend.service
cd /data/web_client && sudo ./start_frontend.sh
```

### Issue: SSL Certificate Issues
```bash
# Check certificate expiry
sudo openssl x509 -in /etc/letsencrypt/live/igniet.kdisc.kerala.gov.in/fullchain.pem -noout -enddate

# Renew certificate
sudo certbot renew

# Test nginx config after renewal
sudo nginx -t && sudo systemctl reload nginx
```

## Database Connection Issues

```bash
# Check backend logs for database errors
sudo journalctl -u igniet-backend.service -n 100 | grep -i "database\|postgres"

# Test PostgreSQL connection from backend server
psql -h 10.5.140.242 -U postgres -d igniet -c "SELECT version();"

# Check .env file has correct DB credentials
sudo cat /opt/web_server/.env | grep -E "DB_|POSTGRES_"
```

## Deployment After Code Changes

### Backend Changes
```bash
cd /opt/web_server
git pull
go build -o web_server main.go
sudo systemctl restart igniet-backend.service
sudo journalctl -u igniet-backend.service -f
# Press Ctrl+C when you see "Server starting"
```

### Frontend Changes
```bash
cd /data/web_client
git pull
sudo ./start_frontend.sh
sudo docker logs igniet-frontend -f
# Press Ctrl+C when you see "Ready"
```

## Monitoring Commands

```bash
# Watch all critical ports
watch -n 2 'sudo ss -tlnp | grep -E ":(80|443|3000|8080)"'

# Monitor backend logs in real-time
sudo journalctl -u igniet-backend.service -f

# Monitor frontend logs in real-time
sudo docker logs igniet-frontend -f

# Monitor nginx access logs
sudo tail -f /var/log/nginx/igniet-frontend-access.log

# Monitor system resources
htop  # or: top
```

## Emergency Recovery

If everything is broken:

```bash
# 1. Stop all services
sudo systemctl stop igniet-backend.service web_server.service
sudo docker stop igniet-frontend

# 2. Kill any remaining processes
sudo pkill -9 web_server

# 3. Restart in order
sudo systemctl start igniet-backend.service
cd /data/web_client && sudo ./start_frontend.sh
sudo systemctl reload nginx

# 4. Verify everything is running
sudo /opt/web_server/debug_services.sh
```

## File Locations

- **Backend**: `/opt/web_server/`
- **Frontend**: `/data/web_client/`
- **Nginx Config**: `/etc/nginx/sites-available/igniet.kdisc.kerala.gov.in`
- **SSL Certs**: `/etc/letsencrypt/live/igniet.kdisc.kerala.gov.in/`
- **Backend Service**: `/etc/systemd/system/igniet-backend.service`
- **Uploads**: `/opt/web_server/uploads/`
- **Backups**: `/backup/`
- **Debug Script**: `/opt/web_server/debug_services.sh`

## Get Help

For detailed deployment information, see:
- `/opt/web_server/DEPLOYMENT_UPDATE.md`
- `/opt/web_server/README.md`
