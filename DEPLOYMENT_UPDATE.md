# Deployment Update - Same VM Configuration

## Summary

Successfully updated the deployment to host both Next.js frontend and Go backend on the same VM, removing the need for Vercel deployment.

## Changes Made

### 1. Frontend Setup ✅

**Location:** `/data/web_client`

- Cloned frontend repository from https://github.com/Ignite-KDISC/web_client.git
- Created production Dockerfile (`Dockerfile.prod`) with multi-stage build
- Configured `next.config.ts` to enable standalone output for Docker
- Created `.env.production` with API URL: `http://igniet.kdisc.kerala.gov.in`
- Built and deployed frontend in Docker container on port 3000
- Created `start_frontend.sh` script for easy deployment

**Status:** Frontend running in Docker container `igniet-frontend` on port 3000

### 2. Backend Setup ✅

**Location:** `/opt/web_server`

- Compiled Go backend binary
- Created systemd service `igniet-backend.service`
- Backend runs natively (not in Docker) on port 8080
- Service starts automatically on boot with auto-restart on failure

**Status:** Backend running as systemd service on port 8080

### 3. Nginx Configuration ✅

**Removed:**
- `api.igniet.kdisc.kerala.gov.in` configuration (API subdomain)

**Added:**
- `igniet.kdisc.kerala.gov.in` configuration for main domain
- Routes `/` to frontend container (port 3000)
- Routes `/api` to backend server (port 8080)
- Both services accessible through same domain

**Status:** Nginx configured and reloaded

### 4. Backup System ✅

**Script:** `/opt/web_server/backup_uploads.py`

**Features:**
- Backs up `/opt/web_server/uploads` folder to `/backup`
- Creates timestamped zip files (e.g., `uploads_backup_20260212_154906.zip`)
- Automatically cleans up backups older than 30 days
- Logs to `/var/log/uploads_backup.log`

**Schedule:** Daily at 3:00 AM IST (21:30 UTC)
**Status:** Cron job configured and tested

### 5. Git Commits ✅

**Backend Repository:**
- Committed `backup_uploads.py` script
- Commit: `f5cac64`

**Frontend Repository:**
- Committed `Dockerfile.prod`
- Committed `start_frontend.sh`
- Committed `next.config.ts` with standalone output
- Commit: `ef24eef`

## Architecture

```
                    Internet
                       │
                       ↓
              ┌────────────────┐
              │  Nginx (Port 80) │
              │                 │
              │  igniet.kdisc.  │
              │  kerala.gov.in  │
              └────────┬────────┘
                       │
           ┌───────────┴──────────┐
           │                      │
           ↓                      ↓
   ┌──────────────┐      ┌──────────────┐
   │  Frontend    │      │  Backend     │
   │  (Docker)    │      │  (Native)    │
   │  Port 3000   │      │  Port 8080   │
   │              │      │              │
   │  Next.js     │─────→│  Go Server   │
   └──────────────┘      └──────┬───────┘
                                │
                                ↓
                         ┌─────────────┐
                         │  PostgreSQL │
                         │  Database   │
                         └─────────────┘
```

## Service Management

### Frontend (Docker)

```bash
# Start frontend
cd /data/web_client && sudo ./start_frontend.sh

# Check status
sudo docker ps | grep igniet-frontend

# View logs
sudo docker logs igniet-frontend

# Stop frontend
sudo docker stop igniet-frontend

# Rebuild and restart
cd /data/web_client && sudo ./start_frontend.sh
```

### Backend (Systemd)

```bash
# Start backend
sudo systemctl start igniet-backend.service

# Stop backend
sudo systemctl stop igniet-backend.service

# Restart backend
sudo systemctl restart igniet-backend.service

# Check status
sudo systemctl status igniet-backend.service

# View logs
sudo journalctl -u igniet-backend.service -f

# Rebuild and restart
cd /opt/web_server && go build -o web_server main.go && sudo systemctl restart igniet-backend.service
```

### Nginx

```bash
# Test configuration
sudo nginx -t

# Reload configuration
sudo systemctl reload nginx

# Restart nginx
sudo systemctl restart nginx

# View logs
tail -f /var/log/nginx/igniet-frontend-access.log
tail -f /var/log/nginx/igniet-frontend-error.log
```

### Backup System

```bash
# Run backup manually
sudo python3 /opt/web_server/backup_uploads.py

# View backup files
ls -lh /backup/

# View backup logs
tail -f /var/log/uploads_backup.log

# Edit cron schedule
sudo crontab -e
```

## Verification

All services are running successfully:

- ✅ Frontend: `http://igniet.kdisc.kerala.gov.in` → Docker port 3000
- ✅ Backend: `http://igniet.kdisc.kerala.gov.in/api` → Native port 8080
- ✅ Backup: Scheduled daily at 3:00 AM IST
- ✅ Both services auto-start on system boot

## Network Configuration

- Frontend and backend communicate via localhost (same VM)
- No firewall issues as both services are local
- Frontend makes API calls to the same domain via nginx proxy
- Nginx handles routing based on path (`/` vs `/api`)

## Security Notes

- Backend runs as root (consider creating dedicated user in future)
- Frontend runs in Docker with non-root user (nextjs)
- Backup files stored in `/backup` (consider adding encryption)
- Environment variables loaded from `/opt/web_server/.env`

## Next Steps (Optional)

1. Set up SSL/TLS certificates for HTTPS
2. Configure firewall rules (UFW) to allow only ports 80, 443, and 22
3. Set up log rotation for application logs
4. Create dedicated system user for backend service
5. Set up monitoring and alerting
6. Configure database backups
7. Set up CI/CD pipeline for automated deployments

## Troubleshooting

### Frontend not accessible
```bash
# Check if container is running
sudo docker ps | grep igniet-frontend

# Check logs
sudo docker logs igniet-frontend

# Restart container
cd /data/web_client && sudo ./start_frontend.sh
```

### Backend API errors
```bash
# Check service status
sudo systemctl status igniet-backend.service

# Check logs
sudo journalctl -u igniet-backend.service -n 100

# Check if port 8080 is listening
sudo ss -tlnp | grep :8080
```

### Nginx errors
```bash
# Test configuration
sudo nginx -t

# Check error logs
tail -n 100 /var/log/nginx/igniet-frontend-error.log

# Reload configuration
sudo systemctl reload nginx
```

### Backup not running
```bash
# Check cron job
sudo crontab -l

# Run manually to test
sudo python3 /opt/web_server/backup_uploads.py

# Check logs
cat /var/log/uploads_backup.log
```

## File Locations

- Frontend: `/data/web_client/`
- Backend: `/opt/web_server/`
- Nginx config: `/etc/nginx/sites-available/igniet.kdisc.kerala.gov.in`
- Backup script: `/opt/web_server/backup_uploads.py`
- Backup files: `/backup/`
- Backend service: `/etc/systemd/system/igniet-backend.service`
- Environment: `/opt/web_server/.env`

---

**Deployment Date:** February 12, 2026  
**Status:** ✅ All systems operational
