# Production Deployment Guide

## Prerequisites
- PostgreSQL database running on 10.5.140.242
- Go binary built for production
- Root access to production VM

## Deployment Steps

### 1. Build the Go binary
```bash
cd /home/aagneye/projects/web_server
GOOS=linux GOARCH=amd64 go build -o web_server main.go
```

### 2. Copy files to production server
```bash
# Create directory on production server
ssh root@10.5.140.242 "mkdir -p /opt/web_server"

# Copy binary
scp web_server root@10.5.140.242:/opt/web_server/

# Copy production environment file
scp .env.production root@10.5.140.242:/opt/web_server/.env

# Copy uploads directory structure (if needed)
ssh root@10.5.140.242 "mkdir -p /opt/web_server/uploads"
```

### 3. Create systemd service
```bash
# Copy the service file to production server
sudo tee /etc/systemd/system/web_server.service > /dev/null <<EOF
[Unit]
Description=Ignite KDISC Go Web Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/web_server
EnvironmentFile=/opt/web_server/.env
ExecStart=/opt/web_server/web_server
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

### 4. Start and enable the service
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable web_server

# Start the service
sudo systemctl start web_server

# Check status
sudo systemctl status web_server
```

### 5. View logs
```bash
# View live logs
sudo journalctl -u web_server -f

# View last 100 lines
sudo journalctl -u web_server -n 100
```

## Configuration Files

### Local Development (.env)
- DB_HOST=localhost
- FRONTEND_URL=http://localhost:3000

### Production (/opt/web_server/.env)
- DB_HOST=10.5.140.242
- FRONTEND_URL=https://igniet.kdisc.kerala.gov.in (update with your actual URL)

## Common Commands

```bash
# Restart service after updates
sudo systemctl restart web_server

# Stop service
sudo systemctl stop web_server

# View service status
sudo systemctl status web_server

# View logs
sudo journalctl -u web_server -f
```

## Updating Production

1. Build new binary locally
2. Stop the service: `sudo systemctl stop web_server`
3. Copy new binary to production
4. Start the service: `sudo systemctl start web_server`

## Database Connection

Make sure PostgreSQL on 10.5.140.242:
- Accepts connections from the production server
- Has the correct database and user created
- pg_hba.conf allows connections from the production server IP
