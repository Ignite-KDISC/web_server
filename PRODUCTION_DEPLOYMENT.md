# Production Deployment Guide

## Architecture
- **APP VM**: 10.5.140.241 (runs Go web server)
- **DB VM**: 10.5.140.242 (PostgreSQL database)

## Prerequisites
- SSH access to APP VM (10.5.140.241)
- PostgreSQL database running on 10.5.140.242
- Git repository access from APP VM
- Go installed on APP VM

## Initial Setup (One-time)

### 1. On APP VM (10.5.140.241)

```bash
# SSH into APP VM
ssh root@10.5.140.241

# Clone repository
mkdir -p /opt
cd /opt
git clone https://github.com/Ignite-KDISC/web_server.git
cd web_server

# Create .env file DIRECTLY ON SERVER (NEVER copy from local)
cat > /opt/web_server/.env <<EOF
# Production - connects to PostgreSQL on DB VM
DB_HOST=10.5.140.242
DB_PORT=5432
DB_USER=igniteuser
DB_PASSWORD=ignitepass
DB_NAME=ignite

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=ignietkdisc@gmail.com
SMTP_PASSWORD=lhbz jfus ezvu bcss
SMTP_FROM=ignietkdisc@gmail.com

# Frontend URL for password reset links
FRONTEND_URL=https://igniet.kdisc.kerala.gov.in
EOF

# Set proper permissions
chmod 600 /opt/web_server/.env

# Create uploads directory
mkdir -p /opt/web_server/uploads

# Build the binary
go build -o web_server main.go
```

### 2. Create systemd service

```bash
cat > /etc/systemd/system/web_server.service <<EOF
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

### Local Development (.env in project root)
- DB_HOST=localhost
- FRONTEND_URL=http://localhost:3000
- Go code loads via `godotenv.Load(".env")`

### Production (/opt/web_server/.env)
- DB_HOST=10.5.140.242
- FRONTEND_URL=https://igniet.kdisc.kerala.gov.in
- systemd loads via `EnvironmentFile=/opt/web_server/.env`
- Go code falls back to `os.Getenv()` (provided by systemd)

**Important**: `.env` is created ONLY on the server, never copied from local!

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

SSH into APP VM and run the deploy script:

```bash
ssh root@10.5.140.241
cd /opt/web_server
./deploy.sh
```

The script will:
1. Pull latest code from GitHub
2. Build binary on server
3. Restart the service
4. Show live logs

**Never**: Copy binaries from local, Never copy .env files!

## Database Connection

Make sure PostgreSQL on 10.5.140.242:
- Accepts connections from the production server
- Has the correct database and user created
- pg_hba.conf allows connections from the production server IP
