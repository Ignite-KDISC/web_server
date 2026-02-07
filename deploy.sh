#!/bin/bash
set -e

APP_DIR="/opt/web_server"
ENV_FILE="/opt/web_server/.env.production"

echo "🔄 Starting deployment..."

cd "$APP_DIR"

echo "📦 Pulling latest code..."
git pull origin main

echo "🛑 Stopping service..."
systemctl stop web_server

echo "🛠️  Building Go binary..."
go build -o web_server

echo "🔐 Verifying env file..."
if [ ! -f "$ENV_FILE" ]; then
  echo "❌ .env.production not found!"
  exit 1
fi

echo "🚀 Starting service..."
systemctl start web_server

echo "✅ Deployment complete"
echo ""
systemctl status web_server --no-pager
