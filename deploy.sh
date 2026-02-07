#!/bin/bash

# Production deployment script
# Usage: ./deploy.sh

set -e

echo "🏗️  Building production binary..."
GOOS=linux GOARCH=amd64 go build -o web_server main.go

echo "📦 Production binary built successfully"
echo ""
echo "📋 Next steps:"
echo "1. Copy binary to production: scp web_server root@10.5.140.242:/opt/web_server/"
echo "2. Copy .env file: scp .env.production root@10.5.140.242:/opt/web_server/.env"
echo "3. Restart service: ssh root@10.5.140.242 'systemctl restart web_server'"
echo ""
echo "Or run the full deployment:"
echo "  scp web_server root@10.5.140.242:/opt/web_server/ && \\"
echo "  scp .env.production root@10.5.140.242:/opt/web_server/.env && \\"
echo "  ssh root@10.5.140.242 'systemctl restart web_server && journalctl -u web_server -n 50 -f'"
