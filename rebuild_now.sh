#!/bin/bash
# Quick deployment after compilation fix
cd /opt/web_server
go build -o web_server main.go
systemctl restart igniet-backend.service
sleep 3
systemctl status igniet-backend.service --no-pager | head -15
