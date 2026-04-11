#!/bin/bash
# ── Disable Caddy and switch to Nginx as the primary reverse proxy ──
# Cloudflare terminates HTTPS → Nginx handles HTTP on port 80.
#
# Prerequisites:
#   1. Set Cloudflare SSL/TLS → Overview → "Flexible"
#      (Cloudflare does HTTPS, server does HTTP only)
#   2. Run this script on the server

set -euo pipefail

echo "==> Stopping Caddy..."
sudo systemctl stop caddy
sudo systemctl disable caddy
echo "    Caddy disabled."

echo "==> Pulling latest code..."
cd ~/Personal-SOC
git pull

echo "==> Rebuilding Nginx container (now on port 80)..."
docker compose up -d --build nginx

echo "==> Verifying..."
sleep 2
docker exec sfd_nginx nginx -s reload
curl -sf http://localhost/health > /dev/null && echo "    /health        ✓" || echo "    /health        ✗"
curl -sf http://localhost/api/soc/ai/health > /dev/null && echo "    /api/soc       ✓" || echo "    /api/soc       ✗"
echo ""
echo "Done. Nginx is now the primary reverse proxy on port 80."
echo ""
echo "IMPORTANT: Set Cloudflare SSL/TLS to 'Flexible' if you haven't already."
