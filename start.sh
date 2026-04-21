#!/usr/bin/env bash
set -e

echo "=== Mahoraga Defender ==="
echo ""

# Reset crapi-fork to unpatched original
echo "[1/5] Resetting crapi-fork to unpatched original..."
rsync -a --delete crapi-original/ crapi-fork/
echo "  crapi-fork reset from crapi-original"

# Clear stale data from previous sessions
echo "  Clearing logs, events, audit, patches, pipeline..."
rm -f events/*.json audit/*.json patches/*.json pipeline/*.json
: > logs/nginx/access.log 2>/dev/null || true
: > logs/nginx/shadow.log 2>/dev/null || true
: > logs/nginx/error.log 2>/dev/null || true
: > reactive_defender.log 2>/dev/null || true

# Start all services
echo "[2/5] Starting services..."
docker compose up -d --build

# Wait for crAPI to be healthy
echo "[3/5] Waiting for crAPI to be ready..."
until docker compose ps crapi-workshop | grep -q "healthy"; do
    sleep 2
done
until docker compose ps shadow-workshop | grep -q "healthy"; do
    sleep 2
done

# Plant flags (idempotent)
echo "[4/5] Planting prod flags..."
python3 plant_flags.py

echo "[5/5] Planting shadow decoy flags..."
python3 plant_shadow_flags.py

echo ""
echo "=== Ready ==="
echo "  App:        http://localhost:8888"
echo "  Challenge:  http://localhost:8888/challenge"
echo "  Dashboard:  http://localhost:3000"
echo "  Scoreboard: http://localhost:8888/flags/scoreboard"
echo ""
