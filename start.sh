#!/usr/bin/env bash
set -e

echo "=== Mahoraga Defender Agent ==="
echo ""

# Start all services
echo "[1/3] Starting services..."
docker compose up -d --build

# Wait for crAPI to be healthy
echo "[2/3] Waiting for crAPI to be ready..."
until docker compose ps crapi-workshop | grep -q "healthy"; do
    sleep 2
done

# Plant flags (idempotent)
echo "[3/3] Planting flags..."
python3 plant_flags.py

echo ""
echo "=== Ready ==="
echo "  App:        http://localhost:8888"
echo "  Challenge:  http://localhost:8888/challenge"
echo "  Dashboard:  http://localhost:3000"
echo "  Scoreboard: http://localhost:8888/chains/flags/scoreboard"
echo ""
