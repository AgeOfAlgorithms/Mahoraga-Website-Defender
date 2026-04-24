#!/usr/bin/env bash
set -e

# BuildKit enables parallel service builds and better layer caching.
# Historical note: we briefly disabled BuildKit because "--network=host" had
# issues on Docker Desktop with openresty/openresty:alpine, but no Dockerfile
# in this repo uses that flag, and openresty is pulled (not built). If BuildKit
# ever causes a regression on Docker Desktop, flip these back to 0.
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

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

# Build prod images first — shadow services reuse them by tag, so they
# must exist locally before `up` tries to pull them from a registry.
echo "[2/5] Building images..."
docker compose build --parallel crapi-identity crapi-community crapi-workshop crapi-web

echo "      Starting services..."
docker compose up -d

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
