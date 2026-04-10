#!/bin/bash
# Test all honeypot endpoints and verify the Watcher detects them.
# Run with Watcher active in background.

BASE="http://localhost:8888"
LOG="test_logs/honeypot_test.log"
> "$LOG"

log() { echo "$@" | tee -a "$LOG"; }

log "=== Honeypot Detection Test ==="
log "Started: $(date)"
log ""

# Get auth token
TOKEN=$(curl -s -X POST "$BASE/identity/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"Passw0rd!"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)

if [ -z "$TOKEN" ]; then
  log "Registering test user first..."
  curl -s -X POST "$BASE/identity/api/auth/signup" \
    -H "Content-Type: application/json" \
    -d '{"name":"Test Attacker","email":"attacker@test.com","password":"Passw0rd!","number":"1234567890"}' > /dev/null
  TOKEN=$(curl -s -X POST "$BASE/identity/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@test.com","password":"Passw0rd!"}' | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
fi
log "Token: ${TOKEN:0:30}..."
log ""

# ── Identity honeypots ────────────────────────────────────────────
log "== Identity Service Honeypots =="

log "  /identity/api/v3/admin/users:"
curl -s "$BASE/identity/api/v3/admin/users" | python3 -m json.tool 2>/dev/null | head -10 | tee -a "$LOG"
log ""

log "  /identity/api/v3/admin/config:"
curl -s "$BASE/identity/api/v3/admin/config" | python3 -m json.tool 2>/dev/null | head -10 | tee -a "$LOG"
log ""

log "  /identity/api/debug/tokens:"
curl -s "$BASE/identity/api/debug/tokens" | python3 -m json.tool 2>/dev/null | head -8 | tee -a "$LOG"
log ""

log "  /identity/api/internal/health:"
curl -s "$BASE/identity/api/internal/health" | python3 -m json.tool 2>/dev/null | head -8 | tee -a "$LOG"
log ""

log "  Honeypot user login (superadmin@vehitrack.io):"
curl -s -X POST "$BASE/identity/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"superadmin@vehitrack.io","password":"wrongpass"}' | tee -a "$LOG"
log ""

# ── Workshop honeypots ────────────────────────────────────────────
log ""
log "== Workshop Service Honeypots =="

log "  /workshop/api/internal/config:"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/workshop/api/internal/config" | python3 -m json.tool 2>/dev/null | head -10 | tee -a "$LOG"
log ""

log "  /workshop/api/internal/database/export:"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/workshop/api/internal/database/export" | python3 -m json.tool 2>/dev/null | head -8 | tee -a "$LOG"
log ""

log "  /workshop/api/internal/coupons/generate:"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/workshop/api/internal/coupons/generate" | python3 -m json.tool 2>/dev/null | head -8 | tee -a "$LOG"
log ""

log "  /workshop/api/internal/orders/bulk-refund:"
curl -s -X POST -H "Authorization: Bearer $TOKEN" "$BASE/workshop/api/internal/orders/bulk-refund" | python3 -m json.tool 2>/dev/null | head -6 | tee -a "$LOG"
log ""

log "  /workshop/api/internal/users/export:"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/workshop/api/internal/users/export" | python3 -m json.tool 2>/dev/null | head -10 | tee -a "$LOG"
log ""

# ── Community honeypots ───────────────────────────────────────────
log ""
log "== Community Service Honeypots =="

log "  /community/api/v2/admin/moderate:"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/community/api/v2/admin/moderate" | python3 -m json.tool 2>/dev/null | head -10 | tee -a "$LOG"
log ""

log "  /community/api/v2/admin/users:"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/community/api/v2/admin/users" | python3 -m json.tool 2>/dev/null | head -10 | tee -a "$LOG"
log ""

log "  /community/api/v2/internal/export:"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/community/api/v2/internal/export" | python3 -m json.tool 2>/dev/null | head -8 | tee -a "$LOG"
log ""

log "  /community/api/v2/debug/db:"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/community/api/v2/debug/db" | python3 -m json.tool 2>/dev/null | head -8 | tee -a "$LOG"
log ""

# ── Nginx-level honeypots ─────────────────────────────────────────
log ""
log "== Nginx-level Honeypots =="

log "  /.env:"
curl -s "$BASE/.env" | tee -a "$LOG"
log ""

log "  /.git:"
curl -s "$BASE/.git" | tee -a "$LOG"
log ""

log "  /admin/debug:"
curl -s "$BASE/admin/debug" | tee -a "$LOG"
log ""

# ── Honeypot data usage (using fake tokens from honeypot responses) ──
log ""
log "== Honeypot Data Usage =="

log "  Using fake debug token from /v3/admin/users:"
curl -s -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi-HONEYPOT-TOKEN" \
  "$BASE/identity/api/v2/user/dashboard" | head -c 100 | tee -a "$LOG"
log ""

log "  Using honeypot coupon code:"
curl -s -X POST "$BASE/workshop/api/shop/apply_coupon" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code":"VTRK-INTERNAL-100","amount":10}' | tee -a "$LOG"
log ""

log "  Using decoy web API key:"
curl -s -H "X-Api-Key: vtrk-web-f84a2c01" "$BASE/identity/api/v2/user/dashboard" | head -c 100 | tee -a "$LOG"
log ""

# ── Normal traffic (should NOT trigger) ───────────────────────────
log ""
log "== Normal Traffic (should not trigger) =="
for i in $(seq 1 5); do
  curl -s "$BASE/" > /dev/null
  curl -s -H "Authorization: Bearer $TOKEN" "$BASE/identity/api/v2/user/dashboard" > /dev/null
  curl -s -H "Authorization: Bearer $TOKEN" "$BASE/workshop/api/shop/products" > /dev/null
  curl -s -H "Authorization: Bearer $TOKEN" "$BASE/community/api/v2/community/posts/recent" > /dev/null
done
log "  20 normal requests sent"

log ""
log "=== Honeypot Test Complete ==="
log "Finished: $(date)"
