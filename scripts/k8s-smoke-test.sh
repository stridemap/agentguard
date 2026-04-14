#!/usr/bin/env bash
# AgentGuard Kubernetes Smoke Test
#
# Verifies a deployed AgentGuard cluster is functional.
# Usage: ./scripts/k8s-smoke-test.sh [API_URL]
#
# Prerequisites: curl, jq

set -euo pipefail

API_URL="${1:-http://localhost:8000}"
ADMIN_KEY="${AGENTGUARD_ADMIN_KEY:-admin-key-dev}"

echo "=== AgentGuard K8s Smoke Test ==="
echo "API URL: $API_URL"
echo ""

PASS=0
FAIL=0

check() {
    local name="$1"
    local result="$2"
    if [ "$result" = "true" ]; then
        echo "  [PASS] $name"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $name"
        FAIL=$((FAIL + 1))
    fi
}

# 1. Health endpoint
echo "--- Health Check ---"
HEALTH=$(curl -sf "$API_URL/health" 2>/dev/null || echo '{}')
HEALTH_STATUS=$(echo "$HEALTH" | jq -r '.status // "unknown"')
check "GET /health returns 200" "$([ "$HEALTH_STATUS" != "unknown" ] && echo true || echo false)"
check "Health status is healthy" "$([ "$HEALTH_STATUS" = "healthy" ] && echo true || echo false)"

# 2. Metrics endpoint
echo "--- Metrics ---"
METRICS=$(curl -sf "$API_URL/metrics" 2>/dev/null || echo '')
check "GET /metrics returns text" "$([ -n "$METRICS" ] && echo true || echo false)"
check "Metrics contain agentguard_version" "$(echo "$METRICS" | grep -q 'agentguard_version' && echo true || echo false)"

# 3. Auth token
echo "--- Authentication ---"
TOKEN_RESP=$(curl -sf -X POST "$API_URL/auth/token" \
    -H "Content-Type: application/json" \
    -d "{\"api_key\": \"$ADMIN_KEY\"}" 2>/dev/null || echo '{}')
TOKEN=$(echo "$TOKEN_RESP" | jq -r '.access_token // ""')
check "POST /auth/token returns JWT" "$([ -n "$TOKEN" ] && [ "$TOKEN" != "" ] && echo true || echo false)"

if [ -n "$TOKEN" ] && [ "$TOKEN" != "" ]; then
    # 4. Query events
    echo "--- Events API ---"
    EVENTS=$(curl -sf -X POST "$API_URL/events" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"limit": 5}' 2>/dev/null || echo 'error')
    check "POST /events returns 200" "$([ "$EVENTS" != "error" ] && echo true || echo false)"

    # 5. Audit chain
    echo "--- Audit Chain ---"
    AUDIT=$(curl -sf "$API_URL/audit/verify" \
        -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo '{}')
    VALID=$(echo "$AUDIT" | jq -r '.is_valid // "unknown"')
    check "GET /audit/verify returns result" "$([ "$VALID" != "unknown" ] && echo true || echo false)"

    # 6. Policies
    echo "--- Policies ---"
    POLICIES=$(curl -sf "$API_URL/policies" \
        -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo 'error')
    check "GET /policies returns 200" "$([ "$POLICIES" != "error" ] && echo true || echo false)"

    # 7. OpenAPI docs
    echo "--- Docs ---"
    DOCS=$(curl -sf "$API_URL/openapi.json" 2>/dev/null || echo '{}')
    TITLE=$(echo "$DOCS" | jq -r '.info.title // ""')
    check "OpenAPI docs accessible" "$([ "$TITLE" = "AgentGuard API" ] && echo true || echo false)"

    # 8. SSO config
    echo "--- SSO ---"
    SSO=$(curl -sf "$API_URL/sso/config" 2>/dev/null || echo '{}')
    check "GET /sso/config returns 200" "$(echo "$SSO" | jq -r '.provider' >/dev/null 2>&1 && echo true || echo false)"
fi

# Summary
echo ""
echo "=== Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "SMOKE TEST FAILED"
    exit 1
else
    echo "SMOKE TEST PASSED"
    exit 0
fi
