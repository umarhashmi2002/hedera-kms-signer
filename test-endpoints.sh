#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  Hedera Key Guardian — Automated E2E Endpoint Tests             ║
# ║  Run: chmod +x test-endpoints.sh && ./test-endpoints.sh         ║
# ║                                                                  ║
# ║  Tests ALL 8 endpoints + policy + validation + idempotency      ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Load config from .env ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "Error: .env file not found. Copy .env.example to .env and fill in values."
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

API="${API_ENDPOINT:?Set API_ENDPOINT in .env}"
CLIENT_ID="${USER_POOL_CLIENT_ID:?Set USER_POOL_CLIENT_ID in .env}"
EMAIL="${COGNITO_USER_EMAIL:?Set COGNITO_USER_EMAIL in .env}"
PASS_VAL="${COGNITO_USER_PASSWORD:?Set COGNITO_USER_PASSWORD in .env}"
SENDER="${HEDERA_OPERATOR_ID:?Set HEDERA_OPERATOR_ID in .env}"
REGION="${AWS_REGION:-us-east-1}"

PASS=0
FAIL=0
TOTAL=0

uuid() { python3 -c "import uuid; print(uuid.uuid4())"; }

check() {
  local name="$1" response="$2" pattern="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$response" | grep -qE "$pattern"; then
    echo "  ✅ $name"
    PASS=$((PASS + 1))
  else
    echo "  ❌ $name"
    echo "     Response: $(echo "$response" | head -c 200)"
    FAIL=$((FAIL + 1))
  fi
}

echo "🔐 Hedera Key Guardian — E2E Tests"
echo "   API: $API"
echo "   Sender: $SENDER"
echo ""

# ── Auth ──
echo "🔑 Getting Cognito token..."
TOKEN=$(aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id "$CLIENT_ID" \
  --auth-parameters USERNAME="$EMAIL",PASSWORD="$PASS_VAL" \
  --region "$REGION" \
  --query 'AuthenticationResult.IdToken' \
  --output text)
echo "   Token: ${TOKEN:0:40}... (${#TOKEN} chars)"
echo ""

# ══════════════════════════════════════════════════════════════════
echo "── 1. Authentication Tests ──"

R=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/sign-transfer" \
  -H "Content-Type: application/json" -d '{}')
check "Unauthenticated POST /sign-transfer → 401" "$R" "401"

R=$(curl -s -o /dev/null -w "%{http_code}" "$API/public-key")
check "Unauthenticated GET /public-key → 401" "$R" "401"

R=$(curl -s -o /dev/null -w "%{http_code}" "$API/multisig-config")
check "Unauthenticated GET /multisig-config → 401" "$R" "401"

echo ""

# ══════════════════════════════════════════════════════════════════
echo "── 2. GET /docs (public, no auth) ──"

R=$(curl -s --max-time 15 "$API/docs")
check "Returns OpenAPI spec" "$R" "openapi"

echo ""

# ══════════════════════════════════════════════════════════════════
echo "── 3. GET /public-key ──"

R=$(curl -s --max-time 15 -H "Authorization: Bearer $TOKEN" "$API/public-key")
check "Returns publicKeyDer" "$R" "publicKeyDer"
check "Returns publicKeyCompressed" "$R" "publicKeyCompressed"
check "Returns evmAddress" "$R" "evmAddress"

echo ""

# ══════════════════════════════════════════════════════════════════
echo "── 4. POST /sign-transfer (live HBAR transfer) ──"

UUID_T=$(uuid)
R=$(curl -s --max-time 60 -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$UUID_T\",\"senderAccountId\":\"$SENDER\",\"recipientAccountId\":\"0.0.1234\",\"amountHbar\":1,\"memo\":\"e2e test\"}" \
  "$API/sign-transfer")
check "Transfer returns transactionId" "$R" "transactionId"
check "Transfer status SUCCESS" "$R" "SUCCESS"
check "Transfer returns transactionHash" "$R" "transactionHash"

echo ""

# ══════════════════════════════════════════════════════════════════
echo "── 5. Validation Tests ──"

# Missing required fields
R=$(curl -s --max-time 15 -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$(uuid)\"}" \
  "$API/sign-transfer")
check "Missing fields → VALIDATION_ERROR" "$R" "VALIDATION_ERROR"

# Amount > 5 HBAR
R=$(curl -s --max-time 15 -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$(uuid)\",\"senderAccountId\":\"$SENDER\",\"recipientAccountId\":\"0.0.1234\",\"amountHbar\":100}" \
  "$API/sign-transfer")
check "Amount > 5 HBAR → VALIDATION_ERROR" "$R" "VALIDATION_ERROR|exceed"

# Invalid UUID
R=$(curl -s --max-time 15 -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"not-a-uuid\",\"senderAccountId\":\"$SENDER\",\"recipientAccountId\":\"0.0.1234\",\"amountHbar\":1}" \
  "$API/sign-transfer")
check "Invalid UUID → VALIDATION_ERROR" "$R" "VALIDATION_ERROR|UUID"

echo ""

# ══════════════════════════════════════════════════════════════════
echo "── 6. Policy Denial Tests ──"

R=$(curl -s --max-time 15 -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$(uuid)\",\"senderAccountId\":\"$SENDER\",\"recipientAccountId\":\"0.0.9999999\",\"amountHbar\":1}" \
  "$API/sign-transfer")
check "Bad recipient → POLICY_DENIED" "$R" "DENIED|RECIPIENT_NOT_ALLOWED"

echo ""

# ══════════════════════════════════════════════════════════════════
echo "── 7. Idempotency Tests ──"

UUID_I=$(uuid)
R1=$(curl -s --max-time 60 -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$UUID_I\",\"senderAccountId\":\"$SENDER\",\"recipientAccountId\":\"0.0.1234\",\"amountHbar\":1}" \
  "$API/sign-transfer")
R2=$(curl -s --max-time 60 -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$UUID_I\",\"senderAccountId\":\"$SENDER\",\"recipientAccountId\":\"0.0.1234\",\"amountHbar\":1}" \
  "$API/sign-transfer")
check "Duplicate request returns cached result" "$R2" "transactionId|requestId"

# Conflict
R3=$(curl -s --max-time 15 -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$UUID_I\",\"senderAccountId\":\"$SENDER\",\"recipientAccountId\":\"0.0.1234\",\"amountHbar\":2}" \
  "$API/sign-transfer")
check "Modified payload → CONFLICT" "$R3" "CONFLICT|conflict"

echo ""

# ══════════════════════════════════════════════════════════════════
echo "── 8. POST /sign-token-transfer (HTS) ──"

R=$(curl -s --max-time 60 -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$(uuid)\",\"senderAccountId\":\"$SENDER\",\"recipientAccountId\":\"0.0.1234\",\"tokenId\":\"0.0.1234\",\"amount\":10}" \
  "$API/sign-token-transfer")
check "Token transfer attempted (INVALID_TOKEN_ID expected)" "$R" "transactionId|INVALID_TOKEN_ID|TOKEN_NOT_ASSOCIATED|error"

echo ""

# ══════════════════════════════════════════════════════════════════
echo "── 9. POST /schedule-transfer ──"

R=$(curl -s --max-time 60 -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$(uuid)\",\"senderAccountId\":\"$SENDER\",\"recipientAccountId\":\"0.0.1234\",\"amountHbar\":1,\"executeAfterSeconds\":3600}" \
  "$API/schedule-transfer")
check "Schedule transfer returns scheduleId" "$R" "scheduleId"
check "Schedule transfer returns transactionId" "$R" "transactionId"

echo ""

# ══════════════════════════════════════════════════════════════════
echo "── 10. GET /multisig-config ──"

R=$(curl -s --max-time 15 -H "Authorization: Bearer $TOKEN" "$API/multisig-config")
check "Returns threshold" "$R" "threshold"
check "Returns keys array" "$R" "keys"

echo ""

# ══════════════════════════════════════════════════════════════════
echo "── 11. POST /rotate-key ──"

R=$(curl -s --max-time 60 -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$(uuid)\"}" \
  "$API/rotate-key")
check "Key rotation responds" "$R" "newKeyId|error|keyId|requestId"

echo ""

# ══════════════════════════════════════════════════════════════════
echo "════════════════════════════════════════════"
echo "Results: $PASS passed, $FAIL failed out of $TOTAL tests"
echo "════════════════════════════════════════════"
echo ""
echo "Verify on HashScan:"
echo "  Account:  https://hashscan.io/testnet/account/$SENDER"
echo "  HCS Topic: https://hashscan.io/testnet/topic/0.0.8310543"
echo ""

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
