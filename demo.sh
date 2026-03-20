#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  Hedera KMS Signer — Live Demo Script                          ║
# ║  Run: chmod +x demo.sh && ./demo.sh                            ║
# ║                                                                  ║
# ║  Shows: Auth → Public Key → Transfer → Policy → Idempotency    ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Colors ──
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Load config from .env ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "Error: .env file not found at $ENV_FILE"
  echo "Copy .env.example to .env and fill in your values."
  exit 1
fi

# Source .env (handles KEY=VALUE format)
set -a
source "$ENV_FILE"
set +a

API_URL="${API_ENDPOINT:?Set API_ENDPOINT in .env}"
CLIENT_ID="${USER_POOL_CLIENT_ID:?Set USER_POOL_CLIENT_ID in .env}"
USERNAME="${COGNITO_USER_EMAIL:?Set COGNITO_USER_EMAIL in .env}"
PASSWORD="${COGNITO_USER_PASSWORD:?Set COGNITO_USER_PASSWORD in .env}"
SENDER="${HEDERA_OPERATOR_ID:?Set HEDERA_OPERATOR_ID in .env}"
REGION="${AWS_REGION:-us-east-1}"
ALLOWED_RECIPIENT="0.0.1234"
BLOCKED_RECIPIENT="0.0.9999999"

# ── Helpers ──
step_count=0

banner() {
  echo ""
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BOLD}  $1${RESET}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

step() {
  step_count=$((step_count + 1))
  echo ""
  echo -e "${YELLOW}▶ Step ${step_count}: $1${RESET}"
  echo -e "${DIM}  $2${RESET}"
  echo ""
}

talk() {
  echo -e "${GREEN}  💬 $1${RESET}"
}

show_cmd() {
  echo -e "${DIM}  \$ $1${RESET}"
}

expect() {
  echo -e "${CYAN}  ✓ Expected: $1${RESET}"
}

pause() {
  echo ""
  echo -e "${DIM}  Press ENTER to continue...${RESET}"
  read -r
}

pretty_json() {
  if command -v python3 &>/dev/null; then
    python3 -m json.tool 2>/dev/null || cat
  elif command -v jq &>/dev/null; then
    jq '.' 2>/dev/null || cat
  else
    cat
  fi
}

# ══════════════════════════════════════════════════════════════════
#  START DEMO
# ══════════════════════════════════════════════════════════════════

banner "🔐 Hedera KMS Signer — Secure Key Management for Onchain Applications"
echo ""
echo -e "  ${BOLD}Problem:${RESET} Private keys in software = single point of compromise"
echo -e "  ${BOLD}Solution:${RESET} AWS KMS hardware signs Hedera transactions — key never leaves HSM"
echo ""
echo -e "  ${DIM}Client → API Gateway (JWT) → Lambda → KMS Sign → Hedera Testnet${RESET}"
echo -e "  ${DIM}                                     → DynamoDB Audit${RESET}"

pause

# ── Step 1: Unauthorized Request ──
step "Unauthorized Request" "Show that the API rejects unauthenticated calls"
talk "Without a valid JWT token, the API blocks all access."

show_cmd "curl -s -X POST \"\$API_URL/sign-transfer\" -H \"Content-Type: application/json\" -d '{}'"
echo ""

RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/sign-transfer" \
  -H "Content-Type: application/json" \
  -d '{}')

echo -e "  ${RED}HTTP $RESPONSE — Unauthorized${RESET}"
expect "401 — API Gateway enforces Cognito JWT auth on all signing endpoints"

pause

# ── Step 2: Get JWT Token ──
step "Authenticate via Cognito" "Get a JWT token using OAuth2 USER_PASSWORD_AUTH flow"
talk "Cognito manages auth — no shared API keys, tokens expire in 1 hour."

show_cmd "curl -s -X POST https://cognito-idp.us-east-1.amazonaws.com/ ..."
echo ""

TOKEN=$(curl -s -X POST \
  "https://cognito-idp.${REGION}.amazonaws.com/" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth" \
  -d "{
    \"AuthFlow\": \"USER_PASSWORD_AUTH\",
    \"ClientId\": \"$CLIENT_ID\",
    \"AuthParameters\": {
      \"USERNAME\": \"$USERNAME\",
      \"PASSWORD\": \"$PASSWORD\"
    }
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['AuthenticationResult']['IdToken'])" 2>/dev/null)

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo -e "  ${RED}✗ Failed to get token. Check credentials.${RESET}"
  exit 1
fi

TOKEN_PREVIEW="${TOKEN:0:40}..."
echo -e "  ${GREEN}✓ JWT Token: ${TOKEN_PREVIEW}${RESET}"
expect "Valid IdToken from Cognito — self-signup disabled, 12+ char password policy"

pause

# ── Step 3: Public Key ──
step "Retrieve KMS Public Key" "Show that the private key lives in KMS hardware"
talk "We derive compressed, uncompressed, and EVM address from the KMS key."
talk "The private key NEVER leaves AWS KMS hardware (FIPS 140-2 Level 3)."

show_cmd "curl -s \"\$API_URL/public-key\" -H \"Authorization: Bearer \$TOKEN\""
echo ""

PK_RESPONSE=$(curl -s "$API_URL/public-key" \
  -H "Authorization: Bearer $TOKEN")

echo "$PK_RESPONSE" | pretty_json
echo ""
expect "DER, compressed (33 bytes), uncompressed (65 bytes), and EVM address"

pause

# ── Step 4: Successful Transfer ──
step "Sign & Submit Transaction to Hedera" "The core flow — KMS signs, Lambda submits to testnet"
talk "Lambda builds a TransferTransaction, hashes with keccak256, sends digest to KMS."
talk "KMS signs the digest — Lambda attaches signature and submits to Hedera consensus."

UUID1=$(uuidgen | tr '[:upper:]' '[:lower:]')
show_cmd "curl -s -X POST \"\$API_URL/sign-transfer\" -d '{\"requestId\":\"$UUID1\", \"senderAccountId\":\"$SENDER\", \"recipientAccountId\":\"$ALLOWED_RECIPIENT\", \"amountHbar\":1, \"memo\":\"hackathon demo\"}'"
echo ""

TRANSFER_RESPONSE=$(curl -s -X POST "$API_URL/sign-transfer" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"requestId\": \"$UUID1\",
    \"senderAccountId\": \"$SENDER\",
    \"recipientAccountId\": \"$ALLOWED_RECIPIENT\",
    \"amountHbar\": 1,
    \"memo\": \"hackathon demo\"
  }")

echo "$TRANSFER_RESPONSE" | pretty_json
echo ""

TX_ID=$(echo "$TRANSFER_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('transactionId',''))" 2>/dev/null || echo "")
if [ -n "$TX_ID" ] && [ "$TX_ID" != "" ]; then
  echo -e "  ${GREEN}✓ Verify on HashScan: https://hashscan.io/testnet/transaction/$TX_ID${RESET}"
fi
expect "transactionId + status: SUCCESS — verifiable on HashScan"

pause

# ── Step 5: Policy Denial — Bad Recipient ──
step "Policy Engine — Recipient Not Allowed" "Show that the policy engine blocks unauthorized recipients"
talk "Policy engine evaluates BEFORE KMS is invoked — the key can't sign what policy rejects."

UUID2=$(uuidgen | tr '[:upper:]' '[:lower:]')
show_cmd "curl -s -X POST \"\$API_URL/sign-transfer\" -d '{\"recipientAccountId\":\"$BLOCKED_RECIPIENT\", \"amountHbar\":1}'"
echo ""

POLICY_RESPONSE=$(curl -s -X POST "$API_URL/sign-transfer" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"requestId\": \"$UUID2\",
    \"senderAccountId\": \"$SENDER\",
    \"recipientAccountId\": \"$BLOCKED_RECIPIENT\",
    \"amountHbar\": 1,
    \"memo\": \"should be blocked\"
  }")

echo "$POLICY_RESPONSE" | pretty_json
echo ""
expect "403 — RECIPIENT_NOT_ALLOWED. KMS was never invoked."

pause

# ── Step 6: Policy Denial — Amount Too High ──
step "Policy Engine — Amount Exceeds Limit" "Max transfer is 5 HBAR per policy"
talk "Four configurable rules: amount limit, recipient allowlist, tx type, time-of-day."

UUID3=$(uuidgen | tr '[:upper:]' '[:lower:]')
show_cmd "curl -s -X POST \"\$API_URL/sign-transfer\" -d '{\"amountHbar\":100}'"
echo ""

AMOUNT_RESPONSE=$(curl -s -X POST "$API_URL/sign-transfer" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"requestId\": \"$UUID3\",
    \"senderAccountId\": \"$SENDER\",
    \"recipientAccountId\": \"$ALLOWED_RECIPIENT\",
    \"amountHbar\": 100,
    \"memo\": \"too much\"
  }")

echo "$AMOUNT_RESPONSE" | pretty_json
echo ""
expect "400 — Amount exceeds POLICY_MAX_AMOUNT_HBAR (5 HBAR)"

pause

# ── Step 7: Idempotency — Same Request ──
step "Idempotency — Duplicate Request" "Same requestId + same payload = cached result (no re-signing)"
talk "DynamoDB stores every request. Duplicates return the cached response."

UUID4=$(uuidgen | tr '[:upper:]' '[:lower:]')

echo -e "  ${DIM}First call (requestId: ${UUID4:0:8}...):${RESET}"
IDEM_1=$(curl -s -X POST "$API_URL/sign-transfer" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"requestId\": \"$UUID4\",
    \"senderAccountId\": \"$SENDER\",
    \"recipientAccountId\": \"$ALLOWED_RECIPIENT\",
    \"amountHbar\": 1
  }")
echo "$IDEM_1" | pretty_json
echo ""

echo -e "  ${DIM}Second call (same requestId, same payload):${RESET}"
IDEM_2=$(curl -s -X POST "$API_URL/sign-transfer" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"requestId\": \"$UUID4\",
    \"senderAccountId\": \"$SENDER\",
    \"recipientAccountId\": \"$ALLOWED_RECIPIENT\",
    \"amountHbar\": 1
  }")
echo "$IDEM_2" | pretty_json
echo ""
expect "Same result returned — no duplicate transaction on Hedera"

pause

# ── Step 8: Idempotency — Conflict ──
step "Idempotency — Payload Conflict" "Same requestId + different payload = 409 Conflict"
talk "Prevents replay attacks with modified payloads."

echo -e "  ${DIM}Same requestId but amountHbar changed to 2:${RESET}"
CONFLICT=$(curl -s -X POST "$API_URL/sign-transfer" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"requestId\": \"$UUID4\",
    \"senderAccountId\": \"$SENDER\",
    \"recipientAccountId\": \"$ALLOWED_RECIPIENT\",
    \"amountHbar\": 2
  }")
echo "$CONFLICT" | pretty_json
echo ""
expect "409 Conflict — same requestId with different payload is rejected"

pause

# ── Step 9: OpenAPI Docs ──
step "OpenAPI 3.0 Documentation" "Public endpoint — no auth required"
talk "Full API spec importable into Postman or Swagger UI."

show_cmd "curl -s \"\$API_URL/docs\" | head -15"
echo ""

curl -s "$API_URL/docs" | head -15
echo ""
expect "OpenAPI 3.0 YAML spec served from Lambda"

pause

# ── Summary ──
banner "✅ Demo Complete"
echo ""
echo -e "  ${BOLD}What we showed:${RESET}"
echo -e "  ${GREEN}1.${RESET} API rejects unauthenticated requests (Cognito JWT)"
echo -e "  ${GREEN}2.${RESET} KMS public key derivation (private key never leaves hardware)"
echo -e "  ${GREEN}3.${RESET} Live transaction signed via KMS and submitted to Hedera testnet"
echo -e "  ${GREEN}4.${RESET} Policy engine blocks unauthorized recipients and excessive amounts"
echo -e "  ${GREEN}5.${RESET} Idempotency prevents duplicate transactions"
echo -e "  ${GREEN}6.${RESET} Payload conflict detection (409)"
echo -e "  ${GREEN}7.${RESET} OpenAPI docs served publicly"
echo ""
echo -e "  ${BOLD}Key innovation:${RESET} keccak256 + KMS bridge — the Hedera SDK uses keccak256"
echo -e "  for ECDSA signing, not SHA-256. We hash locally, send digest to KMS."
echo ""
echo -e "  ${BOLD}Verify on HashScan:${RESET} https://hashscan.io/testnet/account/$SENDER"
echo ""
echo -e "  ${DIM}109 tests | 9 test files | Property-based testing with fast-check${RESET}"
echo ""
