#!/bin/bash
API="https://wgl3tiryug.execute-api.us-east-1.amazonaws.com"
CLIENT_ID="4tb6j0jsnclal4iigsrntdgdah"
EMAIL="hashmiumar.work@gmail.com"
PASS="HederaKms2025Secure!"

# Get fresh token
AUTH_JSON=$(aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id "$CLIENT_ID" \
  --auth-parameters USERNAME="$EMAIL",PASSWORD="$PASS" \
  --region us-east-1 \
  --output json 2>&1)

ID_TOKEN=$(echo "$AUTH_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['AuthenticationResult']['IdToken'])")

echo "=== TEST 1: GET /docs (no auth) ==="
curl -s -w "\nHTTP_STATUS: %{http_code}\n" "$API/docs" | tail -5
echo ""

echo "=== TEST 2: GET /public-key (with auth) ==="
curl -s -w "\nHTTP_STATUS: %{http_code}\n" -H "Authorization: Bearer $ID_TOKEN" "$API/public-key"
echo ""

echo "=== TEST 3: GET /public-key (no auth - should 401) ==="
curl -s -w "\nHTTP_STATUS: %{http_code}\n" "$API/public-key"
echo ""

UUID1=$(python3 -c "import uuid; print(uuid.uuid4())")
echo "=== TEST 4: POST /sign-transfer (valid request, UUID=$UUID1) ==="
curl -s -w "\nHTTP_STATUS: %{http_code}\n" \
  -X POST \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$UUID1\",\"senderAccountId\":\"0.0.8291501\",\"recipientAccountId\":\"0.0.1234\",\"amountHbar\":1,\"memo\":\"kiro test\"}" \
  "$API/sign-transfer"
echo ""

UUID2=$(python3 -c "import uuid; print(uuid.uuid4())")
echo "=== TEST 5: POST /sign-transfer (bad schema - missing fields) ==="
curl -s -w "\nHTTP_STATUS: %{http_code}\n" \
  -X POST \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$UUID2\"}" \
  "$API/sign-transfer"
echo ""

UUID3=$(python3 -c "import uuid; print(uuid.uuid4())")
echo "=== TEST 6: POST /sign-transfer (policy denied - bad recipient) ==="
curl -s -w "\nHTTP_STATUS: %{http_code}\n" \
  -X POST \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$UUID3\",\"senderAccountId\":\"0.0.8291501\",\"recipientAccountId\":\"0.0.9999999\",\"amountHbar\":1,\"memo\":\"bad recipient\"}" \
  "$API/sign-transfer"
echo ""

UUID4=$(python3 -c "import uuid; print(uuid.uuid4())")
echo "=== TEST 7: POST /sign-transfer (policy denied - over max 5 HBAR) ==="
curl -s -w "\nHTTP_STATUS: %{http_code}\n" \
  -X POST \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$UUID4\",\"senderAccountId\":\"0.0.8291501\",\"recipientAccountId\":\"0.0.1234\",\"amountHbar\":99999,\"memo\":\"too much\"}" \
  "$API/sign-transfer"
echo ""

echo "=== TEST 8: Idempotency - replay same UUID=$UUID1 ==="
curl -s -w "\nHTTP_STATUS: %{http_code}\n" \
  -X POST \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$UUID1\",\"senderAccountId\":\"0.0.8291501\",\"recipientAccountId\":\"0.0.1234\",\"amountHbar\":1,\"memo\":\"kiro test\"}" \
  "$API/sign-transfer"
echo ""

echo "=== DONE ==="
