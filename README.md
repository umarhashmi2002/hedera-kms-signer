# Hedera KMS Signer

> Secure Key Management for Onchain Applications — a serverless backend that signs and submits Hedera transactions using AWS KMS-managed ECDSA secp256k1 keys. The private key never leaves FIPS 140-2 Level 3 hardware.

```
Client → API Gateway (JWT) → Lambda → KMS Sign → Hedera Testnet
                                    → DynamoDB Audit
```

## The Problem

Private key management is the single biggest security risk in blockchain applications. Enterprises, custodians, and dApp backends face a hard choice: hold keys in software (fast but risky) or use HSMs (secure but complex to integrate with blockchain networks). Most key management solutions are chain-agnostic wrappers that don't understand the signing conventions of specific networks — leading to integration bugs, signature mismatches, and security gaps.

Hedera's ECDSA secp256k1 signing has a specific requirement: the SDK uses **keccak256** (not SHA-256) for hashing transaction bodies before signing. Generic KMS integrations miss this, producing invalid signatures. This project solves that by bridging AWS KMS and Hedera's signing conventions correctly, with a production-grade policy engine and audit trail on top.

## Why This Needs to Be On-Chain (Not Web2)

A traditional Web2 approach would store signing keys in a database or secrets manager and sign transactions server-side. This creates a single point of compromise — if the server is breached, all keys are exposed. More critically, there's no way to prove to the network or third parties that a transaction was authorized through a controlled process.

By anchoring signing to AWS KMS hardware and submitting transactions directly to Hedera's consensus layer:
- The private key **physically cannot be extracted** from KMS hardware — not by admins, not by AWS, not by attackers
- Every transaction is **verified by Hedera consensus nodes** — the network itself enforces that only the KMS-held key can authorize transfers
- The **immutable audit trail** (DynamoDB + CloudTrail) provides cryptographic proof of every signing decision, queryable by compliance teams
- **Policy enforcement happens before signing** — the key can't be used outside the rules, even if the API is compromised

This is fundamentally different from a Web2 signing service: the security guarantee comes from hardware + consensus, not from trusting application code.

## Innovation: What Makes This Different

1. **keccak256 + KMS bridge**: The Hedera SDK uses keccak256 for ECDSA signing, but AWS KMS `ECDSA_SHA_256` expects a pre-hashed digest. We hash with keccak256 locally, then send the digest to KMS with `MessageType=DIGEST`. This is a non-obvious integration that we discovered and solved — most KMS-to-blockchain integrations get this wrong.

2. **Policy-before-sign architecture**: Unlike generic signing services, the policy engine evaluates every request (amount limits, recipient allowlists, time-of-day restrictions, transaction type filtering) *before* the KMS key is ever invoked. The key literally cannot be used to sign a policy-violating transaction.

3. **Immutable audit with idempotency**: Every signing request — approved, denied, or failed — is recorded in DynamoDB with conditional writes (`attribute_not_exists`). Records can't be overwritten or deleted. Duplicate requests return cached results; payload conflicts return 409.

4. **Zero-secret deployment**: The entire stack deploys via `npx cdk deploy` with no secrets to manage. KMS generates the key, Cognito manages auth, DynamoDB stores audit records. No `.env` files with private keys.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────────────────────┐
│   Client     │────▶│  API Gateway     │────▶│  Lambda (Node.js 20.x)         │
│  (curl/      │     │  HTTP API        │     │                                 │
│   Postman/   │     │  + Cognito JWT   │     │  handler.ts  → route dispatch   │
│   frontend)  │     │  + Rate Limiting │     │  schemas.ts  → validation       │
└─────────────┘     └──────────────────┘     │  policy.ts   → policy engine    │
                                              │  hedera.ts   → tx builder       │
                                              │  kms.ts      → KMS signer       │
                                              │  audit.ts    → DynamoDB audit   │
                                              │  publicKey.ts→ key derivation   │
                                              │  rotation.ts → key rotation     │
                                              └──────┬──────┬──────┬───────────┘
                                                     │      │      │
                                              ┌──────▼┐ ┌───▼──┐ ┌─▼──────────┐
                                              │  KMS   │ │ DDB  │ │  Hedera    │
                                              │secp256k│ │Audit │ │  Testnet   │
                                              └────────┘ └──────┘ └────────────┘
```

## Hedera Integration Depth

This project uses Hedera deeply, not superficially:

- **Transaction construction**: Builds `TransferTransaction` objects using the Hedera SDK (v2.81.0), with proper `TransactionId` generation, node account selection, and `transactionValidDuration`
- **External signing via `signWith()`**: Uses the SDK's `signWith()` callback to inject KMS-produced signatures into frozen transactions — handling the keccak256 hashing that the SDK expects for ECDSA secp256k1
- **Account key management**: The Hedera account's key is updated to the KMS-derived compressed public key via `AccountUpdateTransaction`, so the network recognizes KMS as the sole signer
- **Public key derivation**: Derives compressed (33-byte), uncompressed (65-byte), and EVM address formats from the KMS DER/SPKI key — all formats Hedera supports
- **Key rotation on-chain**: `POST /rotate-key` creates a new KMS key, updates the Hedera account's key list, and disables the old key — all in one atomic flow
- **Network-configurable**: Supports testnet, mainnet, and previewnet via environment variable
- **Live on testnet**: Account `0.0.8291501` is actively signing transactions — verifiable on [HashScan](https://hashscan.io/testnet/account/0.0.8291501)

## Ecosystem Impact

This project benefits the Hedera ecosystem by:

- **Lowering the barrier for enterprise adoption**: Enterprises already use AWS KMS for key management. This project shows them how to extend that to Hedera without changing their security posture.
- **Solving a real integration gap**: The keccak256 signing discovery is documented here and in the code — saving future developers from the same `INVALID_SIGNATURE` debugging journey.
- **Providing a reference architecture**: The policy-before-sign pattern, immutable audit trail, and CloudTrail monitoring are reusable patterns for any Hedera backend.
- **Enabling custodial services**: Exchanges, wallets, and custodians can use this pattern to manage Hedera accounts without ever holding private keys in software.


## Design Decisions

| Decision | Rationale |
|----------|-----------|
| AWS KMS `ECC_SECG_P256K1` | Only cloud KMS that supports secp256k1 natively — no custom curves needed |
| keccak256 pre-hashing | Hedera SDK uses keccak256 for ECDSA, not SHA-256. We hash locally, send digest to KMS |
| Single Lambda, multiple routes | Simpler deployment, shared KMS connection pool, lower cold-start overhead |
| DynamoDB conditional writes | `attribute_not_exists` prevents audit tampering — records are write-once |
| Cognito JWT (not API keys) | Standard OAuth2 flow, token expiry, no shared secrets to rotate |
| CDK (not SAM/Terraform) | Type-safe infrastructure, single `npx cdk deploy`, no YAML templating |
| Policy engine in Lambda | Evaluated before KMS is invoked — the key can't sign what the policy rejects |
| `signWith()` over `addSignature()` | Handles multi-node transaction bodies correctly with external signers |

## MVP Features

- **Sign and submit** CryptoTransfer transactions to Hedera via REST API
- **Policy engine** with 4 configurable rules (amount, recipient, hours, tx type)
- **Immutable audit trail** in DynamoDB with idempotency and conflict detection
- **Public key endpoint** returning DER, compressed, uncompressed, and EVM address formats
- **Key rotation** endpoint that creates a new KMS key and updates the Hedera account
- **OpenAPI 3.0 docs** served at `/docs` (no auth required)
- **Monitoring**: CloudWatch alarms, CloudTrail logging, SNS email alerts
- **109 tests** including property-based tests (fast-check) for DER round-trip, signature structure, policy invariants

## Go-To-Market Strategy

**Phase 1 (Current — Hackathon MVP)**:
- Single-account signing backend on Hedera testnet
- Demonstrates the full flow: auth → policy → sign → submit → audit
- Open-source reference implementation

**Phase 2 (Post-Hackathon)**:
- Multi-account support (multiple KMS keys, multiple Hedera accounts)
- Support for additional transaction types (TokenCreate, ContractCall, etc.)
- Web dashboard for policy management and audit log viewing
- Mainnet deployment with production-grade monitoring

**Phase 3 (Scale)**:
- Multi-tenant SaaS offering for custodians and exchanges
- Cross-chain support (Ethereum, Polygon) using the same KMS key
- Compliance reporting (SOC 2, PCI DSS) leveraging CloudTrail + audit trail
- SDK/CLI for developers to integrate signing into their workflows

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/sign-transfer` | JWT | Sign and submit a CryptoTransfer |
| `GET` | `/public-key` | JWT | Get KMS public key (DER, compressed, uncompressed, EVM address) |
| `POST` | `/rotate-key` | JWT | Rotate the signing key |
| `GET` | `/docs` | None | OpenAPI 3.0 spec (YAML) |

## Signing Flow (How It Works)

```
1. Client sends POST /sign-transfer with JWT
2. API Gateway validates the JWT against Cognito
3. Lambda validates the request schema (UUID, account IDs, amount)
4. Lambda checks idempotency (DynamoDB lookup by requestId)
5. Lambda evaluates policy rules:
   - Amount ≤ 5 HBAR?
   - Recipient in allowlist?
   - Transaction type allowed?
   - Within allowed hours (UTC)?
6. Lambda builds a Hedera TransferTransaction and freezes it
7. Lambda keccak256-hashes the frozen transaction body bytes
   (matching the Hedera SDK's ECDSA signing convention)
8. Lambda sends the keccak256 digest to KMS for ECDSA signing
   (MessageType=DIGEST — KMS signs the pre-hashed digest directly)
9. KMS returns a DER signature → Lambda parses to raw (r, s)
10. Lambda attaches the signature to the frozen transaction via signWith()
11. Lambda submits to Hedera testnet and waits for receipt
12. Lambda writes an audit record to DynamoDB
13. Lambda returns { transactionId, status, transactionHash }
```

## Quick Start

### Prerequisites

- Node.js 20+
- AWS CLI v2 (configured with credentials)
- AWS CDK CLI (`npm install -g aws-cdk`)
- A Hedera testnet account ([portal.hedera.com](https://portal.hedera.com))

### 1. Install Dependencies

```bash
cd hedera-kms-signer && npm install
cd infra && npm install
```

### 2. Deploy

```bash
cd hedera-kms-signer/infra
npx cdk bootstrap aws://<ACCOUNT_ID>/<REGION>  # first time only
npx cdk deploy \
  -c hederaNetwork=testnet \
  -c hederaOperatorId=0.0.YOUR_ACCOUNT_ID \
  -c alertEmail=you@example.com
```

### 3. Create a Cognito User

```bash
aws cognito-idp admin-create-user \
  --user-pool-id <USER_POOL_ID> \
  --username you@example.com \
  --temporary-password 'TempPass123!' \
  --user-attributes Name=email,Value=you@example.com Name=email_verified,Value=true

aws cognito-idp admin-set-user-password \
  --user-pool-id <USER_POOL_ID> \
  --username you@example.com \
  --password 'YourSecurePass2025!' \
  --permanent
```

### 4. Get a JWT Token

```bash
aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id <CLIENT_ID> \
  --auth-parameters USERNAME=you@example.com,PASSWORD='YourSecurePass2025!' \
  --output json
```

Extract the `IdToken` — that's your Bearer token.

### 5. Link Your Hedera Account to the KMS Key

```bash
curl -H "Authorization: Bearer $TOKEN" $API_ENDPOINT/public-key
```

Update your Hedera account's key to the `publicKeyCompressed` value from the response. This can be done via the [Hedera Portal](https://portal.hedera.com), the Hedera SDK (`AccountUpdateTransaction`), or by funding the `evmAddress` to auto-create an alias account.

### 6. Test a Transfer

```bash
curl -X POST "$API_ENDPOINT/sign-transfer" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "'$(uuidgen | tr '[:upper:]' '[:lower:]')'",
    "senderAccountId": "0.0.YOUR_ACCOUNT",
    "recipientAccountId": "0.0.ALLOWED_RECIPIENT",
    "amountHbar": 1,
    "memo": "Hello from KMS"
  }'
```

Verify on [HashScan](https://hashscan.io/testnet) by searching the `transactionId`.

## Demo Walkthrough

### Demo 1: Public Key Retrieval
```bash
curl -s -H "Authorization: Bearer $TOKEN" $API_ENDPOINT/public-key | python3 -m json.tool
```
Shows KMS key derivation: DER → compressed → uncompressed → EVM address. Private key never leaves hardware.

### Demo 2: Schema Validation
```bash
curl -s -X POST "$API_ENDPOINT/sign-transfer" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"requestId": "not-a-uuid"}' | python3 -m json.tool
```
Returns `400` with field-level errors. Every input is validated before policy evaluation.

### Demo 3: Policy Engine
```bash
# Recipient not in allowlist → 403 RECIPIENT_NOT_ALLOWED
curl -s -X POST "$API_ENDPOINT/sign-transfer" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "'$(uuidgen | tr '[:upper:]' '[:lower:]')'",
    "senderAccountId": "0.0.8291501",
    "recipientAccountId": "0.0.9999999",
    "amountHbar": 1
  }' | python3 -m json.tool
```

### Demo 4: Successful Transfer
```bash
curl -s -X POST "$API_ENDPOINT/sign-transfer" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "'$(uuidgen | tr '[:upper:]' '[:lower:]')'",
    "senderAccountId": "0.0.8291501",
    "recipientAccountId": "0.0.1234",
    "amountHbar": 1,
    "memo": "Demo transfer"
  }' | python3 -m json.tool
```
Verify on [HashScan Testnet](https://hashscan.io/testnet) — shows sender, recipient, amount, memo, and ECDSA signature.

### Demo 5: Idempotency
```bash
UUID=$(uuidgen | tr '[:upper:]' '[:lower:]')
# First request → 200 + transaction result
# Same UUID, same payload → 200 + cached result
# Same UUID, different payload → 409 Conflict
```

### Demo 6: Audit Trail
```bash
aws dynamodb scan --table-name hedera_signing_audit --region us-east-1 --output json | python3 -m json.tool
```
Every request (approved, denied, failed) is recorded with caller identity, policy decision, and transaction params.

## Policy Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POLICY_MAX_AMOUNT_HBAR` | `5` | Maximum transfer amount per request |
| `POLICY_ALLOWED_RECIPIENTS` | `0.0.1234,0.0.5678` | Comma-separated allowlist |
| `POLICY_ALLOWED_TRANSACTION_TYPES` | `CryptoTransfer` | Allowed tx types |
| `POLICY_ALLOWED_HOURS_START` | `8` | UTC hour when signing is allowed (inclusive) |
| `POLICY_ALLOWED_HOURS_END` | `22` | UTC hour when signing stops (exclusive) |

## Monitoring & Alerts

- **CloudWatch Alarms**: Lambda error rate (>5%), high denial rate (>10/5min), non-Lambda KMS usage
- **CloudTrail**: All KMS API calls logged to encrypted S3
- **SNS Alerts**: Email notifications on alarm triggers
- **Log Retention**: 7-day retention on Lambda and CloudTrail logs

## Running Tests

```bash
cd hedera-kms-signer
npm test
```

109 tests across 9 files:
- Schema validation (edge cases, boundary values)
- Policy engine (all rule combinations)
- KMS signing (DER parsing, retry logic)
- Handler routing (all endpoints, error paths)
- Hedera transaction building
- Audit trail (idempotency, conflict detection)
- Public key derivation and key rotation
- Property-based tests (fast-check): DER round-trip, signature structure, policy invariants, payload hash determinism, EVM address derivation

## Project Structure

```
hedera-kms-signer/
├── src/
│   ├── handler.ts      # Lambda entry point, route dispatch
│   ├── schemas.ts      # Request validation (Zod-style)
│   ├── policy.ts       # Policy engine (amount, recipient, hours, tx type)
│   ├── hedera.ts       # Transaction builder + keccak256 + KMS signing
│   ├── kms.ts          # KMS Sign/GetPublicKey + DER parsing + retry
│   ├── audit.ts        # DynamoDB audit trail (immutable writes)
│   ├── publicKey.ts    # Public key derivation (compressed, EVM address)
│   ├── rotation.ts     # Key rotation orchestration
│   └── __tests__/      # 109 unit + property-based tests
├── docs/
│   ├── openapi.yaml    # OpenAPI 3.0 spec (served at GET /docs)
│   ├── architecture.md # Architecture deep-dive
│   └── threat-model.md # Threat model and security controls
├── infra/
│   ├── lib/hedera-kms-signer-stack.ts  # CDK stack (all AWS resources)
│   └── bin/app.ts                       # CDK app entry point
├── .env                # Deployed stack outputs (local only)
└── test-endpoints.sh   # Integration test script
```

## Security

- Private key never leaves KMS (FIPS 140-2 Level 3)
- Least-privilege IAM: Lambda can only `kms:Sign`, `kms:GetPublicKey`, `dynamodb:PutItem`, `dynamodb:GetItem`
- Cognito JWT auth with strong password policy (12+ chars, mixed case, digits, symbols)
- DynamoDB conditional writes prevent audit record tampering
- CloudTrail monitors all KMS access; alarms on non-Lambda usage
- API Gateway rate limiting (100 req/s, 50 burst)
- All transport over HTTPS/TLS

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Node.js 20.x (Lambda) |
| Language | TypeScript (ESM) |
| Infrastructure | AWS CDK (TypeScript) |
| Signing | AWS KMS `ECC_SECG_P256K1` |
| Auth | Amazon Cognito (JWT) |
| Audit | Amazon DynamoDB |
| API | Amazon API Gateway HTTP API |
| Monitoring | CloudWatch + CloudTrail + SNS |
| Blockchain | Hedera SDK v2.81.0 (testnet) |
| Testing | Vitest + fast-check (property-based) |

## License

MIT
