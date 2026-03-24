# Hedera Key Guardian

> Secure Key Management for Onchain Applications — a serverless backend that signs and submits Hedera transactions using AWS KMS-managed ECDSA secp256k1 keys. The private key never leaves FIPS 140-2 validated HSMs.

## How It Works (Simple Overview)

```mermaid
graph LR
    You[You] -->|1. Send request| API[API Gateway]
    API -->|2. Check identity| Cognito[Cognito]
    API -->|3. Forward| Lambda[Lambda]
    Lambda -->|4. Check rules| Policy[Policy Engine]
    Lambda -->|5. Sign tx| KMS[AWS KMS HSM]
    Lambda -->|6. Submit tx| Hedera[Hedera Network]
    Lambda -->|7. Log it| DDB[DynamoDB]
    Lambda -->|8. Log to chain| HCS[HCS Topic]
```

Your private key lives inside AWS KMS hardware. It never comes out. When you want to send HBAR or tokens on Hedera, you call our API. We check your identity (Cognito JWT), enforce policy rules (amount limits, recipient allowlists), then ask KMS hardware to sign the transaction. The signed transaction goes to Hedera. Everything is logged.

## Documentation

Detailed docs are in the [`docs/`](docs/) folder:

| Document | Description |
|----------|-------------|
| [`docs/architecture.md`](docs/architecture.md) | Full architecture deep-dive with diagrams |
| [`docs/threat-model.md`](docs/threat-model.md) | Threat model and security controls |
| [`docs/openapi.yaml`](docs/openapi.yaml) | OpenAPI 3.0 spec (also served at `GET /docs`) |

## The Problem

Private key management is the single biggest security risk in blockchain applications. Most key management solutions are chain-agnostic wrappers that don't understand the signing conventions of specific networks.

Hedera's ECDSA secp256k1 signing has a specific requirement: the SDK uses **keccak256** (not SHA-256) for hashing transaction bodies before signing. Generic KMS integrations miss this, producing invalid signatures.

This project solves that by bridging AWS KMS and Hedera's signing conventions correctly, with a production-grade policy engine and audit trail on top.

## System Architecture

```mermaid
graph TB
    Client[API Consumer<br/>curl / Postman / Frontend]

    subgraph AWS["AWS Cloud"]
        APIGW[API Gateway HTTP API<br/>HTTPS + JWT Auth + Rate Limiting]
        
        subgraph LambdaBox["Lambda Function - Node.js 20.x"]
            Handler[handler.ts<br/>Route Dispatch]
            Schemas[schemas.ts<br/>Input Validation]
            Policy[policy.ts<br/>Policy Engine]
            HederaMod[hedera.ts<br/>Tx Builder + keccak256]
            KMSMod[kms.ts<br/>KMS Signer]
            AuditMod[audit.ts<br/>Audit Writer]
            PubKeyMod[publicKey.ts<br/>Key Derivation]
            RotationMod[rotation.ts<br/>Key Rotation]
            TokenMod[tokenTransfer.ts<br/>HTS Transfers]
            SchedMod[scheduledTransfer.ts<br/>Scheduled Tx]
            ConsMod[consensus.ts<br/>HCS Logging]
            MultiMod[multisig.ts<br/>Multi-sig Config]
        end

        Cognito[Cognito User Pool<br/>JWT Issuer]
        KMS[(AWS KMS<br/>ECDSA secp256k1<br/>FIPS 140-2 HSM)]
        DDB[(DynamoDB<br/>Audit Trail)]
        CT[CloudTrail]
        CW[CloudWatch Alarms]
        SNS[SNS Alerts]
    end

    HederaNet[Hedera Testnet<br/>Consensus + HCS]

    Client -->|HTTPS| APIGW
    APIGW -->|Validate JWT| Cognito
    APIGW -->|Invoke| Handler
    KMSMod -->|kms:Sign / GetPublicKey| KMS
    AuditMod -->|PutItem / GetItem| DDB
    HederaMod -->|Submit Tx| HederaNet
    ConsMod -->|HCS Message| HederaNet
    CT -->|Monitor KMS calls| CW
    CW -->|Alert| SNS
```


## Transaction Signing Flow

This is the core innovation — how a transaction goes from API request to Hedera consensus:

```mermaid
sequenceDiagram
    participant C as Client
    participant AG as API Gateway
    participant L as Lambda
    participant P as Policy
    participant K as KMS HSM
    participant H as Hedera
    participant A as DynamoDB
    participant HCS as HCS Topic

    C->>AG: POST /sign-transfer + JWT
    AG->>AG: Validate JWT (Cognito)
    AG->>L: Forward request
    L->>L: Validate schema (UUID, accounts, amount)
    L->>A: Check idempotency (requestId lookup)
    A-->>L: Not found (new request)
    L->>P: Evaluate policy rules
    P-->>L: Approved
    L->>L: Build TransferTransaction
    L->>L: Freeze tx, keccak256 hash
    L->>K: Sign digest (ECDSA_SHA_256, DIGEST mode)
    K-->>L: DER signature
    L->>L: Parse DER, raw (r, s)
    L->>L: Attach signature via signWith()
    L->>H: Submit signed tx
    H-->>L: Receipt (SUCCESS) + txId
    L->>A: Write audit record
    L->>HCS: Log to HCS topic
    L-->>C: { transactionId, status, txHash }
```

## Key Innovation: keccak256 + KMS Bridge

```mermaid
graph LR
    A[Frozen Tx Bytes] -->|keccak256 hash| B[32-byte Digest]
    B -->|Send to KMS| C[KMS HSM Signs<br/>ECDSA_SHA_256<br/>MessageType=DIGEST]
    C -->|DER signature| D[Parse ASN.1 DER]
    D -->|Extract r, s| E[Raw Signature]
    E -->|signWith| F[Signed Hedera Tx]
```

The Hedera SDK uses **keccak256** for ECDSA signing, not SHA-256. AWS KMS `ECDSA_SHA_256` expects a pre-hashed digest. We hash with keccak256 locally, then send the 32-byte digest to KMS with `MessageType=DIGEST`. KMS signs it without re-hashing. This is a non-obvious integration that most KMS-to-blockchain projects get wrong.

## Policy Engine

The policy engine evaluates every request BEFORE KMS is invoked. The key literally cannot sign what the policy rejects.

```mermaid
graph TD
    Req[Incoming Request] --> V{Schema Valid?}
    V -->|No| R1[400 VALIDATION_ERROR]
    V -->|Yes| I{Idempotent?}
    I -->|Duplicate same payload| R2[200 Cached Result]
    I -->|Duplicate diff payload| R3[409 CONFLICT]
    I -->|New request| P1{Amount ≤ 5 HBAR?}
    P1 -->|No| DENY[403 POLICY_DENIED]
    P1 -->|Yes| P2{Recipient in allowlist?}
    P2 -->|No| DENY
    P2 -->|Yes| P3{Tx type allowed?}
    P3 -->|No| DENY
    P3 -->|Yes| P4{Within allowed hours?}
    P4 -->|No| DENY
    P4 -->|Yes| SIGN[Sign via KMS, Submit to Hedera]
```

## Security Layers

```mermaid
graph TB
    subgraph Layer1["Layer 1: Network"]
        TLS[HTTPS/TLS Encryption]
        Rate[API Gateway Rate Limiting<br/>100 req/s, 50 burst]
    end
    
    subgraph Layer2["Layer 2: Identity"]
        Cognito[Cognito JWT Auth<br/>1-hour expiry, no self-signup]
        Password[Password Policy<br/>12+ chars, mixed case, digits, symbols]
    end
    
    subgraph Layer3["Layer 3: Application"]
        Schema[Schema Validation<br/>UUID, account IDs, amount limits]
        PolicyEng[Policy Engine<br/>Amount, recipient, tx type, hours]
        Idempotency[Idempotency<br/>DynamoDB conditional writes]
    end
    
    subgraph Layer4["Layer 4: Cryptographic"]
        KMSLayer[AWS KMS HSM<br/>FIPS 140-2 validated]
        NoExport[Private key cannot be exported]
        Keccak[keccak256 pre-hashing]
    end
    
    subgraph Layer5["Layer 5: Audit & Detection"]
        DDBLayer[DynamoDB Immutable Audit]
        HCSLayer[HCS Decentralized Log]
        CTLayer[CloudTrail KMS Monitoring]
        Alarms[CloudWatch Alarms + SNS]
    end

    Layer1 --> Layer2 --> Layer3 --> Layer4 --> Layer5
```

## Token Transfer Flow (HTS)

```mermaid
sequenceDiagram
    participant C as Client
    participant L as Lambda
    participant P as Policy
    participant K as KMS
    participant H as Hedera

    C->>L: POST /sign-token-transfer
    Note over C,L: tokenId, amount, sender, recipient
    L->>L: Validate schema
    L->>P: Evaluate policy (type=TokenTransfer)
    Note over P: Amount check skipped for tokens
    P-->>L: Approved
    L->>L: Build TransferTransaction<br/>+ addTokenTransfer()
    L->>L: Freeze, keccak256 hash
    L->>K: Sign digest via KMS
    K-->>L: DER signature, parse (r,s)
    L->>H: Submit signed tx
    H-->>L: Receipt + txId
    L-->>C: { transactionId, status }
```

## Why This Needs to Be On-Chain

A traditional Web2 approach would store signing keys in a database. This creates a single point of compromise. By anchoring signing to AWS KMS hardware and submitting transactions directly to Hedera's consensus layer:

- The private key **physically cannot be extracted** from KMS hardware
- Every transaction is **verified by Hedera consensus nodes**
- The **immutable audit trail** (DynamoDB + HCS + CloudTrail) provides cryptographic proof of every signing decision
- **Policy enforcement happens before signing** — the key can't be used outside the rules

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/sign-transfer` | JWT | Sign and submit an HBAR transfer |
| `POST` | `/sign-token-transfer` | JWT | Sign and submit an HTS token transfer |
| `POST` | `/schedule-transfer` | JWT | Schedule a transfer for future execution |
| `GET` | `/public-key` | JWT | Get KMS public key (DER, compressed, EVM address) |
| `POST` | `/rotate-key` | JWT | Rotate the signing key |
| `GET` | `/multisig-config` | JWT | View multi-sig / threshold key configuration |
| `POST` | `/create-audit-topic` | JWT | Create an HCS topic for audit logging |
| `GET` | `/docs` | None | OpenAPI 3.0 spec |


## Key Rotation Flow

```mermaid
sequenceDiagram
    participant Op as Operator
    participant L as Lambda
    participant KMS as KMS
    participant H as Hedera
    
    Op->>L: POST /rotate-key
    L->>KMS: CreateKey (new secp256k1)
    KMS-->>L: New Key ID
    L->>KMS: GetPublicKey (new key)
    KMS-->>L: New public key
    L->>L: Build AccountUpdateTransaction
    L->>KMS: Sign with current key
    L->>H: Submit key update
    H-->>L: SUCCESS
    L->>KMS: DisableKey (old key)
    L-->>Op: { oldKeyId, newKeyId, status }
```

## Multi-Signature Support

```mermaid
graph TD
    Account[Hedera Account Key<br/>KeyList threshold=2-of-3]
    Account --> K1[KMS Key<br/>Hot signer - automatic]
    Account --> K2[Cold Key<br/>Hardware wallet - manual]
    Account --> K3[Recovery Key<br/>Break-glass - vault]
```

Configure via environment variables:
```bash
MULTISIG_ENABLED=true
MULTISIG_THRESHOLD=2
MULTISIG_KEYS=kms:<kmsKeyId>:Primary,manual:<coldPubKeyHex>:ColdKey,manual:<recoveryPubKeyHex>:Recovery
```

## Scheduled Transactions

```mermaid
sequenceDiagram
    participant C as Client
    participant L as Lambda
    participant K as KMS
    participant H as Hedera

    C->>L: POST /schedule-transfer<br/>(executeAfterSeconds: 60)
    L->>L: Build inner TransferTransaction
    L->>L: Wrap in ScheduleCreateTransaction
    L->>K: Sign schedule via KMS
    L->>H: Submit schedule
    H-->>L: scheduleId + txId
    L-->>C: { scheduleId, status: SUCCESS }
    Note over H: 60 seconds later...
    H->>H: Auto-execute the transfer
```

## HCS Consensus Audit Logging

```mermaid
graph LR
    Lambda[Lambda] -->|Primary audit| DDB[DynamoDB<br/>Fast + Queryable]
    Lambda -->|Decentralized audit| HCS[HCS Topic<br/>Tamper-proof + Verifiable]
    DDB -.->|Compliance queries| Team[Compliance Team]
    HCS -.->|Public verification| Anyone[Anyone with Topic ID]
```

Every signing decision is logged to both DynamoDB (fast, queryable) and Hedera Consensus Service (tamper-proof, decentralized). HCS messages contain: event type, requestId, status, timestamp, transactionId, and policy violations.

## Monitoring & Security

```mermaid
graph TB
    Lambda[Lambda] -->|Logs| CWLogs[CloudWatch Logs<br/>7-day retention]
    KMS[KMS] -->|API calls| CT[CloudTrail<br/>Encrypted S3]
    CT -->|Metric filter| CW1[Alarm: Non-Lambda KMS usage]
    Lambda -->|Error metric| CW2[Alarm: Lambda errors > 5%]
    Lambda -->|Denial metric| CW3[Alarm: High denial rate]
    CW1 -->|Alert| SNS[Email Alert]
    CW2 -->|Alert| SNS
    CW3 -->|Alert| SNS
```

Three CloudWatch alarms protect the system:
1. Non-Lambda KMS usage (someone else trying to use the signing key)
2. Lambda error rate > 5% in 5 minutes
3. High denial rate > 10 in 5 minutes (possible attack)

## Quick Start

### Prerequisites
- Node.js 20+, AWS CLI v2, AWS CDK CLI
- A Hedera testnet account ([portal.hedera.com](https://portal.hedera.com))

### 1. Install & Deploy
```bash
cd hedera-kms-signer && npm install
cd infra && npm install
npx cdk deploy -c hederaNetwork=testnet -c hederaOperatorId=0.0.YOUR_ACCOUNT -c alertEmail=you@example.com
```

### 2. Create Cognito User
```bash
aws cognito-idp admin-create-user --user-pool-id <POOL_ID> --username you@example.com \
  --temporary-password 'TempPass123!' \
  --user-attributes Name=email,Value=you@example.com Name=email_verified,Value=true
```

### 3. Link Hedera Account to KMS Key
```bash
# Get the KMS public key
curl -H "Authorization: Bearer $TOKEN" $API_ENDPOINT/public-key
# Update your Hedera account's key to the publicKeyCompressed value
```

### 4. Test a Transfer
```bash
curl -X POST "$API_ENDPOINT/sign-transfer" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"requestId":"'$(uuidgen | tr A-Z a-z)'","senderAccountId":"0.0.YOUR_ACCOUNT","recipientAccountId":"0.0.1234","amountHbar":1}'
```

### 5. Run the Demo
```bash
chmod +x demo.sh && ./demo.sh
```

Interactive 13-step demo covering all endpoints with verification links.

### 6. Run Automated Tests
```bash
# Unit tests (143 tests, 13 files)
npm test

# E2E endpoint tests (22 checks against live API)
bash test-endpoints.sh
```


## Design Decisions

| Decision | Rationale |
|----------|-----------|
| AWS KMS `ECC_SECG_P256K1` | Only cloud KMS that supports secp256k1 natively |
| keccak256 pre-hashing | Hedera SDK uses keccak256 for ECDSA, not SHA-256 |
| Single Lambda, multiple routes | Simpler deployment, shared KMS connection pool |
| DynamoDB conditional writes | `attribute_not_exists` prevents audit tampering |
| Cognito JWT (not API keys) | Standard OAuth2 flow, token expiry, no shared secrets |
| CDK (not SAM/Terraform) | Type-safe infrastructure, single `npx cdk deploy` |
| Policy engine in Lambda | Evaluated before KMS — key can't sign what policy rejects |

## Project Structure

```
hedera-kms-signer/
├── src/
│   ├── handler.ts           # Lambda entry point, route dispatch
│   ├── schemas.ts           # Request validation
│   ├── policy.ts            # Policy engine (amount, recipient, hours, tx type)
│   ├── hedera.ts            # Transaction builder + keccak256 + KMS signing
│   ├── tokenTransfer.ts     # HTS token transfer builder
│   ├── scheduledTransfer.ts # Scheduled transaction builder
│   ├── consensus.ts         # HCS consensus event logging
│   ├── kms.ts               # KMS Sign/GetPublicKey + DER parsing
│   ├── audit.ts             # DynamoDB audit trail (immutable writes)
│   ├── publicKey.ts         # Public key derivation
│   ├── rotation.ts          # Key rotation orchestration
│   ├── multisig.ts          # Multi-sig / threshold key config
│   └── __tests__/           # 143 unit + property-based tests
├── docs/
│   ├── architecture.md      # Architecture deep-dive with diagrams
│   ├── threat-model.md      # Threat model and security controls
│   └── openapi.yaml         # OpenAPI 3.0 spec
├── infra/
│   └── lib/hedera-kms-signer-stack.ts  # CDK stack
├── demo.sh                  # Interactive 13-step demo
├── test-endpoints.sh        # Automated E2E tests (22 checks)
└── .env                     # Deployed stack outputs (local only)
```

## Ecosystem Impact

- **Lowers the barrier for enterprise Hedera adoption** — enterprises already use AWS KMS
- **Solves a real integration gap** — the keccak256 signing discovery saves future developers from `INVALID_SIGNATURE` debugging
- **Provides a reference architecture** — policy-before-sign, immutable audit, CloudTrail monitoring are reusable patterns
- **Enables custodial services** — exchanges and wallets can manage Hedera accounts without holding private keys

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Node.js 20.x (Lambda) |
| Language | TypeScript (ESM) |
| Infrastructure | AWS CDK (TypeScript) |
| Signing | AWS KMS `ECC_SECG_P256K1` |
| Auth | Amazon Cognito (JWT) |
| Audit | DynamoDB + HCS |
| API | API Gateway HTTP API |
| Monitoring | CloudWatch + CloudTrail + SNS |
| Blockchain | Hedera SDK v2.81.0 |
| Testing | Vitest + fast-check (property-based) |

## Future Roadmap

```mermaid
timeline
    title Hedera Key Guardian — Roadmap
    section Phase 1 — Hackathon MVP (Done)
        Core Signing : AWS KMS secp256k1 + keccak256 bridge
        Policy Engine : Amount limits, allowlists, hours, tx types
        Audit Trail : DynamoDB + HCS dual logging
        Full API : 8 endpoints with Cognito JWT auth
        Monitoring : CloudTrail + CloudWatch alarms + SNS
        Token & Scheduled Tx : HTS transfers + scheduled execution
    section Phase 2 — Post-Hackathon
        Multi-Account : Manage multiple Hedera accounts per tenant
        Web Dashboard : React UI for signing, audit, policy config
        Mainnet Deployment : Production hardening + mainnet support
        Webhook Notifications : Real-time tx status callbacks
        Policy DSL : Custom policy rules via JSON/YAML config
    section Phase 3 — Scale
        Multi-Tenant SaaS : Isolated KMS keys per tenant, usage billing
        Cross-Chain : Ethereum + Polygon signing via same KMS keys
        Compliance Reporting : SOC 2 audit exports, PDF reports
        SDK & CLI : npm package + CLI for developer integration
        Enterprise SSO : SAML/OIDC federation for Cognito
```

### Go-To-Market Strategy

| Phase | Timeline | Focus | Target Users |
|-------|----------|-------|-------------|
| Phase 1 | Hackathon | Working MVP with full docs | Judges, Hedera devs |
| Phase 2 | 1–3 months | Dashboard + mainnet + multi-account | Early adopters, startups |
| Phase 3 | 3–6 months | Multi-tenant SaaS + cross-chain | Enterprises, exchanges, custodians |

**Phase 1 (Now):** Open-source reference architecture. Developers can fork and deploy in minutes with `npx cdk deploy`. Full test coverage (143 unit tests + 22 E2E tests) and interactive demo.

**Phase 2 (Next):** Add a web dashboard so non-CLI users can manage signing policies, view audit logs, and trigger transactions. Deploy to Hedera mainnet with production-grade monitoring.

**Phase 3 (Scale):** Multi-tenant SaaS where each customer gets isolated KMS keys, DynamoDB tables, and policy configs. Expand to Ethereum/Polygon signing (same secp256k1 keys work). Enterprise compliance features for regulated industries.

## Live on Testnet

- Account: [`0.0.8291501`](https://hashscan.io/testnet/account/0.0.8291501)
- HCS Audit Topic: [`0.0.8310543`](https://hashscan.io/testnet/topic/0.0.8310543)
- API Docs: `GET /docs` (public, no auth)

## License

MIT
