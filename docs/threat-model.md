# Threat Model — Hedera KMS Signing Backend

## Overview

This document describes the threat model for the Hedera KMS Signing Backend, a serverless system that signs and submits Hedera transactions using AWS KMS-managed keys. The private key never leaves KMS. The system is composed of API Gateway (with Cognito JWT auth), a single Lambda function, AWS KMS (ECC_SECG_P256K1), DynamoDB (immutable audit trail), CloudTrail, and CloudWatch alarms.

**Validates: Requirements 14.1, 14.2, 14.3, 14.4**

---

## 1. Trust Boundaries

The system has five trust boundaries where data crosses between components with different privilege levels:

```
┌─────────────────────────────────────────────────────────────┐
│  External                                                   │
│  ┌──────────┐                                               │
│  │  Client   │──── HTTPS (TLS) ────┐                        │
│  └──────────┘                      │                        │
│                          ┌─────────▼──────────┐             │
│                          │   API Gateway       │             │
│                          │  (Cognito JWT Auth  │             │
│                          │   + Rate Limiting)  │             │
│                          └─────────┬──────────┘             │
│                                    │  TB1                   │
│                          ┌─────────▼──────────────────┐     │
│                          │  Lambda (Signing_Service)   │     │
│                          │                             │     │
│                          │  ┌─────────┐  ┌──────────┐ │     │
│                     TB2  │  │   KMS   │  │ DynamoDB │ │ TB3 │
│                          │  └─────────┘  └──────────┘ │     │
│                          └─────────┬──────────────────┘     │
│                                    │  TB4                   │
│                          ┌─────────▼──────────┐             │
│                          │  Hedera Testnet     │             │
│                          └────────────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

| Boundary | From | To | Transport | Auth Mechanism |
|----------|------|----|-----------|----------------|
| TB1 | Client | API Gateway | HTTPS (TLS termination) | Cognito JWT bearer token |
| TB2 | API Gateway | Lambda | AWS internal invoke | IAM-based invocation |
| TB3 | Lambda | KMS | AWS internal API | IAM policy scoped to specific key + operations |
| TB4 | Lambda | DynamoDB | AWS internal API | IAM policy scoped to specific table + operations |
| TB5 | Lambda | Hedera Network | External HTTPS | Transaction-level authentication via ECDSA signature |

---

## 2. Key Threats

### T1: Unauthorized Key Access

- **Description:** An attacker gains the ability to invoke `kms:Sign` or `kms:GetPublicKey` on the signing key, allowing them to sign arbitrary Hedera transactions.
- **Impact:** Critical — attacker can drain funds or execute unauthorized transactions on the Hedera account.
- **Attack Vectors:** Compromised IAM credentials, overly permissive key policy, lateral movement within the AWS account.

### T2: Private Key Exposure

- **Description:** The ECDSA secp256k1 private key material is extracted, exported, or logged, giving an attacker permanent signing capability outside of KMS.
- **Impact:** Critical — full compromise of the signing capability; attacker can sign offline without detection.
- **Attack Vectors:** KMS misconfiguration allowing `kms:Decrypt` or key export, logging of key material, side-channel attacks.

### T3: Transaction Tampering

- **Description:** A transaction is modified after construction but before submission to Hedera, causing the signed transaction to differ from what was requested.
- **Impact:** High — funds sent to wrong recipient or wrong amount submitted.
- **Attack Vectors:** Man-in-the-middle between Lambda and Hedera, memory corruption, code injection in the Lambda runtime.

### T4: Replay Attacks

- **Description:** A previously signed and submitted transaction is resubmitted, causing duplicate fund transfers.
- **Impact:** High — double-spend or duplicate operations on the Hedera network.
- **Attack Vectors:** Network replay of API requests, reuse of `requestId` with the same or different payload.

### T5: Audit Log Tampering

- **Description:** An attacker modifies or deletes audit records in DynamoDB to cover their tracks after unauthorized activity.
- **Impact:** High — loss of forensic evidence, inability to detect or investigate security incidents.
- **Attack Vectors:** Compromised IAM credentials with DynamoDB write/delete access, direct table manipulation.

### T6: Unauthorized API Access

- **Description:** An unauthenticated or unauthorized caller submits signing requests to the API, bypassing intended access controls.
- **Impact:** High — unauthorized transactions signed and submitted.
- **Attack Vectors:** Stolen or forged JWT tokens, brute-force attacks, API endpoint discovery, missing auth on routes.

### T7: Privilege Escalation

- **Description:** The Lambda execution role or another IAM principal gains permissions beyond what is required, enabling access to additional AWS resources or operations.
- **Impact:** Medium to High — expanded blast radius; attacker could access other KMS keys, DynamoDB tables, or AWS services.
- **Attack Vectors:** Overly permissive IAM policies, policy misconfiguration, role assumption chains.

---

## 3. Mitigations

### 3.1 KMS Key Policy (Mitigates: T1, T2)

- The KMS key (`ECC_SECG_P256K1`) is configured with `keyUsage: SIGN_VERIFY` — no decrypt or export operations are possible.
- The key policy restricts `kms:Sign` and `kms:GetPublicKey` to the Lambda execution role only.
- Private key material never leaves KMS hardware security modules (HSMs).
- No API exists to export the private key from KMS for asymmetric keys.

### 3.2 Least-Privilege IAM (Mitigates: T1, T7)

- The Lambda execution role is granted only:
  - `kms:Sign` and `kms:GetPublicKey` on the specific signing key ARN
  - `dynamodb:PutItem` and `dynamodb:GetItem` on the specific audit table ARN
  - CloudWatch Logs permissions for its own log group
- No wildcard (`*`) resource permissions for KMS or DynamoDB operations.
- Key rotation operations (`kms:CreateKey`, `kms:DisableKey`) are scoped separately.

### 3.3 Conditional DynamoDB Writes (Mitigates: T5)

- All audit records are written with `ConditionExpression: attribute_not_exists(pk) AND attribute_not_exists(sk)`.
- Once written, a record cannot be overwritten or modified — any attempt throws `ConditionalCheckFailedException`.
- The Lambda role has no `dynamodb:DeleteItem` or `dynamodb:UpdateItem` permissions on the audit table.
- DynamoDB TTL is configured for future cleanup (90+ day retention) but does not allow manual deletion.

### 3.4 CloudTrail Monitoring (Mitigates: T1, T5)

- A dedicated CloudTrail trail logs all management events including KMS API calls.
- CloudTrail logs are delivered to an S3 bucket with server-side encryption (SSE) and public access blocked.
- A CloudWatch metric filter detects KMS `Sign` or `GetPublicKey` calls made by any principal other than the Lambda execution role.
- CloudTrail provides an independent, tamper-resistant record of all API activity.

### 3.5 Idempotency Checks (Mitigates: T4)

- Each signing request includes a client-generated `requestId` (UUID).
- Before processing, the handler checks DynamoDB for an existing record with the same `requestId`.
- If found with the same `payloadHash`, the cached response is returned (no re-signing).
- If found with a different `payloadHash`, HTTP 409 Conflict is returned (detects `requestId` reuse with different payload).
- Hedera's own `transactionValidDuration` (120 seconds) provides network-level replay protection.

### 3.6 Rate Limiting (Mitigates: T6)

- API Gateway enforces throttling: 100 requests/second rate limit with 50-request burst limit.
- Rate limiting prevents brute-force attacks and API abuse.
- CloudWatch alarms trigger on high denial rates (>10 denied requests in 5 minutes).

### 3.7 Key Rotation (Mitigates: T2)

- A `POST /rotate-key` endpoint creates a new KMS key, updates the Hedera account key list, and disables the old key.
- Rotation limits the blast radius of a compromised key — even if a key is somehow compromised, it has a limited useful lifetime.
- Rotation events are recorded in the audit trail with old key ID, new key ID, and Hedera transaction ID.
- The old key is scheduled for disabling after a configurable grace period.

### 3.8 Cognito JWT Auth (Mitigates: T6)

- API Gateway uses a Cognito User Pool with JWT authorizer on all authenticated routes.
- JWTs are validated against the Cognito issuer URL and audience (client ID).
- Self-signup is disabled — only operator-provisioned users can authenticate.
- Password policy enforces minimum 12 characters with uppercase, lowercase, digits, and symbols.
- Access tokens expire after 1 hour; refresh tokens after 30 days.

### 3.9 Policy Engine (Mitigates: T3)

- A configurable policy engine evaluates every signing request before KMS is invoked.
- Four rules are enforced:
  1. **Amount limit** — rejects transfers exceeding `POLICY_MAX_AMOUNT_HBAR` (default: 5 HBAR)
  2. **Recipient allowlist** — rejects transfers to accounts not in `POLICY_ALLOWED_RECIPIENTS`
  3. **Transaction type allowlist** — rejects non-`CryptoTransfer` transaction types
  4. **Time-of-day restriction** — rejects requests outside `POLICY_ALLOWED_HOURS_START` to `POLICY_ALLOWED_HOURS_END` (UTC)
- All violations are returned (not just the first), and every policy decision is recorded in the audit trail.
- Transactions are frozen (producing deterministic bytes) before signing, and the payload hash is stored in the audit record for post-hoc verification.

---

## 4. Security Controls Summary

The following table maps each security control to the threats it mitigates:

| Control | Description | Threats Mitigated |
|---------|-------------|-------------------|
| KMS Key Policy | Restricts `kms:Sign` and `kms:GetPublicKey` to Lambda role; `SIGN_VERIFY` usage only; no export | T1, T2 |
| Least-Privilege IAM | Lambda role has minimal permissions scoped to specific resource ARNs | T1, T7 |
| Conditional DynamoDB Writes | `attribute_not_exists` condition prevents audit record overwrites; no delete/update permissions | T4, T5 |
| CloudTrail Monitoring | Logs all KMS and management API calls to encrypted S3 bucket | T1, T5 |
| CloudWatch Alarms | Alerts on non-Lambda KMS usage, high denial rates (>10/5min), Lambda error rate (>5%/5min) | T1, T6 |
| Idempotency Checks | `requestId` + `payloadHash` prevent duplicate processing and detect payload conflicts | T4 |
| Rate Limiting | API Gateway throttling (100 req/s, 50 burst) prevents abuse | T6 |
| Key Rotation | Periodic key rotation via `/rotate-key` limits blast radius of compromise | T2 |
| Cognito JWT Auth | JWT bearer token auth on API Gateway; Cognito User Pool with strong password policy | T6 |
| Policy Engine | Configurable rules (amount, recipient, tx type, hours) block risky transactions | T3, T6 |
| TLS/HTTPS Only | API Gateway enforces encrypted transport for all API traffic | T3, T6 |
| Freeze-Before-Sign | Transactions frozen to deterministic bytes before signing; hash stored in audit | T3 |
| SNS Alert Notifications | Alarm actions notify operators via email for rapid incident response | T1, T6 |
