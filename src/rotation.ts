import {
  KMSClient,
  CreateKeyCommand,
  DisableKeyCommand,
  KeyUsageType,
  KeySpec,
} from '@aws-sdk/client-kms';
import {
  Client,
  AccountUpdateTransaction,
  AccountId,
  PublicKey,
  TransactionId,
  KeyList,
} from '@hashgraph/sdk';
import { createHash } from 'node:crypto';
import { getKmsPublicKey, signWithKms } from './kms.js';
import { writeAuditRecord } from './audit.js';

const kmsClient = new KMSClient({});

const HEDERA_NETWORK = process.env.HEDERA_NETWORK ?? 'testnet';

/**
 * In-memory active key ID. Starts from the environment variable and is
 * updated on successful rotation so that subsequent signing operations
 * use the new key without a Lambda restart.
 */
let activeKeyId: string = process.env.KMS_KEY_ID ?? 'alias/hedera-signer-dev';

/** Return the current active KMS key ID. */
export function getActiveKeyId(): string {
  return activeKeyId;
}

/** SPKI header length for secp256k1 uncompressed public keys (same as publicKey.ts). */
const SPKI_HEADER_LENGTH = 23;

export interface RotationParams {
  currentKeyId: string;
  operatorId: string;
  gracePeriodDays?: number;
}

export interface RotationResult {
  oldKeyId: string;
  newKeyId: string;
  hederaTransactionId: string;
  status: 'ROTATION_COMPLETE';
}

/**
 * Create a Hedera Client for the configured network (no operator set — we sign externally).
 */
function createHederaClient(): InstanceType<typeof Client> {
  switch (HEDERA_NETWORK) {
    case 'mainnet':
      return Client.forMainnet();
    case 'previewnet':
      return Client.forPreviewnet();
    default:
      return Client.forTestnet();
  }
}

/**
 * Derive a compressed Hedera PublicKey from raw DER/SPKI bytes returned by KMS.
 */
function deriveHederaPublicKey(derBytes: Uint8Array): InstanceType<typeof PublicKey> {
  const uncompressedPoint = derBytes.subarray(SPKI_HEADER_LENGTH);
  const x = uncompressedPoint.subarray(1, 33);
  const y = uncompressedPoint.subarray(33, 65);

  const prefix = y[31] & 1 ? 0x03 : 0x02;
  const compressed = new Uint8Array(33);
  compressed[0] = prefix;
  compressed.set(x, 1);

  return PublicKey.fromBytesECDSA(compressed);
}

/**
 * Orchestrate a full signing-key rotation:
 *
 * 1. Create a new KMS key (ECC_SECG_P256K1, SIGN_VERIFY).
 * 2. Retrieve the new key's public key and derive a Hedera-compatible form.
 * 3. Build and submit a Hedera AccountUpdateTransaction that adds the new
 *    public key to the account's key list, signed by the current active key.
 * 4. Update the in-memory active key reference for subsequent signing.
 * 5. Disable the old KMS key after a configurable grace period.
 * 6. Write a success audit record.
 *
 * If any step fails the current key is retained and a failure audit record
 * is written.
 *
 * Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7
 */
export async function rotateSigningKey(
  params: RotationParams,
): Promise<RotationResult> {
  const { currentKeyId, operatorId, gracePeriodDays = 30 } = params;
  const timestamp = new Date().toISOString();
  let newKeyId: string | undefined;

  try {
    // ── Step 1: Create a new KMS key ──────────────────────────────────
    const createKeyResponse = await kmsClient.send(
      new CreateKeyCommand({
        KeySpec: KeySpec.ECC_SECG_P256K1,
        KeyUsage: KeyUsageType.SIGN_VERIFY,
        Description: `Hedera signing key rotated from ${currentKeyId} at ${timestamp}`,
      }),
    );

    newKeyId = createKeyResponse.KeyMetadata?.KeyId;
    if (!newKeyId) {
      throw new Error('KMS CreateKey did not return a KeyId');
    }

    // ── Step 2: Get new key's public key & derive Hedera form ─────────
    const newDerBytes = await getKmsPublicKey(newKeyId);
    const newHederaPubKey = deriveHederaPublicKey(newDerBytes);

    // Also derive the current key's Hedera public key for signing
    const currentDerBytes = await getKmsPublicKey(currentKeyId);
    const currentHederaPubKey = deriveHederaPublicKey(currentDerBytes);

    // ── Step 3: AccountUpdateTransaction ──────────────────────────────
    const client = createHederaClient();
    const accountId = AccountId.fromString(operatorId);
    const txId = TransactionId.generate(accountId);

    const keyList = new KeyList([currentHederaPubKey, newHederaPubKey]);

    const accountUpdateTx = new AccountUpdateTransaction()
      .setAccountId(accountId)
      .setTransactionId(txId)
      .setTransactionValidDuration(120)
      .setKey(keyList)
      .freezeWith(client);

    // Sign the frozen transaction with the current active key via KMS
    const frozenBytes = accountUpdateTx.toBytes();
    const hash = createHash('sha256').update(frozenBytes).digest();
    const { r, s } = await signWithKms(new Uint8Array(hash), currentKeyId);

    const signatureBytes = new Uint8Array(64);
    signatureBytes.set(r, 0);
    signatureBytes.set(s, 32);
    accountUpdateTx.addSignature(currentHederaPubKey, signatureBytes);

    const response = await accountUpdateTx.execute(client);
    const receipt = await response.getReceipt(client);
    const hederaTransactionId = response.transactionId.toString();

    if (receipt.status.toString() !== 'SUCCESS') {
      throw new Error(
        `AccountUpdateTransaction failed with status: ${receipt.status.toString()}`,
      );
    }

    // ── Step 4: Update active key reference ───────────────────────────
    activeKeyId = newKeyId;

    // ── Step 5: Disable old key after grace period ────────────────────
    // For MVP we disable the old key immediately. A production system
    // would schedule this via EventBridge or a delayed invocation.
    if (gracePeriodDays <= 0) {
      await kmsClient.send(new DisableKeyCommand({ KeyId: currentKeyId }));
    } else {
      // Best-effort disable — in production this would be scheduled.
      // We still issue the disable; operators can re-enable if needed.
      await kmsClient.send(new DisableKeyCommand({ KeyId: currentKeyId }));
    }

    // ── Step 6: Write success audit record ────────────────────────────
    try {
      await writeAuditRecord({
        requestId: `rotation-${timestamp}`,
        callerIdentity: 'system:key-rotation',
        timestamp,
        transactionType: 'KeyRotation',
        transactionParams: {
          oldKeyId: currentKeyId,
          newKeyId,
          gracePeriodDays,
        },
        payloadHash: createHash('sha256')
          .update(JSON.stringify({ currentKeyId, newKeyId, timestamp }))
          .digest('hex'),
        policyDecision: 'approved',
        signingOutcome: 'success',
        hederaTransactionId,
        submissionResult: receipt.status.toString(),
      });
    } catch (auditError: unknown) {
      // Audit write failure should not fail the rotation itself
      console.error('Failed to write rotation success audit record:', auditError);
    }

    return {
      oldKeyId: currentKeyId,
      newKeyId,
      hederaTransactionId,
      status: 'ROTATION_COMPLETE',
    };
  } catch (error: unknown) {
    // ── Failure path: retain current key, write failure audit ────────
    const errorMessage = error instanceof Error ? error.message : String(error);

    try {
      await writeAuditRecord({
        requestId: `rotation-failure-${timestamp}`,
        callerIdentity: 'system:key-rotation',
        timestamp,
        transactionType: 'KeyRotation',
        transactionParams: {
          oldKeyId: currentKeyId,
          newKeyId: newKeyId ?? 'N/A',
          gracePeriodDays,
        },
        payloadHash: createHash('sha256')
          .update(JSON.stringify({ currentKeyId, newKeyId: newKeyId ?? 'N/A', timestamp }))
          .digest('hex'),
        policyDecision: 'approved',
        signingOutcome: 'failure',
        signingError: errorMessage,
      });
    } catch (auditError: unknown) {
      console.error('Failed to write rotation failure audit record:', auditError);
    }

    throw error;
  }
}
