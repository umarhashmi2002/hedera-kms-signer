import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── vi.hoisted mock functions ─────────────────────────────────────────────
const mocks = vi.hoisted(() => ({
  kmsSend: vi.fn(),
  getKmsPublicKey: vi.fn(),
  signWithKms: vi.fn(),
  writeAuditRecord: vi.fn(),
}));

// ── Mock @aws-sdk/client-kms ──────────────────────────────────────────────
vi.mock('@aws-sdk/client-kms', () => ({
  KMSClient: class MockKMSClient {
    send(...args: unknown[]) {
      return mocks.kmsSend(...args);
    }
  },
  CreateKeyCommand: class MockCreateKeyCommand {
    constructor(public input: unknown) {}
  },
  DisableKeyCommand: class MockDisableKeyCommand {
    constructor(public input: unknown) {}
  },
  KeyUsageType: { SIGN_VERIFY: 'SIGN_VERIFY' },
  KeySpec: { ECC_SECG_P256K1: 'ECC_SECG_P256K1' },
}));

// ── Mock @hashgraph/sdk ───────────────────────────────────────────────────
const mockExecute = vi.hoisted(() => vi.fn());
const mockGetReceipt = vi.hoisted(() => vi.fn());
const mockFreeze = vi.hoisted(() => vi.fn());
const mockAddSignature = vi.hoisted(() => vi.fn());
const mockToBytes = vi.hoisted(() => vi.fn());

vi.mock('@hashgraph/sdk', () => {
  const mockTxInstance = {
    setAccountId: vi.fn().mockReturnThis(),
    setTransactionId: vi.fn().mockReturnThis(),
    setTransactionValidDuration: vi.fn().mockReturnThis(),
    setKey: vi.fn().mockReturnThis(),
    freezeWith: vi.fn().mockReturnThis(),
    toBytes: mockToBytes,
    addSignature: mockAddSignature,
    execute: mockExecute,
  };

  return {
    Client: {
      forTestnet: () => ({}),
      forMainnet: () => ({}),
      forPreviewnet: () => ({}),
    },
    AccountUpdateTransaction: class {
      setAccountId = mockTxInstance.setAccountId;
      setTransactionId = mockTxInstance.setTransactionId;
      setTransactionValidDuration = mockTxInstance.setTransactionValidDuration;
      setKey = mockTxInstance.setKey;
      freezeWith = mockTxInstance.freezeWith;
      toBytes = mockTxInstance.toBytes;
      addSignature = mockTxInstance.addSignature;
      execute = mockTxInstance.execute;
    },
    AccountId: { fromString: (s: string) => s },
    PublicKey: { fromBytesECDSA: (b: Uint8Array) => ({ _bytes: b }) },
    TransactionId: { generate: () => 'mock-tx-id' },
    KeyList: class {
      constructor(public keys: unknown[]) {}
    },
  };
});

// ── Mock local modules ────────────────────────────────────────────────────
vi.mock('../kms.js', () => ({
  getKmsPublicKey: mocks.getKmsPublicKey,
  signWithKms: mocks.signWithKms,
}));

vi.mock('../audit.js', () => ({
  writeAuditRecord: mocks.writeAuditRecord,
}));

// ── Import after mocks ───────────────────────────────────────────────────
import { rotateSigningKey, getActiveKeyId } from '../rotation.js';

// ── Helpers ──────────────────────────────────────────────────────────────
/**
 * Build a fake DER/SPKI-encoded secp256k1 public key (91 bytes).
 * 23-byte SPKI header + 65-byte uncompressed point (04 || x || y).
 */
function makeFakeDerPublicKey(fill: number): Uint8Array {
  const der = new Uint8Array(88);
  // SPKI header (23 bytes) — just needs to be present for subarray offset
  der.fill(0x00, 0, 23);
  // Uncompressed point: 04 prefix + 32-byte x + 32-byte y
  der[23] = 0x04;
  der.fill(fill, 24, 56);  // x coordinate
  der.fill(fill + 1, 56, 88); // y coordinate (even last byte → 0x02 prefix)
  return der;
}

const DEFAULT_PARAMS = {
  currentKeyId: 'alias/hedera-signer-dev',
  operatorId: '0.0.8291501',
  gracePeriodDays: 0,
};

beforeEach(() => {
  vi.clearAllMocks();
  // Default happy-path mocks
  mocks.kmsSend.mockImplementation((cmd: { input?: unknown; constructor?: { name?: string } }) => {
    const name = cmd?.constructor?.name;
    if (name === 'MockCreateKeyCommand') {
      return Promise.resolve({ KeyMetadata: { KeyId: 'new-key-id-123' } });
    }
    if (name === 'MockDisableKeyCommand') {
      return Promise.resolve({});
    }
    return Promise.resolve({});
  });
  mocks.getKmsPublicKey.mockImplementation((keyId: string) => {
    if (keyId === 'new-key-id-123') return Promise.resolve(makeFakeDerPublicKey(0xaa));
    return Promise.resolve(makeFakeDerPublicKey(0xbb));
  });
  mocks.signWithKms.mockResolvedValue({
    r: new Uint8Array(32).fill(0x11),
    s: new Uint8Array(32).fill(0x22),
  });
  mockToBytes.mockReturnValue(new Uint8Array(100).fill(0x01));
  mockAddSignature.mockReturnThis();
  mockExecute.mockResolvedValue({
    transactionId: { toString: () => '0.0.8291501@1234567890.000' },
    getReceipt: mockGetReceipt,
  });
  mockGetReceipt.mockResolvedValue({
    status: { toString: () => 'SUCCESS' },
  });
  mocks.writeAuditRecord.mockResolvedValue(undefined);
});

// ── Tests ────────────────────────────────────────────────────────────────
describe('rotateSigningKey', () => {
  it('completes a successful rotation flow', async () => {
    const result = await rotateSigningKey(DEFAULT_PARAMS);

    expect(result).toEqual({
      oldKeyId: 'alias/hedera-signer-dev',
      newKeyId: 'new-key-id-123',
      hederaTransactionId: '0.0.8291501@1234567890.000',
      status: 'ROTATION_COMPLETE',
    });

    // KMS CreateKey was called
    expect(mocks.kmsSend).toHaveBeenCalledTimes(2); // CreateKey + DisableKey
    // GetPublicKey called for both new and current keys
    expect(mocks.getKmsPublicKey).toHaveBeenCalledTimes(2);
    expect(mocks.getKmsPublicKey).toHaveBeenCalledWith('new-key-id-123');
    expect(mocks.getKmsPublicKey).toHaveBeenCalledWith('alias/hedera-signer-dev');
    // signWithKms called to sign the AccountUpdate tx
    expect(mocks.signWithKms).toHaveBeenCalledOnce();
    // Hedera tx executed
    expect(mockExecute).toHaveBeenCalledOnce();
    // Success audit record written
    expect(mocks.writeAuditRecord).toHaveBeenCalledOnce();
    const auditArg = mocks.writeAuditRecord.mock.calls[0][0];
    expect(auditArg.transactionType).toBe('KeyRotation');
    expect(auditArg.signingOutcome).toBe('success');
    expect(auditArg.hederaTransactionId).toBe('0.0.8291501@1234567890.000');
  });

  it('updates the active key ID after successful rotation', async () => {
    await rotateSigningKey(DEFAULT_PARAMS);
    expect(getActiveKeyId()).toBe('new-key-id-123');
  });

  it('throws when KMS CreateKey fails and writes failure audit', async () => {
    mocks.kmsSend.mockRejectedValue(new Error('KMS CreateKey throttled'));

    await expect(rotateSigningKey(DEFAULT_PARAMS)).rejects.toThrow('KMS CreateKey throttled');

    // Failure audit record should be written
    expect(mocks.writeAuditRecord).toHaveBeenCalledOnce();
    const auditArg = mocks.writeAuditRecord.mock.calls[0][0];
    expect(auditArg.signingOutcome).toBe('failure');
    expect(auditArg.signingError).toBe('KMS CreateKey throttled');
    expect(auditArg.transactionType).toBe('KeyRotation');
  });

  it('throws when KMS CreateKey returns no KeyId', async () => {
    mocks.kmsSend.mockImplementation((cmd: { constructor?: { name?: string } }) => {
      if (cmd?.constructor?.name === 'MockCreateKeyCommand') {
        return Promise.resolve({ KeyMetadata: {} }); // no KeyId
      }
      return Promise.resolve({});
    });

    await expect(rotateSigningKey(DEFAULT_PARAMS)).rejects.toThrow(
      'KMS CreateKey did not return a KeyId',
    );

    expect(mocks.writeAuditRecord).toHaveBeenCalledOnce();
    const auditArg = mocks.writeAuditRecord.mock.calls[0][0];
    expect(auditArg.signingOutcome).toBe('failure');
  });

  it('throws when Hedera AccountUpdate fails and writes failure audit', async () => {
    mockGetReceipt.mockResolvedValue({
      status: { toString: () => 'INVALID_SIGNATURE' },
    });

    await expect(rotateSigningKey(DEFAULT_PARAMS)).rejects.toThrow(
      'AccountUpdateTransaction failed with status: INVALID_SIGNATURE',
    );

    // Failure audit should be written
    expect(mocks.writeAuditRecord).toHaveBeenCalledOnce();
    const auditArg = mocks.writeAuditRecord.mock.calls[0][0];
    expect(auditArg.signingOutcome).toBe('failure');
    expect(auditArg.signingError).toContain('INVALID_SIGNATURE');
    expect(auditArg.transactionParams.newKeyId).toBe('new-key-id-123');
  });

  it('throws when Hedera execute rejects and writes failure audit', async () => {
    mockExecute.mockRejectedValue(new Error('Hedera network timeout'));

    await expect(rotateSigningKey(DEFAULT_PARAMS)).rejects.toThrow('Hedera network timeout');

    expect(mocks.writeAuditRecord).toHaveBeenCalledOnce();
    const auditArg = mocks.writeAuditRecord.mock.calls[0][0];
    expect(auditArg.signingOutcome).toBe('failure');
    expect(auditArg.signingError).toBe('Hedera network timeout');
  });

  it('writes success audit record with correct fields', async () => {
    await rotateSigningKey(DEFAULT_PARAMS);

    expect(mocks.writeAuditRecord).toHaveBeenCalledOnce();
    const auditArg = mocks.writeAuditRecord.mock.calls[0][0];
    expect(auditArg.requestId).toMatch(/^rotation-/);
    expect(auditArg.callerIdentity).toBe('system:key-rotation');
    expect(auditArg.transactionType).toBe('KeyRotation');
    expect(auditArg.transactionParams).toEqual({
      oldKeyId: 'alias/hedera-signer-dev',
      newKeyId: 'new-key-id-123',
      gracePeriodDays: 0,
    });
    expect(auditArg.policyDecision).toBe('approved');
    expect(auditArg.signingOutcome).toBe('success');
    expect(auditArg.payloadHash).toBeDefined();
  });

  it('writes failure audit record with newKeyId N/A when CreateKey fails', async () => {
    mocks.kmsSend.mockRejectedValue(new Error('Access denied'));

    await expect(rotateSigningKey(DEFAULT_PARAMS)).rejects.toThrow('Access denied');

    const auditArg = mocks.writeAuditRecord.mock.calls[0][0];
    expect(auditArg.requestId).toMatch(/^rotation-failure-/);
    expect(auditArg.transactionParams.newKeyId).toBe('N/A');
  });

  it('does not fail rotation if success audit write throws', async () => {
    mocks.writeAuditRecord.mockRejectedValue(new Error('DDB write failed'));

    // Rotation should still succeed even if audit write fails
    const result = await rotateSigningKey(DEFAULT_PARAMS);
    expect(result.status).toBe('ROTATION_COMPLETE');
  });
});
