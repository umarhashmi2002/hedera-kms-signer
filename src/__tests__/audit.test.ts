import { describe, it, expect, vi, beforeEach } from 'vitest';

// Create mock send via vi.hoisted so it's available before vi.mock factories run.
const mockSend = vi.hoisted(() => vi.fn());

vi.mock('@aws-sdk/client-dynamodb', () => {
  return {
    DynamoDBClient: class MockDynamoDBClient {},
  };
});

vi.mock('@aws-sdk/lib-dynamodb', () => {
  return {
    DynamoDBDocumentClient: {
      from: () => ({
        send: mockSend,
      }),
    },
    PutCommand: class MockPutCommand {
      constructor(public input: unknown) {}
    },
    GetCommand: class MockGetCommand {
      constructor(public input: unknown) {}
    },
  };
});

import type { AuditRecord } from '../audit.js';
import { computePayloadHash, writeAuditRecord, getExistingRecord } from '../audit.js';

// ─── Helper: build a valid AuditRecord for reuse ───
function buildAuditRecord(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    requestId: 'req-001',
    callerIdentity: 'user@example.com',
    timestamp: '2025-01-15T12:00:00.000Z',
    transactionType: 'CryptoTransfer',
    transactionParams: { recipientAccountId: '0.0.1234', amountHbar: 1 },
    payloadHash: 'abc123hash',
    policyDecision: 'approved',
    ...overrides,
  };
}

// ─── computePayloadHash tests ───
describe('computePayloadHash', () => {
  it('returns consistent SHA-256 hex for the same input', () => {
    const payload = { requestId: 'r1', amount: 5 };
    const hash1 = computePayloadHash(payload);
    const hash2 = computePayloadHash(payload);
    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);
  });

  it('returns different hashes for different inputs', () => {
    const hash1 = computePayloadHash({ amount: 1 });
    const hash2 = computePayloadHash({ amount: 2 });
    expect(hash1).not.toBe(hash2);
  });
});

// ─── writeAuditRecord tests ───
describe('writeAuditRecord', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('calls PutCommand with correct pk/sk and condition expression', async () => {
    mockSend.mockResolvedValueOnce({});
    const record = buildAuditRecord({ requestId: 'req-42' });

    await writeAuditRecord(record);

    expect(mockSend).toHaveBeenCalledTimes(1);
    const putCmd = mockSend.mock.calls[0][0];
    expect(putCmd.input).toEqual(
      expect.objectContaining({
        TableName: 'hedera_signing_audit',
        Item: expect.objectContaining({
          pk: 'REQUEST#req-42',
          sk: 'REQUEST#req-42',
          requestId: 'req-42',
        }),
        ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
      }),
    );
  });

  it('swallows ConditionalCheckFailedException (duplicate write)', async () => {
    const err = new Error('Conditional check failed');
    err.name = 'ConditionalCheckFailedException';
    mockSend.mockRejectedValueOnce(err);

    const record = buildAuditRecord();
    // Should not throw
    await expect(writeAuditRecord(record)).resolves.toBeUndefined();
  });

  it('re-throws other errors', async () => {
    mockSend.mockRejectedValueOnce(new Error('InternalServerError'));

    const record = buildAuditRecord();
    await expect(writeAuditRecord(record)).rejects.toThrow('InternalServerError');
  });
});

// ─── getExistingRecord tests ───
describe('getExistingRecord', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('returns null when no record exists', async () => {
    mockSend.mockResolvedValueOnce({ Item: undefined });

    const result = await getExistingRecord('req-missing', 'somehash');
    expect(result).toBeNull();
  });

  it('returns { record, conflict: false } when payloadHash matches', async () => {
    const storedRecord = buildAuditRecord({ requestId: 'req-1', payloadHash: 'hash-abc' });
    mockSend.mockResolvedValueOnce({
      Item: { pk: 'REQUEST#req-1', sk: 'REQUEST#req-1', ...storedRecord },
    });

    const result = await getExistingRecord('req-1', 'hash-abc');
    expect(result).not.toBeNull();
    expect(result!.conflict).toBe(false);
    expect(result!.record.requestId).toBe('req-1');
  });

  it('returns { record, conflict: true } when payloadHash differs', async () => {
    const storedRecord = buildAuditRecord({ requestId: 'req-2', payloadHash: 'hash-original' });
    mockSend.mockResolvedValueOnce({
      Item: { pk: 'REQUEST#req-2', sk: 'REQUEST#req-2', ...storedRecord },
    });

    const result = await getExistingRecord('req-2', 'hash-different');
    expect(result).not.toBeNull();
    expect(result!.conflict).toBe(true);
    expect(result!.record.requestId).toBe('req-2');
  });
});
