import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the KMS and publicKey modules before importing consensus
vi.mock('../kms.js', () => ({
  signWithKms: vi.fn().mockResolvedValue({
    r: new Uint8Array(32).fill(1),
    s: new Uint8Array(32).fill(2),
  }),
  getKmsPublicKey: vi.fn(),
}));

vi.mock('../publicKey.js', () => ({
  getPublicKeyInfo: vi.fn().mockResolvedValue({
    publicKeyDer: 'aa'.repeat(44),
    publicKeyCompressed: '02' + 'bb'.repeat(32),
    publicKeyUncompressed: '04' + 'cc'.repeat(64),
    evmAddress: '0x' + 'dd'.repeat(20),
  }),
}));

describe('consensus module', () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
  });

  describe('submitConsensusLog', () => {
    it('returns null when HCS_TOPIC_ID is not set', async () => {
      vi.stubEnv('HCS_TOPIC_ID', '');
      // Re-import to pick up env change
      const { submitConsensusLog } = await import('../consensus.js');
      const result = await submitConsensusLog({
        event: 'SIGN_REQUEST',
        requestId: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        status: 'APPROVED',
        timestamp: new Date().toISOString(),
        account: '0.0.8291501',
      });
      expect(result).toBeNull();
    });

    it('throws when HEDERA_OPERATOR_ID is not set but topic is configured', async () => {
      vi.stubEnv('HCS_TOPIC_ID', '0.0.12345');
      vi.stubEnv('HEDERA_OPERATOR_ID', '');
      // Need fresh import to pick up env
      vi.resetModules();
      const { submitConsensusLog } = await import('../consensus.js');
      await expect(
        submitConsensusLog({
          event: 'SIGN_REQUEST',
          requestId: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
          status: 'APPROVED',
          timestamp: new Date().toISOString(),
          account: '0.0.8291501',
        }),
      ).rejects.toThrow('HEDERA_OPERATOR_ID');
    });
  });

  describe('ConsensusLogEntry structure', () => {
    it('accepts a complete log entry', () => {
      const entry = {
        event: 'SIGN_REQUEST',
        requestId: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        status: 'APPROVED',
        timestamp: '2025-01-01T00:00:00.000Z',
        account: '0.0.8291501',
        transactionType: 'CryptoTransfer',
        hederaTransactionId: '0.0.8291501@1719000000.000000000',
      };
      // Verify the structure is valid JSON-serializable
      const json = JSON.stringify(entry);
      const parsed = JSON.parse(json);
      expect(parsed.event).toBe('SIGN_REQUEST');
      expect(parsed.status).toBe('APPROVED');
      expect(parsed.transactionType).toBe('CryptoTransfer');
    });

    it('accepts a denial log entry with violations', () => {
      const entry = {
        event: 'SIGN_REQUEST',
        requestId: 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
        status: 'DENIED',
        timestamp: '2025-01-01T00:00:00.000Z',
        account: '0.0.8291501',
        transactionType: 'CryptoTransfer',
        policyViolations: ['AMOUNT_EXCEEDS_MAX', 'RECIPIENT_NOT_ALLOWED'],
      };
      const json = JSON.stringify(entry);
      const parsed = JSON.parse(json);
      expect(parsed.policyViolations).toHaveLength(2);
      expect(parsed.status).toBe('DENIED');
    });

    it('accepts a scheduled transfer log entry', () => {
      const entry = {
        event: 'SCHEDULED_TRANSFER',
        requestId: 'c3d4e5f6-a7b8-9012-cdef-123456789012',
        status: 'APPROVED',
        timestamp: '2025-01-01T00:00:00.000Z',
        account: '0.0.8291501',
        transactionType: 'ScheduledTransfer',
      };
      const json = JSON.stringify(entry);
      expect(JSON.parse(json).event).toBe('SCHEDULED_TRANSFER');
    });
  });

  describe('createAuditTopic', () => {
    it('throws when HEDERA_OPERATOR_ID is not set', async () => {
      vi.stubEnv('HEDERA_OPERATOR_ID', '');
      vi.resetModules();
      const { createAuditTopic } = await import('../consensus.js');
      await expect(createAuditTopic()).rejects.toThrow('HEDERA_OPERATOR_ID');
    });
  });
});
