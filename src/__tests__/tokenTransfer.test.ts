import { describe, it, expect } from 'vitest';
import { validateSignTokenTransferRequest } from '../schemas.js';

describe('validateSignTokenTransferRequest', () => {
  const validBody = {
    requestId: '550e8400-e29b-41d4-a716-446655440000',
    senderAccountId: '0.0.8291501',
    recipientAccountId: '0.0.1234',
    tokenId: '0.0.456789',
    amount: 100,
  };

  it('accepts a valid token transfer request', () => {
    const result = validateSignTokenTransferRequest(validBody);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.data.tokenId).toBe('0.0.456789');
      expect(result.data.amount).toBe(100);
    }
  });

  it('accepts request with optional memo', () => {
    const result = validateSignTokenTransferRequest({ ...validBody, memo: 'test' });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.data.memo).toBe('test');
    }
  });

  it('rejects missing tokenId', () => {
    const { tokenId, ...body } = validBody;
    const result = validateSignTokenTransferRequest(body);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('tokenId is required');
    }
  });

  it('rejects invalid tokenId format', () => {
    const result = validateSignTokenTransferRequest({ ...validBody, tokenId: 'invalid' });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('tokenId must be a valid Hedera token ID (0.0.N)');
    }
  });

  it('rejects non-integer amount', () => {
    const result = validateSignTokenTransferRequest({ ...validBody, amount: 1.5 });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('amount must be a positive integer (smallest token unit)');
    }
  });

  it('rejects zero amount', () => {
    const result = validateSignTokenTransferRequest({ ...validBody, amount: 0 });
    expect(result.valid).toBe(false);
  });

  it('rejects negative amount', () => {
    const result = validateSignTokenTransferRequest({ ...validBody, amount: -10 });
    expect(result.valid).toBe(false);
  });

  it('rejects missing requestId', () => {
    const { requestId, ...body } = validBody;
    const result = validateSignTokenTransferRequest(body);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('requestId is required');
    }
  });

  it('rejects null body', () => {
    const result = validateSignTokenTransferRequest(null);
    expect(result.valid).toBe(false);
  });

  it('rejects memo exceeding 100 characters', () => {
    const result = validateSignTokenTransferRequest({
      ...validBody,
      memo: 'x'.repeat(101),
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('memo must not exceed 100 characters');
    }
  });
});
