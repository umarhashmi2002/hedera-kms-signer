import { describe, it, expect } from 'vitest';
import { validateSignTransferRequest } from '../schemas.js';

const validRequest = {
  requestId: '550e8400-e29b-41d4-a716-446655440000',
  senderAccountId: '0.0.8291501',
  recipientAccountId: '0.0.1234',
  amountHbar: 2.5,
  memo: 'test transfer',
};

describe('validateSignTransferRequest', () => {
  // 1. Valid request with all fields
  it('accepts a valid request with all fields', () => {
    const result = validateSignTransferRequest(validRequest);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.data).toEqual(validRequest);
    }
  });

  // 2. Valid request without memo
  it('accepts a valid request without memo', () => {
    const { memo, ...noMemo } = validRequest;
    const result = validateSignTransferRequest(noMemo);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.data.memo).toBeUndefined();
    }
  });

  // 3. Missing requestId
  it('rejects missing requestId', () => {
    const { requestId, ...rest } = validRequest;
    const result = validateSignTransferRequest(rest);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('requestId is required');
    }
  });

  // 4. Invalid UUID format
  it('rejects invalid UUID format', () => {
    const result = validateSignTransferRequest({ ...validRequest, requestId: 'not-a-uuid' });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('requestId must be a valid UUID');
    }
  });

  // 5. Missing senderAccountId
  it('rejects missing senderAccountId', () => {
    const { senderAccountId, ...rest } = validRequest;
    const result = validateSignTransferRequest(rest);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('senderAccountId is required');
    }
  });

  // 6. Invalid Hedera account ID formats
  it('rejects invalid Hedera account ID "0.0.0"', () => {
    const result = validateSignTransferRequest({ ...validRequest, senderAccountId: '0.0.0' });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.some(e => e.includes('senderAccountId'))).toBe(true);
    }
  });

  it('rejects invalid Hedera account ID "1.2.3"', () => {
    const result = validateSignTransferRequest({ ...validRequest, recipientAccountId: '1.2.3' });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.some(e => e.includes('recipientAccountId'))).toBe(true);
    }
  });

  it('rejects invalid Hedera account ID "abc"', () => {
    const result = validateSignTransferRequest({ ...validRequest, senderAccountId: 'abc' });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.some(e => e.includes('senderAccountId'))).toBe(true);
    }
  });

  // 7. Missing recipientAccountId
  it('rejects missing recipientAccountId', () => {
    const { recipientAccountId, ...rest } = validRequest;
    const result = validateSignTransferRequest(rest);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('recipientAccountId is required');
    }
  });

  // 8. amountHbar = 0
  it('rejects amountHbar of 0', () => {
    const result = validateSignTransferRequest({ ...validRequest, amountHbar: 0 });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.some(e => e.includes('amountHbar') && e.includes('positive'))).toBe(true);
    }
  });

  // 9. amountHbar = -1
  it('rejects negative amountHbar', () => {
    const result = validateSignTransferRequest({ ...validRequest, amountHbar: -1 });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.some(e => e.includes('amountHbar'))).toBe(true);
    }
  });

  // 10. amountHbar = 5 (boundary, exactly at max)
  it('accepts amountHbar exactly at max (5)', () => {
    const result = validateSignTransferRequest({ ...validRequest, amountHbar: 5 });
    expect(result.valid).toBe(true);
  });

  // 11. amountHbar = 5.01 (exceeds max)
  it('rejects amountHbar exceeding max (5.01)', () => {
    const result = validateSignTransferRequest({ ...validRequest, amountHbar: 5.01 });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.some(e => e.includes('amountHbar') && e.includes('5'))).toBe(true);
    }
  });

  // 12. memo with 100 chars (valid boundary)
  it('accepts memo with exactly 100 characters', () => {
    const result = validateSignTransferRequest({ ...validRequest, memo: 'a'.repeat(100) });
    expect(result.valid).toBe(true);
  });

  // 13. memo with 101 chars (exceeds max)
  it('rejects memo with 101 characters', () => {
    const result = validateSignTransferRequest({ ...validRequest, memo: 'a'.repeat(101) });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.some(e => e.includes('memo') && e.includes('100'))).toBe(true);
    }
  });

  // 14. memo as non-string
  it('rejects memo as non-string', () => {
    const result = validateSignTransferRequest({ ...validRequest, memo: 42 });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.some(e => e.includes('memo') && e.includes('string'))).toBe(true);
    }
  });

  // 15. null body
  it('rejects null body', () => {
    const result = validateSignTransferRequest(null);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('Request body must be a non-null object');
    }
  });

  // 16. Array body
  it('rejects array body', () => {
    const result = validateSignTransferRequest([1, 2, 3]);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('Request body must be a non-null object');
    }
  });

  // 17. Empty object → multiple errors
  it('returns multiple errors for empty object', () => {
    const result = validateSignTransferRequest({});
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.length).toBeGreaterThanOrEqual(4);
      expect(result.errors).toContain('requestId is required');
      expect(result.errors).toContain('senderAccountId is required');
      expect(result.errors).toContain('recipientAccountId is required');
      expect(result.errors).toContain('amountHbar is required');
    }
  });

  // 18. Extra fields should not cause errors
  it('ignores extra fields', () => {
    const result = validateSignTransferRequest({ ...validRequest, extraField: 'hello', anotherOne: 99 });
    expect(result.valid).toBe(true);
  });

  // 19. Empty string requestId
  it('rejects empty string requestId', () => {
    const result = validateSignTransferRequest({ ...validRequest, requestId: '' });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('requestId must be a valid UUID');
    }
  });

  // Additional edge case: special characters in memo
  it('accepts memo with special characters', () => {
    const result = validateSignTransferRequest({ ...validRequest, memo: '🚀 héllo <script>alert("xss")</script>' });
    expect(result.valid).toBe(true);
  });
});
