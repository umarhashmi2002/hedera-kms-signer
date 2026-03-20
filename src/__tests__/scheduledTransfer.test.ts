import { describe, it, expect } from 'vitest';
import { validateScheduleTransferRequest } from '../schemas.js';

describe('validateScheduleTransferRequest', () => {
  const validRequest = {
    requestId: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
    senderAccountId: '0.0.8291501',
    recipientAccountId: '0.0.1234',
    amountHbar: 1.5,
    executeAfterSeconds: 3600,
    memo: 'Scheduled payment',
  };

  it('accepts a valid scheduled transfer request', () => {
    const result = validateScheduleTransferRequest(validRequest);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.data.executeAfterSeconds).toBe(3600);
      expect(result.data.amountHbar).toBe(1.5);
    }
  });

  it('rejects missing executeAfterSeconds', () => {
    const { executeAfterSeconds, ...noDelay } = validRequest;
    const result = validateScheduleTransferRequest(noDelay);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('executeAfterSeconds is required');
    }
  });

  it('rejects non-integer executeAfterSeconds', () => {
    const result = validateScheduleTransferRequest({ ...validRequest, executeAfterSeconds: 3.5 });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors[0]).toContain('positive integer');
    }
  });

  it('rejects executeAfterSeconds less than 1', () => {
    const result = validateScheduleTransferRequest({ ...validRequest, executeAfterSeconds: 0 });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors[0]).toContain('positive integer');
    }
  });

  it('rejects executeAfterSeconds exceeding 60 days', () => {
    const result = validateScheduleTransferRequest({ ...validRequest, executeAfterSeconds: 5184001 });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors[0]).toContain('5184000');
    }
  });

  it('accepts executeAfterSeconds at maximum (60 days)', () => {
    const result = validateScheduleTransferRequest({ ...validRequest, executeAfterSeconds: 5184000 });
    expect(result.valid).toBe(true);
  });

  it('accepts executeAfterSeconds at minimum (1 second)', () => {
    const result = validateScheduleTransferRequest({ ...validRequest, executeAfterSeconds: 1 });
    expect(result.valid).toBe(true);
  });

  it('rejects invalid requestId', () => {
    const result = validateScheduleTransferRequest({ ...validRequest, requestId: 'not-a-uuid' });
    expect(result.valid).toBe(false);
  });

  it('rejects amountHbar exceeding 5', () => {
    const result = validateScheduleTransferRequest({ ...validRequest, amountHbar: 10 });
    expect(result.valid).toBe(false);
  });

  it('rejects invalid senderAccountId', () => {
    const result = validateScheduleTransferRequest({ ...validRequest, senderAccountId: 'invalid' });
    expect(result.valid).toBe(false);
  });

  it('accepts request without optional memo', () => {
    const { memo, ...noMemo } = validRequest;
    const result = validateScheduleTransferRequest(noMemo);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.data.memo).toBeUndefined();
    }
  });

  it('rejects non-object body', () => {
    expect(validateScheduleTransferRequest(null).valid).toBe(false);
    expect(validateScheduleTransferRequest('string').valid).toBe(false);
    expect(validateScheduleTransferRequest([]).valid).toBe(false);
  });
});
