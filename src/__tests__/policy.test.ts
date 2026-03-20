import { describe, it, expect, vi, afterEach } from 'vitest';
import { evaluatePolicy, PolicyConfig } from '../policy.js';
import type { SignTransferRequest } from '../schemas.js';

// Helper: build a valid request that passes all default policy rules
function makeRequest(overrides?: Partial<SignTransferRequest>): SignTransferRequest {
  return {
    requestId: '550e8400-e29b-41d4-a716-446655440000',
    senderAccountId: '0.0.8291501',
    recipientAccountId: '0.0.1234',
    amountHbar: 2.5,
    memo: 'test transfer',
    ...overrides,
  };
}

// Helper: default policy config that approves the default request
function makeConfig(overrides?: Partial<PolicyConfig>): PolicyConfig {
  return {
    maxAmountHbar: 5,
    allowedRecipients: ['0.0.1234', '0.0.5678'],
    allowedTransactionTypes: ['CryptoTransfer'],
    allowedHoursUtc: { start: 8, end: 22 },
    ...overrides,
  };
}

describe('evaluatePolicy', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  // 1. Approves a fully compliant request (all rules pass)
  it('approves a fully compliant request', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T12:00:00Z')); // hour 12, within 8–22

    const result = evaluatePolicy(makeRequest(), makeConfig());

    expect(result.approved).toBe(true);
    expect(result.violations).toEqual([]);
  });

  // 2. Denies when amountHbar exceeds max (AMOUNT_EXCEEDS_MAX)
  it('denies when amountHbar exceeds max', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T12:00:00Z'));

    const result = evaluatePolicy(
      makeRequest({ amountHbar: 5.01 }),
      makeConfig(),
    );

    expect(result.approved).toBe(false);
    expect(result.violations).toContain('AMOUNT_EXCEEDS_MAX');
  });

  // 3. Approves when amountHbar exactly equals max (boundary)
  it('approves when amountHbar exactly equals max', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T12:00:00Z'));

    const result = evaluatePolicy(
      makeRequest({ amountHbar: 5 }),
      makeConfig({ maxAmountHbar: 5 }),
    );

    expect(result.approved).toBe(true);
    expect(result.violations).not.toContain('AMOUNT_EXCEEDS_MAX');
  });

  // 4. Denies when recipient not in allowed list (RECIPIENT_NOT_ALLOWED)
  it('denies when recipient not in allowed list', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T12:00:00Z'));

    const result = evaluatePolicy(
      makeRequest({ recipientAccountId: '0.0.9999' }),
      makeConfig(),
    );

    expect(result.approved).toBe(false);
    expect(result.violations).toContain('RECIPIENT_NOT_ALLOWED');
  });

  // 5. Denies when transaction type not allowed (TRANSACTION_TYPE_NOT_ALLOWED)
  it('denies when transaction type not allowed', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T12:00:00Z'));

    const result = evaluatePolicy(
      makeRequest(),
      makeConfig({ allowedTransactionTypes: ['TokenAssociate'] }),
    );

    expect(result.approved).toBe(false);
    expect(result.violations).toContain('TRANSACTION_TYPE_NOT_ALLOWED');
  });

  // 6. Denies when outside allowed hours (OUTSIDE_ALLOWED_HOURS)
  it('denies when outside allowed hours', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T03:00:00Z')); // hour 3, outside 8–22

    const result = evaluatePolicy(makeRequest(), makeConfig());

    expect(result.approved).toBe(false);
    expect(result.violations).toContain('OUTSIDE_ALLOWED_HOURS');
  });

  // 7. Hour boundary: request at start hour (8) is allowed (inclusive)
  it('allows request at start hour boundary (inclusive)', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T08:00:00Z')); // hour 8 exactly

    const result = evaluatePolicy(makeRequest(), makeConfig());

    expect(result.approved).toBe(true);
    expect(result.violations).not.toContain('OUTSIDE_ALLOWED_HOURS');
  });

  // 8. Hour boundary: request at end hour (22) is denied (exclusive)
  it('denies request at end hour boundary (exclusive)', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T22:00:00Z')); // hour 22 exactly

    const result = evaluatePolicy(makeRequest(), makeConfig());

    expect(result.approved).toBe(false);
    expect(result.violations).toContain('OUTSIDE_ALLOWED_HOURS');
  });

  // 9. Returns multiple violations when multiple rules are violated
  it('returns multiple violations when multiple rules fail', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T03:00:00Z')); // outside hours

    const result = evaluatePolicy(
      makeRequest({ amountHbar: 100, recipientAccountId: '0.0.9999' }),
      makeConfig({ allowedTransactionTypes: ['TokenAssociate'] }),
    );

    expect(result.approved).toBe(false);
    expect(result.violations).toContain('AMOUNT_EXCEEDS_MAX');
    expect(result.violations).toContain('RECIPIENT_NOT_ALLOWED');
    expect(result.violations).toContain('TRANSACTION_TYPE_NOT_ALLOWED');
    expect(result.violations).toContain('OUTSIDE_ALLOWED_HOURS');
    expect(result.violations).toHaveLength(4);
  });

  // 10. Empty allowed recipients list → always RECIPIENT_NOT_ALLOWED
  it('denies any recipient when allowed list is empty', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T12:00:00Z'));

    const result = evaluatePolicy(
      makeRequest(),
      makeConfig({ allowedRecipients: [] }),
    );

    expect(result.approved).toBe(false);
    expect(result.violations).toContain('RECIPIENT_NOT_ALLOWED');
  });

  // 11. Empty allowed transaction types list → always TRANSACTION_TYPE_NOT_ALLOWED
  it('denies any transaction type when allowed list is empty', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T12:00:00Z'));

    const result = evaluatePolicy(
      makeRequest(),
      makeConfig({ allowedTransactionTypes: [] }),
    );

    expect(result.approved).toBe(false);
    expect(result.violations).toContain('TRANSACTION_TYPE_NOT_ALLOWED');
  });
});
