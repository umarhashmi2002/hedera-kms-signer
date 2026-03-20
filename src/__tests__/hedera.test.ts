import { describe, it, expect, vi, beforeAll } from 'vitest';
import type { TransferParams } from '../hedera.js';

// The hedera module captures HEDERA_OPERATOR_ID at module level.
// We must set the env var BEFORE the module is imported.
// vi.hoisted runs before imports are evaluated.
vi.hoisted(() => {
  process.env.HEDERA_OPERATOR_ID = '0.0.8291501';
  process.env.HEDERA_NETWORK = 'testnet';
});

// Now import — the module will see HEDERA_OPERATOR_ID = '0.0.8291501'
const { buildFrozenTransfer } = await import('../hedera.js');

const OPERATOR_ID = '0.0.8291501';

describe('buildFrozenTransfer', () => {
  // --- Sender validation (Req 4.1) ---

  it('rejects when senderAccountId does not match HEDERA_OPERATOR_ID', () => {
    expect(() =>
      buildFrozenTransfer({
        senderAccountId: '0.0.9999999',
        recipientAccountId: '0.0.1234',
        amountHbar: 1,
      }),
    ).toThrow(/does not match operator account/);
  });

  it('rejects when senderAccountId is empty string', () => {
    expect(() =>
      buildFrozenTransfer({
        senderAccountId: '',
        recipientAccountId: '0.0.1234',
        amountHbar: 1,
      }),
    ).toThrow();
  });

  // --- Amount validation (Req 4.3) ---

  it('rejects zero amountHbar', () => {
    expect(() =>
      buildFrozenTransfer({
        senderAccountId: OPERATOR_ID,
        recipientAccountId: '0.0.1234',
        amountHbar: 0,
      }),
    ).toThrow(/amountHbar must be positive/);
  });

  it('rejects negative amountHbar', () => {
    expect(() =>
      buildFrozenTransfer({
        senderAccountId: OPERATOR_ID,
        recipientAccountId: '0.0.1234',
        amountHbar: -5,
      }),
    ).toThrow(/amountHbar must be positive/);
  });

  // --- Successful build (Req 4.1, 4.4, 6.1) ---

  it('builds a frozen transaction with valid params', () => {
    const tx = buildFrozenTransfer({
      senderAccountId: OPERATOR_ID,
      recipientAccountId: '0.0.1234',
      amountHbar: 1,
    });

    expect(tx).toBeDefined();
    expect(tx.transactionId).toBeDefined();
    expect(tx.toBytes().length).toBeGreaterThan(0);
  });

  // --- Memo handling (Req 6.2, 6.3) ---

  it('includes memo when provided', () => {
    const tx = buildFrozenTransfer({
      senderAccountId: OPERATOR_ID,
      recipientAccountId: '0.0.1234',
      amountHbar: 1,
      memo: 'test payment',
    });

    expect(tx).toBeDefined();
    expect(tx.transactionMemo).toBe('test payment');
  });

  it('has no memo when not provided', () => {
    const tx = buildFrozenTransfer({
      senderAccountId: OPERATOR_ID,
      recipientAccountId: '0.0.1234',
      amountHbar: 2,
    });

    expect(tx.transactionMemo).toBe('');
  });

  // --- Malformed account IDs (Req 4.3) ---

  it('rejects malformed sender account ID', () => {
    // 'not-an-account' doesn't match OPERATOR_ID, so it throws sender mismatch first
    expect(() =>
      buildFrozenTransfer({
        senderAccountId: 'not-an-account',
        recipientAccountId: '0.0.1234',
        amountHbar: 1,
      }),
    ).toThrow();
  });

  it('rejects malformed recipient account ID', () => {
    expect(() =>
      buildFrozenTransfer({
        senderAccountId: OPERATOR_ID,
        recipientAccountId: 'invalid',
        amountHbar: 1,
      }),
    ).toThrow();
  });
});
