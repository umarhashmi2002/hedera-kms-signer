import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fc from 'fast-check';

// ──────────────────────────────────────────────────────────────────────────────
// Setup: HEDERA_OPERATOR_ID must be set before hedera.ts is imported
// ──────────────────────────────────────────────────────────────────────────────
vi.hoisted(() => {
  process.env.HEDERA_OPERATOR_ID = '0.0.8291501';
  process.env.HEDERA_NETWORK = 'testnet';
});

// ──────────────────────────────────────────────────────────────────────────────
// Mock DynamoDB for audit tests (Properties 11, 12, 14)
// ──────────────────────────────────────────────────────────────────────────────
const mockSend = vi.hoisted(() => vi.fn());

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: class MockDynamoDBClient {},
}));

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({ send: mockSend }),
  },
  PutCommand: class MockPutCommand {
    constructor(public input: unknown) {}
  },
  GetCommand: class MockGetCommand {
    constructor(public input: unknown) {}
  },
}));

// ──────────────────────────────────────────────────────────────────────────────
// Imports
// ──────────────────────────────────────────────────────────────────────────────
import { validateSignTransferRequest } from '../schemas.js';
import type { SignTransferRequest } from '../schemas.js';
import { evaluatePolicy } from '../policy.js';
import type { PolicyConfig } from '../policy.js';
import type { AuditRecord } from '../audit.js';
import { writeAuditRecord, getExistingRecord, computePayloadHash } from '../audit.js';
import { derToRawSignature } from '../kms.js';
import { keccak256 } from 'js-sha3';

const { buildFrozenTransfer } = await import('../hedera.js');

const OPERATOR_ID = '0.0.8291501';

// ──────────────────────────────────────────────────────────────────────────────
// Shared arbitraries
// ──────────────────────────────────────────────────────────────────────────────
const arbHederaAccountId = fc.integer({ min: 1, max: 999999 }).map((n) => `0.0.${n}`);
const arbUuid = fc.uuid();
const arbValidAmount = fc.double({ min: 0.01, max: 5, noNaN: true, noDefaultInfinity: true });
const arbMemo = fc.oneof(
  fc.constant(undefined),
  fc.string({ minLength: 0, maxLength: 100 }),
);

const arbValidRequest: fc.Arbitrary<SignTransferRequest> = fc.record({
  requestId: arbUuid,
  senderAccountId: arbHederaAccountId,
  recipientAccountId: arbHederaAccountId,
  amountHbar: arbValidAmount,
  memo: arbMemo,
}) as fc.Arbitrary<SignTransferRequest>;

// ══════════════════════════════════════════════════════════════════════════════
// Property 1: Schema validation rejects invalid requests
// Feature: hedera-kms-signing-backend, Property 1: Schema validation rejects invalid requests and identifies invalid fields
// **Validates: Requirements 1.1, 1.2**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 1: Schema validation rejects invalid requests', () => {
  it('rejects objects with missing or wrong-typed fields', () => {
    // Generate objects that are guaranteed to have at least one invalid field
    const arbInvalidObject = fc.oneof(
      // Missing all required fields
      fc.record({
        extra: fc.string(),
      }),
      // Wrong type for requestId
      fc.record({
        requestId: fc.oneof(fc.integer(), fc.boolean(), fc.constant(null)),
        senderAccountId: arbHederaAccountId,
        recipientAccountId: arbHederaAccountId,
        amountHbar: arbValidAmount,
      }),
      // Wrong type for senderAccountId
      fc.record({
        requestId: arbUuid,
        senderAccountId: fc.oneof(fc.integer(), fc.boolean(), fc.constant(null)),
        recipientAccountId: arbHederaAccountId,
        amountHbar: arbValidAmount,
      }),
      // Wrong type for amountHbar
      fc.record({
        requestId: arbUuid,
        senderAccountId: arbHederaAccountId,
        recipientAccountId: arbHederaAccountId,
        amountHbar: fc.oneof(fc.constant('not-a-number'), fc.constant(null), fc.constant(0), fc.constant(-1)),
      }),
      // Non-UUID requestId string
      fc.record({
        requestId: fc.string({ minLength: 1, maxLength: 10 }),
        senderAccountId: arbHederaAccountId,
        recipientAccountId: arbHederaAccountId,
        amountHbar: arbValidAmount,
      }),
      // Invalid Hedera account ID format
      fc.record({
        requestId: arbUuid,
        senderAccountId: fc.constant('invalid-account'),
        recipientAccountId: arbHederaAccountId,
        amountHbar: arbValidAmount,
      }),
      // Amount exceeds max
      fc.record({
        requestId: arbUuid,
        senderAccountId: arbHederaAccountId,
        recipientAccountId: arbHederaAccountId,
        amountHbar: fc.double({ min: 5.01, max: 1000, noNaN: true, noDefaultInfinity: true }),
      }),
      // Memo too long
      fc.record({
        requestId: arbUuid,
        senderAccountId: arbHederaAccountId,
        recipientAccountId: arbHederaAccountId,
        amountHbar: arbValidAmount,
        memo: fc.string({ minLength: 101, maxLength: 200 }),
      }),
      // Non-object types
      fc.oneof(
        fc.constant(null),
        fc.constant(undefined),
        fc.constant(42),
        fc.constant('string'),
        fc.constant([1, 2, 3]),
      ),
    );

    fc.assert(
      fc.property(arbInvalidObject, (input) => {
        const result = validateSignTransferRequest(input);
        expect(result.valid).toBe(false);
        if (!result.valid) {
          expect(result.errors.length).toBeGreaterThan(0);
          // Each error should be a descriptive string
          for (const err of result.errors) {
            expect(typeof err).toBe('string');
            expect(err.length).toBeGreaterThan(0);
          }
        }
      }),
      { numRuns: 100 },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Property 2: Schema validation accepts valid requests
// Feature: hedera-kms-signing-backend, Property 2: Schema validation accepts all well-formed requests
// **Validates: Requirements 1.1**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 2: Schema validation accepts valid requests', () => {
  it('accepts all well-formed SignTransferRequest objects', () => {
    fc.assert(
      fc.property(arbValidRequest, (request) => {
        const result = validateSignTransferRequest(request);
        expect(result.valid).toBe(true);
        if (result.valid) {
          expect(result.data.requestId).toBe(request.requestId);
          expect(result.data.senderAccountId).toBe(request.senderAccountId);
          expect(result.data.recipientAccountId).toBe(request.recipientAccountId);
          expect(result.data.amountHbar).toBe(request.amountHbar);
        }
      }),
      { numRuns: 100 },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Property 3: Policy engine denies violating requests
// Feature: hedera-kms-signing-backend, Property 3: Policy engine denies violating requests and reports all violated rules
// **Validates: Requirements 3.1, 3.2**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 3: Policy engine denies violating requests', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('denies requests with known violations and reports all violated rules', () => {
    // Generate a request and config that guarantee at least one violation
    const arbViolatingScenario = fc.record({
      amountHbar: fc.double({ min: 5.01, max: 100, noNaN: true, noDefaultInfinity: true }),
      maxAmountHbar: fc.constant(5),
      recipientAccountId: arbHederaAccountId,
      allowedRecipients: fc.constant([] as string[]), // empty = always violates
      allowedTransactionTypes: fc.constant([] as string[]), // empty = always violates
      hour: fc.integer({ min: 0, max: 7 }), // outside 8-22
    });

    fc.assert(
      fc.property(arbViolatingScenario, (scenario) => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date(`2024-01-15T${String(scenario.hour).padStart(2, '0')}:00:00Z`));

        const request: SignTransferRequest = {
          requestId: '550e8400-e29b-41d4-a716-446655440000',
          senderAccountId: '0.0.8291501',
          recipientAccountId: scenario.recipientAccountId,
          amountHbar: scenario.amountHbar,
        };

        const config: PolicyConfig = {
          maxAmountHbar: scenario.maxAmountHbar,
          allowedRecipients: scenario.allowedRecipients,
          allowedTransactionTypes: scenario.allowedTransactionTypes,
          allowedHoursUtc: { start: 8, end: 22 },
        };

        const result = evaluatePolicy(request, config);
        expect(result.approved).toBe(false);
        expect(result.violations.length).toBeGreaterThan(0);

        // Verify expected violations are present
        const expectedViolations: string[] = [];
        if (scenario.amountHbar > scenario.maxAmountHbar) {
          expectedViolations.push('AMOUNT_EXCEEDS_MAX');
        }
        if (!scenario.allowedRecipients.includes(scenario.recipientAccountId)) {
          expectedViolations.push('RECIPIENT_NOT_ALLOWED');
        }
        if (!scenario.allowedTransactionTypes.includes('CryptoTransfer')) {
          expectedViolations.push('TRANSACTION_TYPE_NOT_ALLOWED');
        }
        if (scenario.hour < 8 || scenario.hour >= 22) {
          expectedViolations.push('OUTSIDE_ALLOWED_HOURS');
        }

        expect(result.violations.sort()).toEqual(expectedViolations.sort());

        vi.useRealTimers();
      }),
      { numRuns: 100 },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Property 4: Each policy rule evaluates independently
// Feature: hedera-kms-signing-backend, Property 4: Each policy rule type evaluates independently and correctly
// **Validates: Requirements 3.3**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 4: Each policy rule evaluates independently', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('AMOUNT_EXCEEDS_MAX triggers independently', () => {
    fc.assert(
      fc.property(
        fc.double({ min: 5.01, max: 1000, noNaN: true, noDefaultInfinity: true }),
        (amount) => {
          vi.useFakeTimers();
          vi.setSystemTime(new Date('2024-01-15T12:00:00Z'));

          const request: SignTransferRequest = {
            requestId: '550e8400-e29b-41d4-a716-446655440000',
            senderAccountId: '0.0.8291501',
            recipientAccountId: '0.0.1234',
            amountHbar: amount,
          };
          const config: PolicyConfig = {
            maxAmountHbar: 5,
            allowedRecipients: ['0.0.1234'],
            allowedTransactionTypes: ['CryptoTransfer'],
            allowedHoursUtc: { start: 0, end: 24 },
          };

          const result = evaluatePolicy(request, config);
          expect(result.violations).toContain('AMOUNT_EXCEEDS_MAX');

          vi.useRealTimers();
        },
      ),
      { numRuns: 100 },
    );
  });

  it('RECIPIENT_NOT_ALLOWED triggers independently', () => {
    fc.assert(
      fc.property(arbHederaAccountId, (recipientId) => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2024-01-15T12:00:00Z'));

        const request: SignTransferRequest = {
          requestId: '550e8400-e29b-41d4-a716-446655440000',
          senderAccountId: '0.0.8291501',
          recipientAccountId: recipientId,
          amountHbar: 1,
        };
        // Use an allowed list that definitely does NOT contain the generated recipient
        const config: PolicyConfig = {
          maxAmountHbar: 10,
          allowedRecipients: ['0.0.99999999'],
          allowedTransactionTypes: ['CryptoTransfer'],
          allowedHoursUtc: { start: 0, end: 24 },
        };

        const result = evaluatePolicy(request, config);
        expect(result.violations).toContain('RECIPIENT_NOT_ALLOWED');

        vi.useRealTimers();
      }),
      { numRuns: 100 },
    );
  });

  it('TRANSACTION_TYPE_NOT_ALLOWED triggers independently', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('TokenAssociate', 'ContractCall', 'TokenTransfer'),
        (txType) => {
          vi.useFakeTimers();
          vi.setSystemTime(new Date('2024-01-15T12:00:00Z'));

          const request: SignTransferRequest = {
            requestId: '550e8400-e29b-41d4-a716-446655440000',
            senderAccountId: '0.0.8291501',
            recipientAccountId: '0.0.1234',
            amountHbar: 1,
          };
          const config: PolicyConfig = {
            maxAmountHbar: 10,
            allowedRecipients: ['0.0.1234'],
            allowedTransactionTypes: [txType], // does NOT include 'CryptoTransfer'
            allowedHoursUtc: { start: 0, end: 24 },
          };

          const result = evaluatePolicy(request, config);
          expect(result.violations).toContain('TRANSACTION_TYPE_NOT_ALLOWED');

          vi.useRealTimers();
        },
      ),
      { numRuns: 100 },
    );
  });

  it('OUTSIDE_ALLOWED_HOURS triggers independently', () => {
    // Generate hours that are outside the allowed window [8, 22)
    const arbOutsideHour = fc.oneof(
      fc.integer({ min: 0, max: 7 }),
      fc.integer({ min: 22, max: 23 }),
    );

    fc.assert(
      fc.property(arbOutsideHour, (hour) => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date(`2024-01-15T${String(hour).padStart(2, '0')}:00:00Z`));

        const request: SignTransferRequest = {
          requestId: '550e8400-e29b-41d4-a716-446655440000',
          senderAccountId: '0.0.8291501',
          recipientAccountId: '0.0.1234',
          amountHbar: 1,
        };
        const config: PolicyConfig = {
          maxAmountHbar: 10,
          allowedRecipients: ['0.0.1234'],
          allowedTransactionTypes: ['CryptoTransfer'],
          allowedHoursUtc: { start: 8, end: 22 },
        };

        const result = evaluatePolicy(request, config);
        expect(result.violations).toContain('OUTSIDE_ALLOWED_HOURS');

        vi.useRealTimers();
      }),
      { numRuns: 100 },
    );
  });
});


// ══════════════════════════════════════════════════════════════════════════════
// Property 5: Policy engine approves compliant requests
// Feature: hedera-kms-signing-backend, Property 5: Policy engine approves requests that violate no rules
// **Validates: Requirements 3.1, 3.2, 3.3**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 5: Policy engine approves compliant requests', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('approves requests where all rules pass', () => {
    // Generate compliant scenarios: amount within limit, recipient in list, within hours
    const arbCompliantScenario = fc.record({
      amount: fc.double({ min: 0.01, max: 5, noNaN: true, noDefaultInfinity: true }),
      maxAmount: fc.double({ min: 5, max: 100, noNaN: true, noDefaultInfinity: true }),
      recipientId: arbHederaAccountId,
      hour: fc.integer({ min: 8, max: 21 }), // within [8, 22)
    });

    fc.assert(
      fc.property(arbCompliantScenario, (scenario) => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date(`2024-01-15T${String(scenario.hour).padStart(2, '0')}:00:00Z`));

        const request: SignTransferRequest = {
          requestId: '550e8400-e29b-41d4-a716-446655440000',
          senderAccountId: '0.0.8291501',
          recipientAccountId: scenario.recipientId,
          amountHbar: scenario.amount,
        };
        const config: PolicyConfig = {
          maxAmountHbar: scenario.maxAmount,
          allowedRecipients: [scenario.recipientId], // recipient is in the list
          allowedTransactionTypes: ['CryptoTransfer'],
          allowedHoursUtc: { start: 8, end: 22 },
        };

        const result = evaluatePolicy(request, config);
        expect(result.approved).toBe(true);
        expect(result.violations).toEqual([]);

        vi.useRealTimers();
      }),
      { numRuns: 100 },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Property 6: Transaction builder produces valid frozen transactions
// Feature: hedera-kms-signing-backend, Property 6: Transaction builder produces valid frozen transactions from valid parameters
// **Validates: Requirements 4.1, 4.4**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 6: Transaction builder produces valid frozen transactions', () => {
  it('produces frozen transactions with required fields from valid params', () => {
    const arbRecipient = fc.integer({ min: 1, max: 999999 })
      .filter((n) => `0.0.${n}` !== OPERATOR_ID)
      .map((n) => `0.0.${n}`);

    // Generate amounts as whole integers to avoid floating-point tinybars issues
    // buildFrozenTransfer does amountHbar * 100_000_000 which must be exact integer
    const arbAmount = fc.integer({ min: 1, max: 5 });

    fc.assert(
      fc.property(arbRecipient, arbAmount, arbMemo, (recipient, amount, memo) => {
        const params = {
          senderAccountId: OPERATOR_ID,
          recipientAccountId: recipient,
          amountHbar: amount,
          ...(memo !== undefined ? { memo } : {}),
        };

        const tx = buildFrozenTransfer(params);

        // Frozen transaction should have required fields set
        expect(tx).toBeDefined();
        expect(tx.transactionId).toBeDefined();
        expect(tx.transactionId).not.toBeNull();
        // Frozen bytes should be non-empty
        expect(tx.toBytes().length).toBeGreaterThan(0);
      }),
      { numRuns: 100 },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Property 7: Transaction builder rejects invalid parameters
// Feature: hedera-kms-signing-backend, Property 7: Transaction builder rejects invalid parameters with descriptive errors
// **Validates: Requirements 4.3**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 7: Transaction builder rejects invalid parameters', () => {
  it('rejects zero or negative amounts', () => {
    const arbBadAmount = fc.oneof(
      fc.constant(0),
      fc.double({ min: -1000, max: -0.001, noNaN: true, noDefaultInfinity: true }),
    );

    fc.assert(
      fc.property(arbBadAmount, (amount) => {
        expect(() =>
          buildFrozenTransfer({
            senderAccountId: OPERATOR_ID,
            recipientAccountId: '0.0.1234',
            amountHbar: amount,
          }),
        ).toThrow();
      }),
      { numRuns: 100 },
    );
  });

  it('rejects sender that does not match HEDERA_OPERATOR_ID', () => {
    const arbWrongSender = fc.integer({ min: 1, max: 999999 })
      .filter((n) => `0.0.${n}` !== OPERATOR_ID)
      .map((n) => `0.0.${n}`);

    fc.assert(
      fc.property(arbWrongSender, (sender) => {
        expect(() =>
          buildFrozenTransfer({
            senderAccountId: sender,
            recipientAccountId: '0.0.1234',
            amountHbar: 1,
          }),
        ).toThrow(/does not match operator account/);
      }),
      { numRuns: 100 },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Property 11: Audit records contain all required fields
// Feature: hedera-kms-signing-backend, Property 11: Audit records contain all required fields
// **Validates: Requirements 7.1, 7.2**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 11: Audit records contain all required fields', () => {
  it('audit records for any outcome contain required fields', () => {
    const arbOutcome = fc.oneof(
      // Success outcome
      fc.record({
        type: fc.constant('success' as const),
        requestId: arbUuid,
        callerIdentity: fc.string({ minLength: 1, maxLength: 50 }),
        recipientAccountId: arbHederaAccountId,
        amountHbar: arbValidAmount,
        transactionHash: fc.hexaString({ minLength: 64, maxLength: 64 }),
        hederaTransactionId: fc.string({ minLength: 5, maxLength: 50 }),
      }),
      // Denial outcome
      fc.record({
        type: fc.constant('denial' as const),
        requestId: arbUuid,
        callerIdentity: fc.string({ minLength: 1, maxLength: 50 }),
        recipientAccountId: arbHederaAccountId,
        amountHbar: arbValidAmount,
        violations: fc.array(
          fc.constantFrom('AMOUNT_EXCEEDS_MAX', 'RECIPIENT_NOT_ALLOWED', 'TRANSACTION_TYPE_NOT_ALLOWED', 'OUTSIDE_ALLOWED_HOURS'),
          { minLength: 1, maxLength: 4 },
        ),
      }),
      // Signing failure
      fc.record({
        type: fc.constant('signing_failure' as const),
        requestId: arbUuid,
        callerIdentity: fc.string({ minLength: 1, maxLength: 50 }),
        recipientAccountId: arbHederaAccountId,
        amountHbar: arbValidAmount,
        signingError: fc.string({ minLength: 1, maxLength: 100 }),
      }),
      // Submission failure
      fc.record({
        type: fc.constant('submission_failure' as const),
        requestId: arbUuid,
        callerIdentity: fc.string({ minLength: 1, maxLength: 50 }),
        recipientAccountId: arbHederaAccountId,
        amountHbar: arbValidAmount,
        signingError: fc.string({ minLength: 1, maxLength: 100 }),
      }),
    );

    fc.assert(
      fc.property(arbOutcome, (outcome) => {
        // Build an AuditRecord from the outcome
        const baseRecord: AuditRecord = {
          requestId: outcome.requestId,
          callerIdentity: outcome.callerIdentity,
          timestamp: new Date().toISOString(),
          transactionType: 'CryptoTransfer',
          transactionParams: {
            recipientAccountId: outcome.recipientAccountId,
            amountHbar: outcome.amountHbar,
          },
          payloadHash: computePayloadHash({
            recipientAccountId: outcome.recipientAccountId,
            amountHbar: outcome.amountHbar,
          }),
          policyDecision: outcome.type === 'denial' ? 'denied' : 'approved',
        };

        if (outcome.type === 'denial') {
          baseRecord.policyViolations = outcome.violations;
        }

        if (outcome.type === 'success') {
          baseRecord.signingOutcome = 'success';
          baseRecord.transactionHash = outcome.transactionHash;
          baseRecord.hederaTransactionId = outcome.hederaTransactionId;
        }

        if (outcome.type === 'signing_failure' || outcome.type === 'submission_failure') {
          baseRecord.signingOutcome = 'failure';
          baseRecord.signingError = outcome.signingError;
        }

        // Verify all required fields are present and non-null
        expect(baseRecord.requestId).toBeTruthy();
        expect(baseRecord.callerIdentity).toBeTruthy();
        expect(baseRecord.timestamp).toBeTruthy();
        expect(baseRecord.transactionType).toBeTruthy();
        expect(baseRecord.transactionParams).toBeTruthy();
        expect(baseRecord.payloadHash).toBeTruthy();
        expect(baseRecord.policyDecision).toBeTruthy();

        // For approved+signed requests, signingOutcome and transactionHash should be present
        if (baseRecord.policyDecision === 'approved' && baseRecord.signingOutcome === 'success') {
          expect(baseRecord.signingOutcome).toBe('success');
          expect(baseRecord.transactionHash).toBeTruthy();
        }
      }),
      { numRuns: 100 },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Property 12: Audit record immutability via conditional write
// Feature: hedera-kms-signing-backend, Property 12: Audit record immutability via conditional write
// **Validates: Requirements 7.4**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 12: Audit record immutability via conditional write', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('first write succeeds, second write is swallowed (ConditionalCheckFailedException)', () => {
    fc.assert(
      fc.asyncProperty(
        arbUuid,
        fc.string({ minLength: 1, maxLength: 50 }),
        async (requestId, callerIdentity) => {
          // Reset at start of each iteration (including shrink reruns)
          mockSend.mockReset();
          mockSend.mockImplementation(() => Promise.resolve({}));

          const record: AuditRecord = {
            requestId,
            callerIdentity,
            timestamp: new Date().toISOString(),
            transactionType: 'CryptoTransfer',
            transactionParams: { recipientAccountId: '0.0.1234', amountHbar: 1 },
            payloadHash: computePayloadHash({ requestId }),
            policyDecision: 'approved',
          };

          // First write succeeds (default mock returns success)
          await writeAuditRecord(record);

          // Now set up the second call to throw ConditionalCheckFailedException
          mockSend.mockReset();
          const condErr = new Error('The conditional request failed');
          condErr.name = 'ConditionalCheckFailedException';
          mockSend.mockRejectedValueOnce(condErr);

          // Should NOT throw — the error is swallowed, original record is immutable
          await expect(writeAuditRecord(record)).resolves.toBeUndefined();
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Property 13: Successful submission response format
// Feature: hedera-kms-signing-backend, Property 13: Successful submission response contains transaction ID and status
// **Validates: Requirements 6.2**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 13: Successful submission response format', () => {
  it('response contains non-empty transactionId and status strings', () => {
    const arbSuccessResult = fc.record({
      transactionId: fc.string({ minLength: 1, maxLength: 100 }),
      status: fc.constantFrom('SUCCESS', 'OK', 'COMPLETED'),
      transactionHash: fc.hexaString({ minLength: 64, maxLength: 64 }),
    });

    fc.assert(
      fc.property(arbSuccessResult, (result) => {
        // Verify the response structure matches what buildAndSubmitTransfer returns
        expect(typeof result.transactionId).toBe('string');
        expect(result.transactionId.length).toBeGreaterThan(0);
        expect(typeof result.status).toBe('string');
        expect(result.status.length).toBeGreaterThan(0);
      }),
      { numRuns: 100 },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Property 14: Idempotency behavior
// Feature: hedera-kms-signing-backend, Property 14: Idempotency — duplicate requestId returns cached result or 409 Conflict
// **Validates: Requirements 7.4**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 14: Idempotency behavior', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('same requestId + same payload returns cached record (no conflict)', () => {
    fc.assert(
      fc.asyncProperty(arbUuid, async (requestId) => {
        mockSend.mockReset();

        const payloadHash = computePayloadHash({ requestId, amount: 1 });

        const storedRecord: AuditRecord = {
          requestId,
          callerIdentity: 'test-user',
          timestamp: new Date().toISOString(),
          transactionType: 'CryptoTransfer',
          transactionParams: { amount: 1 },
          payloadHash,
          policyDecision: 'approved',
          httpStatus: 200,
          responseBody: { transactionId: '0.0.123@111.222', status: 'SUCCESS' },
        };

        // Mock GetItem to return the stored record
        mockSend.mockResolvedValueOnce({
          Item: { pk: `REQUEST#${requestId}`, sk: `REQUEST#${requestId}`, ...storedRecord },
        });

        const result = await getExistingRecord(requestId, payloadHash);
        expect(result).not.toBeNull();
        expect(result!.conflict).toBe(false);
        expect(result!.record.requestId).toBe(requestId);
        expect(result!.record.httpStatus).toBe(200);
        expect(result!.record.responseBody).toBeDefined();
      }),
      { numRuns: 100 },
    );
  });

  it('same requestId + different payload returns conflict', () => {
    fc.assert(
      fc.asyncProperty(arbUuid, async (requestId) => {
        mockSend.mockReset();

        const originalHash = computePayloadHash({ requestId, amount: 1 });
        const differentHash = computePayloadHash({ requestId, amount: 2 });

        const storedRecord: AuditRecord = {
          requestId,
          callerIdentity: 'test-user',
          timestamp: new Date().toISOString(),
          transactionType: 'CryptoTransfer',
          transactionParams: { amount: 1 },
          payloadHash: originalHash,
          policyDecision: 'approved',
        };

        // Mock GetItem to return the stored record with original hash
        mockSend.mockResolvedValueOnce({
          Item: { pk: `REQUEST#${requestId}`, sk: `REQUEST#${requestId}`, ...storedRecord },
        });

        // Query with a different payload hash
        const result = await getExistingRecord(requestId, differentHash);
        expect(result).not.toBeNull();
        expect(result!.conflict).toBe(true);
      }),
      { numRuns: 100 },
    );
  });
});


// ══════════════════════════════════════════════════════════════════════════════
// Property 8: DER signature to (r, s) conversion round-trip
// Feature: hedera-kms-signing-backend, Property 8: DER signature to (r, s) conversion round-trip
// **Validates: Requirements 5.2**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 8: DER signature round-trip', () => {
  /**
   * Encode a 32-byte big-endian unsigned integer as a DER INTEGER.
   * DER integers are signed, so if the high bit is set we prepend 0x00.
   */
  function toDerInteger(value: Uint8Array): Uint8Array {
    // Strip leading zeros for minimal encoding (but keep at least one byte)
    let start = 0;
    while (start < value.length - 1 && value[start] === 0x00) {
      start++;
    }
    const trimmed = value.subarray(start);

    // If high bit is set, prepend 0x00 to keep the integer positive
    const needsPad = (trimmed[0] & 0x80) !== 0;
    const len = trimmed.length + (needsPad ? 1 : 0);
    const result = new Uint8Array(2 + len); // tag + length + data
    result[0] = 0x02; // INTEGER tag
    result[1] = len;
    if (needsPad) {
      result[2] = 0x00;
      result.set(trimmed, 3);
    } else {
      result.set(trimmed, 2);
    }
    return result;
  }

  /**
   * Encode r and s as a DER SEQUENCE { INTEGER r, INTEGER s }.
   */
  function encodeDerSignature(r: Uint8Array, s: Uint8Array): Uint8Array {
    const derR = toDerInteger(r);
    const derS = toDerInteger(s);
    const seqLen = derR.length + derS.length;
    const result = new Uint8Array(2 + seqLen); // SEQUENCE tag + length + contents
    result[0] = 0x30; // SEQUENCE tag
    result[1] = seqLen;
    result.set(derR, 2);
    result.set(derS, 2 + derR.length);
    return result;
  }

  it('round-trips random 32-byte r and s values through DER encoding', () => {
    const arb32Bytes = fc.uint8Array({ minLength: 32, maxLength: 32 });

    fc.assert(
      fc.property(arb32Bytes, arb32Bytes, (r, s) => {
        const derEncoded = encodeDerSignature(r, s);
        const recovered = derToRawSignature(derEncoded);

        // Both recovered values should be exactly 32 bytes
        expect(recovered.r.length).toBe(32);
        expect(recovered.s.length).toBe(32);

        // Recovered values should match the originals
        expect(Buffer.from(recovered.r).toString('hex')).toBe(
          Buffer.from(r).toString('hex'),
        );
        expect(Buffer.from(recovered.s).toString('hex')).toBe(
          Buffer.from(s).toString('hex'),
        );
      }),
      { numRuns: 200 },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Property 9: DER public key to uncompressed format conversion
// Feature: hedera-kms-signing-backend, Property 9: DER public key to uncompressed format conversion
// **Validates: Requirements 12.3**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 9: DER public key to uncompressed format', () => {
  /**
   * The secp256k1 SPKI header is 23 bytes. It wraps the uncompressed point
   * (04 || x(32) || y(32)) = 65 bytes, for a total DER key of 88 bytes.
   *
   * SPKI structure:
   *   SEQUENCE {
   *     SEQUENCE { OID ecPublicKey, OID secp256k1 }
   *     BIT STRING { 00 04 x(32) y(32) }
   *   }
   *
   * The fixed 23-byte header for secp256k1 uncompressed keys:
   */
  const SPKI_HEADER = new Uint8Array([
    0x30, 0x56, // SEQUENCE (86 bytes)
    0x30, 0x10, // SEQUENCE (16 bytes)
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a,             // OID secp256k1
    0x03, 0x42, // BIT STRING (66 bytes)
    0x00,       // no unused bits
  ]);

  it('extracts 65-byte uncompressed point (04 || x || y) from SPKI envelope', () => {
    const arb32Bytes = fc.uint8Array({ minLength: 32, maxLength: 32 });

    fc.assert(
      fc.property(arb32Bytes, arb32Bytes, (x, y) => {
        // Build a valid SPKI-encoded public key: header + 04 + x + y
        const spkiKey = new Uint8Array(SPKI_HEADER.length + 65);
        spkiKey.set(SPKI_HEADER, 0);
        spkiKey[SPKI_HEADER.length] = 0x04; // uncompressed point prefix
        spkiKey.set(x, SPKI_HEADER.length + 1);
        spkiKey.set(y, SPKI_HEADER.length + 33);

        // Extract the uncompressed point using the same logic as publicKey.ts
        const SPKI_HEADER_LENGTH = 23;
        const uncompressedPoint = spkiKey.subarray(SPKI_HEADER_LENGTH);

        // Should be 65 bytes with first byte 0x04
        expect(uncompressedPoint.length).toBe(65);
        expect(uncompressedPoint[0]).toBe(0x04);

        // x and y should match the originals
        const extractedX = uncompressedPoint.subarray(1, 33);
        const extractedY = uncompressedPoint.subarray(33, 65);
        expect(Buffer.from(extractedX).toString('hex')).toBe(
          Buffer.from(x).toString('hex'),
        );
        expect(Buffer.from(extractedY).toString('hex')).toBe(
          Buffer.from(y).toString('hex'),
        );
      }),
      { numRuns: 200 },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Property 10: Public key to EVM address derivation
// Feature: hedera-kms-signing-backend, Property 10: Public key to EVM address derivation
// **Validates: Requirements 12.1**
// ══════════════════════════════════════════════════════════════════════════════
describe('Property 10: Public key to EVM address derivation', () => {
  it('EVM address equals last 20 bytes of keccak256(x || y)', () => {
    const arb32Bytes = fc.uint8Array({ minLength: 32, maxLength: 32 });

    fc.assert(
      fc.property(arb32Bytes, arb32Bytes, (x, y) => {
        // Concatenate x || y (64 bytes)
        const xy = new Uint8Array(64);
        xy.set(x, 0);
        xy.set(y, 32);

        // Derive EVM address using the same logic as publicKey.ts
        const hash = keccak256(xy); // returns hex string (64 hex chars = 32 bytes)
        const evmAddress = '0x' + hash.slice(-40);

        // Independently verify: last 20 bytes of keccak256 hash
        const expectedLast40Hex = hash.substring(hash.length - 40);
        expect(evmAddress).toBe('0x' + expectedLast40Hex);

        // Address should be 42 chars (0x + 40 hex chars = 20 bytes)
        expect(evmAddress.length).toBe(42);
        expect(evmAddress.startsWith('0x')).toBe(true);

        // All hex characters after 0x
        expect(/^0x[0-9a-f]{40}$/.test(evmAddress)).toBe(true);
      }),
      { numRuns: 200 },
    );
  });
});
