import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { APIGatewayProxyEventV2 } from 'aws-lambda';

// --- vi.hoisted mock functions ---
const mocks = vi.hoisted(() => ({
  validateSignTransferRequest: vi.fn(),
  evaluatePolicy: vi.fn(),
  defaultPolicyConfig: {
    maxAmountHbar: 5,
    allowedRecipients: ['0.0.1234'],
    allowedTransactionTypes: ['CryptoTransfer'],
    allowedHoursUtc: { start: 0, end: 24 },
  },
  writeAuditRecord: vi.fn(),
  getExistingRecord: vi.fn(),
  computePayloadHash: vi.fn(),
  buildAndSubmitTransfer: vi.fn(),
  getPublicKeyInfo: vi.fn(),
  readFileSync: vi.fn(),
}));

// --- vi.mock for each module ---
vi.mock('../schemas.js', () => ({
  validateSignTransferRequest: mocks.validateSignTransferRequest,
}));

vi.mock('../policy.js', () => ({
  evaluatePolicy: mocks.evaluatePolicy,
  defaultPolicyConfig: mocks.defaultPolicyConfig,
}));

vi.mock('../audit.js', () => ({
  writeAuditRecord: mocks.writeAuditRecord,
  getExistingRecord: mocks.getExistingRecord,
  computePayloadHash: mocks.computePayloadHash,
}));

vi.mock('../hedera.js', () => ({
  buildAndSubmitTransfer: mocks.buildAndSubmitTransfer,
}));

vi.mock('../publicKey.js', () => ({
  getPublicKeyInfo: mocks.getPublicKeyInfo,
}));

vi.mock('node:fs', () => ({
  readFileSync: mocks.readFileSync,
}));

// Import handler after mocks are set up
import { handler } from '../handler.js';

/** Cast the result to the object form for easier assertions. */
function asObj(res: Awaited<ReturnType<typeof handler>>) {
  return res as { statusCode: number; headers?: Record<string, string>; body?: string };
}

// --- Helper to build a minimal APIGatewayProxyEventV2 ---
function makeEvent(method: string, path: string, body?: string): APIGatewayProxyEventV2 {
  return {
    requestContext: {
      http: { method, path, protocol: 'HTTP/1.1', sourceIp: '127.0.0.1', userAgent: 'test' },
      accountId: '123456789',
      apiId: 'test',
      domainName: 'test',
      domainPrefix: 'test',
      requestId: 'test-req',
      routeKey: `${method} ${path}`,
      stage: '$default',
      time: '2024-01-15T12:00:00Z',
      timeEpoch: 1705320000000,
    },
    version: '2.0',
    routeKey: `${method} ${path}`,
    rawPath: path,
    rawQueryString: '',
    headers: {},
    isBase64Encoded: false,
    body: body ?? null,
  } as unknown as APIGatewayProxyEventV2;
}

const validBody = {
  requestId: '550e8400-e29b-41d4-a716-446655440000',
  senderAccountId: '0.0.8291501',
  recipientAccountId: '0.0.1234',
  amountHbar: 2.5,
  memo: 'test transfer',
};

beforeEach(() => {
  vi.clearAllMocks();
  mocks.computePayloadHash.mockReturnValue('abc123hash');
});

describe('handler route dispatch', () => {
  it('returns 404 for unknown routes', async () => {
    const r = asObj(await handler(makeEvent('GET', '/unknown')));
    expect(r.statusCode).toBe(404);
    const body = JSON.parse(r.body!);
    expect(body.error).toBe('Not found');
  });

  it('returns 404 for wrong method on /sign-transfer', async () => {
    const r = asObj(await handler(makeEvent('GET', '/sign-transfer')));
    expect(r.statusCode).toBe(404);
  });
});

describe('POST /sign-transfer', () => {
  it('returns 400 for invalid JSON body', async () => {
    const r = asObj(await handler(makeEvent('POST', '/sign-transfer', '{not json')));
    expect(r.statusCode).toBe(400);
    const body = JSON.parse(r.body!);
    expect(body.error).toBe('VALIDATION_ERROR');
    expect(body.details).toContain('Invalid JSON body');
  });

  it('returns 400 when validation fails', async () => {
    mocks.validateSignTransferRequest.mockReturnValue({
      valid: false,
      errors: ['requestId is required'],
    });

    const r = asObj(await handler(makeEvent('POST', '/sign-transfer', JSON.stringify({}))));
    expect(r.statusCode).toBe(400);
    const body = JSON.parse(r.body!);
    expect(body.error).toBe('VALIDATION_ERROR');
    expect(body.details).toContain('requestId is required');
  });

  it('returns 409 for duplicate requestId with different payload (conflict)', async () => {
    mocks.validateSignTransferRequest.mockReturnValue({ valid: true, data: validBody });
    mocks.getExistingRecord.mockResolvedValue({
      record: { requestId: validBody.requestId, payloadHash: 'different' },
      conflict: true,
    });

    const r = asObj(await handler(makeEvent('POST', '/sign-transfer', JSON.stringify(validBody))));
    expect(r.statusCode).toBe(409);
    const body = JSON.parse(r.body!);
    expect(body.error).toBe('CONFLICT');
  });

  it('returns 200 with cached result for duplicate requestId with same payload (idempotent replay)', async () => {
    const cachedResponse = { transactionId: '0.0.123@111.222', status: 'SUCCESS', transactionHash: 'aabbcc' };
    mocks.validateSignTransferRequest.mockReturnValue({ valid: true, data: validBody });
    mocks.getExistingRecord.mockResolvedValue({
      record: {
        requestId: validBody.requestId,
        payloadHash: 'abc123hash',
        httpStatus: 200,
        responseBody: cachedResponse,
      },
      conflict: false,
    });

    const r = asObj(await handler(makeEvent('POST', '/sign-transfer', JSON.stringify(validBody))));
    expect(r.statusCode).toBe(200);
    const body = JSON.parse(r.body!);
    expect(body).toEqual(cachedResponse);
  });

  it('returns 403 when policy denies the request', async () => {
    mocks.validateSignTransferRequest.mockReturnValue({ valid: true, data: validBody });
    mocks.getExistingRecord.mockResolvedValue(null);
    mocks.evaluatePolicy.mockReturnValue({
      approved: false,
      violations: ['AMOUNT_EXCEEDS_MAX'],
    });
    mocks.writeAuditRecord.mockResolvedValue(undefined);

    const r = asObj(await handler(makeEvent('POST', '/sign-transfer', JSON.stringify(validBody))));
    expect(r.statusCode).toBe(403);
    const body = JSON.parse(r.body!);
    expect(body.error).toBe('POLICY_DENIED');
    expect(body.violations).toContain('AMOUNT_EXCEEDS_MAX');
  });

  it('returns 200 on successful sign-transfer flow', async () => {
    mocks.validateSignTransferRequest.mockReturnValue({ valid: true, data: validBody });
    mocks.getExistingRecord.mockResolvedValue(null);
    mocks.evaluatePolicy.mockReturnValue({ approved: true, violations: [] });
    mocks.buildAndSubmitTransfer.mockResolvedValue({
      transactionId: '0.0.8291501@1705320000.000',
      status: 'SUCCESS',
      transactionHash: 'deadbeef',
    });
    mocks.writeAuditRecord.mockResolvedValue(undefined);

    const r = asObj(await handler(makeEvent('POST', '/sign-transfer', JSON.stringify(validBody))));
    expect(r.statusCode).toBe(200);
    const body = JSON.parse(r.body!);
    expect(body.transactionId).toBe('0.0.8291501@1705320000.000');
    expect(body.status).toBe('SUCCESS');
    expect(body.transactionHash).toBe('deadbeef');
    // Verify audit record was written
    expect(mocks.writeAuditRecord).toHaveBeenCalledOnce();
  });
});

describe('GET /public-key', () => {
  it('returns 200 with public key info', async () => {
    const keyInfo = {
      publicKeyDer: 'aabb',
      publicKeyCompressed: 'ccdd',
      publicKeyUncompressed: 'eeff',
      evmAddress: '0x1234567890abcdef1234567890abcdef12345678',
    };
    mocks.getPublicKeyInfo.mockResolvedValue(keyInfo);

    const r = asObj(await handler(makeEvent('GET', '/public-key')));
    expect(r.statusCode).toBe(200);
    const body = JSON.parse(r.body!);
    expect(body).toEqual(keyInfo);
  });
});

describe('GET /docs', () => {
  it('returns 200 with OpenAPI spec content', async () => {
    mocks.readFileSync.mockReturnValue('openapi: "3.0.0"\ninfo:\n  title: Test');

    const r = asObj(await handler(makeEvent('GET', '/docs')));
    expect(r.statusCode).toBe(200);
    expect(r.headers).toMatchObject({ 'content-type': 'text/yaml' });
    expect(r.body).toContain('openapi');
  });
});

describe('error handling', () => {
  it('returns 500 when an unhandled error occurs', async () => {
    mocks.validateSignTransferRequest.mockReturnValue({ valid: true, data: validBody });
    mocks.getExistingRecord.mockResolvedValue(null);
    mocks.evaluatePolicy.mockImplementation(() => {
      throw new Error('Unexpected boom');
    });

    const r = asObj(await handler(makeEvent('POST', '/sign-transfer', JSON.stringify(validBody))));
    expect(r.statusCode).toBe(500);
    const body = JSON.parse(r.body!);
    expect(body.error).toBe('INTERNAL_ERROR');
  });
});
