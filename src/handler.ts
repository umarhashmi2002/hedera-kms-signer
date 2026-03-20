import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { validateSignTransferRequest } from './schemas.js';
import { evaluatePolicy, defaultPolicyConfig } from './policy.js';
import { writeAuditRecord, getExistingRecord, computePayloadHash } from './audit.js';
import { buildAndSubmitTransfer } from './hedera.js';
import { getPublicKeyInfo } from './publicKey.js';
import { rotateSigningKey } from './rotation.js';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Extract caller identity from API Gateway v2 authorizer context.
 * Falls back to 'anonymous' if no identity is available.
 */
function extractCallerIdentity(event: APIGatewayProxyEventV2): string {
  // The authorizer field is present at runtime when JWT auth is configured,
  // but the base APIGatewayProxyEventV2 type doesn't include it.
  const ctx = event.requestContext as unknown as Record<string, unknown>;
  const authorizer = ctx.authorizer as
    | { jwt?: { claims?: Record<string, string> } }
    | undefined;
  if (authorizer?.jwt?.claims) {
    return authorizer.jwt.claims.sub ?? authorizer.jwt.claims.email ?? 'anonymous';
  }
  return 'anonymous';
}

/**
 * Build a JSON response with standard headers.
 */
function jsonResponse(statusCode: number, body: object): APIGatewayProxyResultV2 {
  return {
    statusCode,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  };
}

/**
 * Lambda entry point — route dispatch based on HTTP method + path.
 */
export async function handler(event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> {
  const method = event.requestContext.http.method;
  const path = event.requestContext.http.path;

  try {
    if (method === 'POST' && path === '/sign-transfer') {
      return await handleSignTransfer(event);
    }
    if (method === 'GET' && path === '/public-key') {
      return await handleGetPublicKey();
    }
    if (method === 'GET' && path === '/docs') {
      return handleGetDocs();
    }
    if (method === 'POST' && path === '/rotate-key') {
      return await handleRotateKey();
    }

    return jsonResponse(404, { error: 'Not found' });
  } catch (error: unknown) {
    console.error('Unhandled error in handler:', error);
    return jsonResponse(500, { error: 'INTERNAL_ERROR' });
  }
}

/**
 * POST /sign-transfer
 *
 * Flow: validate schema → check idempotency → evaluate policy → build/sign/submit → write audit → return response
 */
async function handleSignTransfer(event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> {
  const callerIdentity = extractCallerIdentity(event);

  // 1. Parse and validate request body
  let body: unknown;
  try {
    body = JSON.parse(event.body ?? '{}');
  } catch {
    return jsonResponse(400, { error: 'VALIDATION_ERROR', details: ['Invalid JSON body'] });
  }

  const validation = validateSignTransferRequest(body);
  if (!validation.valid) {
    return jsonResponse(400, { error: 'VALIDATION_ERROR', details: validation.errors });
  }

  const request = validation.data;
  const payloadHash = computePayloadHash(request);

  // 2. Check idempotency
  try {
    const existing = await getExistingRecord(request.requestId, payloadHash);
    if (existing) {
      if (existing.conflict) {
        return jsonResponse(409, {
          error: 'CONFLICT',
          message: 'requestId already used with a different payload',
        });
      }
      // Return cached result
      const cachedStatus = existing.record.httpStatus ?? 200;
      const cachedBody = existing.record.responseBody ?? {
        transactionId: existing.record.hederaTransactionId,
        status: existing.record.submissionResult,
      };
      return jsonResponse(cachedStatus, cachedBody);
    }
  } catch (error: unknown) {
    console.error('Error checking idempotency:', error);
    // Continue processing — idempotency check failure should not block the request
  }

  // 3. Evaluate policy
  const policyResult = evaluatePolicy(request, defaultPolicyConfig);
  if (!policyResult.approved) {
    const httpStatus = 403;
    const responseBody = { error: 'POLICY_DENIED', violations: policyResult.violations };

    // Best-effort audit write for policy denial
    try {
      await writeAuditRecord({
        requestId: request.requestId,
        callerIdentity,
        timestamp: new Date().toISOString(),
        transactionType: 'CryptoTransfer',
        transactionParams: request,
        payloadHash,
        policyDecision: 'denied',
        policyViolations: policyResult.violations,
        httpStatus,
        responseBody,
      });
    } catch (auditError: unknown) {
      console.error('Failed to write denial audit record:', auditError);
    }

    return jsonResponse(httpStatus, responseBody);
  }

  // 4. Build, sign, and submit the transaction
  let transactionId: string;
  let status: string;
  let transactionHash: string;

  try {
    const result = await buildAndSubmitTransfer({
      senderAccountId: request.senderAccountId,
      recipientAccountId: request.recipientAccountId,
      amountHbar: request.amountHbar,
      memo: request.memo,
    });
    transactionId = result.transactionId;
    status = result.status;
    transactionHash = result.transactionHash;
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const isSigningError = errorMessage.includes('KMS') || errorMessage.includes('sign');
    const httpStatus = 502;
    const responseBody = isSigningError
      ? { error: 'SIGNING_ERROR', message: errorMessage }
      : { error: 'SUBMISSION_ERROR', message: errorMessage };

    // Best-effort audit write for signing/submission failure
    try {
      await writeAuditRecord({
        requestId: request.requestId,
        callerIdentity,
        timestamp: new Date().toISOString(),
        transactionType: 'CryptoTransfer',
        transactionParams: request,
        payloadHash,
        policyDecision: 'approved',
        signingOutcome: 'failure',
        signingError: errorMessage,
        httpStatus,
        responseBody,
      });
    } catch (auditError: unknown) {
      console.error('Failed to write failure audit record:', auditError);
    }

    return jsonResponse(httpStatus, responseBody);
  }

  // 5. Write success audit record and return response
  const httpStatus = 200;
  const responseBody = { transactionId, status, transactionHash };

  try {
    await writeAuditRecord({
      requestId: request.requestId,
      callerIdentity,
      timestamp: new Date().toISOString(),
      transactionType: 'CryptoTransfer',
      transactionParams: request,
      payloadHash,
      policyDecision: 'approved',
      signingOutcome: 'success',
      hederaTransactionId: transactionId,
      submissionResult: status,
      transactionHash,
      httpStatus,
      responseBody,
    });
  } catch (auditError: unknown) {
    console.error('Failed to write success audit record:', auditError);
  }

  return jsonResponse(httpStatus, responseBody);
}

/**
 * GET /public-key
 *
 * Returns the KMS public key info (compressed, uncompressed, EVM address).
 */
async function handleGetPublicKey(): Promise<APIGatewayProxyResultV2> {
  try {
    const keyInfo = await getPublicKeyInfo();
    return jsonResponse(200, keyInfo);
  } catch (error: unknown) {
    console.error('Error retrieving public key:', error);
    return jsonResponse(500, { error: 'INTERNAL_ERROR' });
  }
}

/**
 * GET /docs
 *
 * Reads and returns the OpenAPI spec from docs/openapi.yaml.
 */
function handleGetDocs(): APIGatewayProxyResultV2 {
  try {
    const docsPath = join(__dirname, 'docs', 'openapi.yaml');
    const content = readFileSync(docsPath, 'utf-8');
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/yaml' },
      body: content,
    };
  } catch (error: unknown) {
    console.error('Error reading OpenAPI spec:', error);
    return jsonResponse(500, { error: 'INTERNAL_ERROR' });
  }
}


/**
 * POST /rotate-key
 *
 * Initiates a signing key rotation: creates a new KMS key, updates the Hedera
 * account key list, and disables the old key.
 */
async function handleRotateKey(): Promise<APIGatewayProxyResultV2> {
  try {
    const result = await rotateSigningKey({
      currentKeyId: process.env.KMS_KEY_ID!,
      operatorId: process.env.HEDERA_OPERATOR_ID!,
    });
    return jsonResponse(200, result);
  } catch (error: unknown) {
    console.error('Key rotation failed:', error);
    const message = error instanceof Error ? error.message : 'Key rotation failed';
    return jsonResponse(500, { error: 'ROTATION_ERROR', message });
  }
}
