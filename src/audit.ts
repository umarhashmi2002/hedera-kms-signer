import { createHash } from 'node:crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
} from '@aws-sdk/lib-dynamodb';

// Module-level client for Lambda execution context reuse
const ddbClient = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(ddbClient);

const AUDIT_TABLE_NAME = process.env.AUDIT_TABLE_NAME ?? 'hedera_signing_audit';

export interface AuditRecord {
  requestId: string;
  callerIdentity: string;
  timestamp: string;
  transactionType: string;
  transactionParams: object;
  payloadHash: string;
  policyDecision: 'approved' | 'denied';
  policyViolations?: string[];
  signingOutcome?: 'success' | 'failure';
  signingError?: string;
  transactionHash?: string;
  hederaTransactionId?: string;
  submissionResult?: string;
  httpStatus?: number;
  responseBody?: object;
}

/**
 * Compute SHA-256 hash of the canonical JSON representation of a request object.
 * Returns a hex-encoded string.
 */
export function computePayloadHash(payload: unknown): string {
  const canonical = JSON.stringify(payload);
  return createHash('sha256').update(canonical).digest('hex');
}

/**
 * Write an immutable audit record to DynamoDB.
 * Uses a condition expression to prevent overwriting existing entries.
 */
export async function writeAuditRecord(record: AuditRecord): Promise<void> {
  const pk = `REQUEST#${record.requestId}`;

  try {
    await docClient.send(
      new PutCommand({
        TableName: AUDIT_TABLE_NAME,
        Item: {
          pk,
          sk: pk,
          ...record,
        },
        ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
      }),
    );
  } catch (error: unknown) {
    if (
      error instanceof Error &&
      error.name === 'ConditionalCheckFailedException'
    ) {
      // Record already exists — this is expected for duplicate writes.
      // Swallow the error; the original record remains immutable.
      return;
    }
    throw error;
  }
}

/**
 * Retrieve an existing audit record by requestId and check for payload conflicts.
 *
 * Returns `null` if no record exists.
 * Returns `{ record, conflict: false }` if the record exists and payloadHash matches.
 * Returns `{ record, conflict: true }` if the record exists but payloadHash differs
 * (same requestId reused with a different payload).
 */
export async function getExistingRecord(
  requestId: string,
  payloadHash: string,
): Promise<{ record: AuditRecord; conflict: boolean } | null> {
  const pk = `REQUEST#${requestId}`;

  const result = await docClient.send(
    new GetCommand({
      TableName: AUDIT_TABLE_NAME,
      Key: { pk, sk: pk },
    }),
  );

  if (!result.Item) {
    return null;
  }

  const record = result.Item as AuditRecord;
  const conflict = record.payloadHash !== payloadHash;

  return { record, conflict };
}
