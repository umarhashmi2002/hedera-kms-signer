export interface SignTransferRequest {
  requestId: string;
  senderAccountId: string;
  recipientAccountId: string;
  amountHbar: number;
  memo?: string;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEDERA_ACCOUNT_ID_REGEX = /^0\.0\.[1-9]\d*$/;

export function validateSignTransferRequest(
  body: unknown
): { valid: true; data: SignTransferRequest } | { valid: false; errors: string[] } {
  const errors: string[] = [];

  if (body === null || body === undefined || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, errors: ['Request body must be a non-null object'] };
  }

  const obj = body as Record<string, unknown>;

  // requestId
  if (obj.requestId === undefined || obj.requestId === null) {
    errors.push('requestId is required');
  } else if (typeof obj.requestId !== 'string') {
    errors.push('requestId must be a string');
  } else if (!UUID_REGEX.test(obj.requestId)) {
    errors.push('requestId must be a valid UUID');
  }

  // senderAccountId
  if (obj.senderAccountId === undefined || obj.senderAccountId === null) {
    errors.push('senderAccountId is required');
  } else if (typeof obj.senderAccountId !== 'string') {
    errors.push('senderAccountId must be a string');
  } else if (!HEDERA_ACCOUNT_ID_REGEX.test(obj.senderAccountId)) {
    errors.push('senderAccountId must be a valid Hedera account ID (0.0.N)');
  }

  // recipientAccountId
  if (obj.recipientAccountId === undefined || obj.recipientAccountId === null) {
    errors.push('recipientAccountId is required');
  } else if (typeof obj.recipientAccountId !== 'string') {
    errors.push('recipientAccountId must be a string');
  } else if (!HEDERA_ACCOUNT_ID_REGEX.test(obj.recipientAccountId)) {
    errors.push('recipientAccountId must be a valid Hedera account ID (0.0.N)');
  }

  // amountHbar
  if (obj.amountHbar === undefined || obj.amountHbar === null) {
    errors.push('amountHbar is required');
  } else if (typeof obj.amountHbar !== 'number' || !Number.isFinite(obj.amountHbar)) {
    errors.push('amountHbar must be a finite number');
  } else if (obj.amountHbar <= 0) {
    errors.push('amountHbar must be a positive number');
  } else if (obj.amountHbar > 5) {
    errors.push('amountHbar must not exceed 5 HBAR');
  }

  // memo (optional)
  if (obj.memo !== undefined && obj.memo !== null) {
    if (typeof obj.memo !== 'string') {
      errors.push('memo must be a string');
    } else if (obj.memo.length > 100) {
      errors.push('memo must not exceed 100 characters');
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    data: {
      requestId: obj.requestId as string,
      senderAccountId: obj.senderAccountId as string,
      recipientAccountId: obj.recipientAccountId as string,
      amountHbar: obj.amountHbar as number,
      ...(obj.memo !== undefined && obj.memo !== null ? { memo: obj.memo as string } : {}),
    },
  };
}
