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


// ── Token Transfer Schema ──

export interface SignTokenTransferRequest {
  requestId: string;
  senderAccountId: string;
  recipientAccountId: string;
  tokenId: string;
  amount: number;
  memo?: string;
}

const HEDERA_TOKEN_ID_REGEX = /^0\.0\.[1-9]\d*$/;

export function validateSignTokenTransferRequest(
  body: unknown,
): { valid: true; data: SignTokenTransferRequest } | { valid: false; errors: string[] } {
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
  } else if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(obj.requestId)) {
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

  // tokenId
  if (obj.tokenId === undefined || obj.tokenId === null) {
    errors.push('tokenId is required');
  } else if (typeof obj.tokenId !== 'string') {
    errors.push('tokenId must be a string');
  } else if (!HEDERA_TOKEN_ID_REGEX.test(obj.tokenId)) {
    errors.push('tokenId must be a valid Hedera token ID (0.0.N)');
  }

  // amount (integer, token smallest unit)
  if (obj.amount === undefined || obj.amount === null) {
    errors.push('amount is required');
  } else if (typeof obj.amount !== 'number' || !Number.isFinite(obj.amount)) {
    errors.push('amount must be a finite number');
  } else if (!Number.isInteger(obj.amount) || obj.amount <= 0) {
    errors.push('amount must be a positive integer (smallest token unit)');
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
      tokenId: obj.tokenId as string,
      amount: obj.amount as number,
      ...(obj.memo !== undefined && obj.memo !== null ? { memo: obj.memo as string } : {}),
    },
  };
}


// ── Scheduled Transfer Schema ──

export interface ScheduleTransferRequest {
  requestId: string;
  senderAccountId: string;
  recipientAccountId: string;
  amountHbar: number;
  memo?: string;
  executeAfterSeconds: number;
}

export function validateScheduleTransferRequest(
  body: unknown,
): { valid: true; data: ScheduleTransferRequest } | { valid: false; errors: string[] } {
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
  } else if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(obj.requestId)) {
    errors.push('requestId must be a valid UUID');
  }

  // senderAccountId
  if (obj.senderAccountId === undefined || obj.senderAccountId === null) {
    errors.push('senderAccountId is required');
  } else if (typeof obj.senderAccountId !== 'string') {
    errors.push('senderAccountId must be a string');
  } else if (!/^0\.0\.[1-9]\d*$/.test(obj.senderAccountId)) {
    errors.push('senderAccountId must be a valid Hedera account ID (0.0.N)');
  }

  // recipientAccountId
  if (obj.recipientAccountId === undefined || obj.recipientAccountId === null) {
    errors.push('recipientAccountId is required');
  } else if (typeof obj.recipientAccountId !== 'string') {
    errors.push('recipientAccountId must be a string');
  } else if (!/^0\.0\.[1-9]\d*$/.test(obj.recipientAccountId)) {
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

  // executeAfterSeconds
  if (obj.executeAfterSeconds === undefined || obj.executeAfterSeconds === null) {
    errors.push('executeAfterSeconds is required');
  } else if (typeof obj.executeAfterSeconds !== 'number' || !Number.isFinite(obj.executeAfterSeconds)) {
    errors.push('executeAfterSeconds must be a finite number');
  } else if (!Number.isInteger(obj.executeAfterSeconds) || obj.executeAfterSeconds < 1) {
    errors.push('executeAfterSeconds must be a positive integer (minimum 1)');
  } else if (obj.executeAfterSeconds > 5184000) {
    errors.push('executeAfterSeconds must not exceed 5184000 (60 days)');
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
      executeAfterSeconds: obj.executeAfterSeconds as number,
      ...(obj.memo !== undefined && obj.memo !== null ? { memo: obj.memo as string } : {}),
    },
  };
}
