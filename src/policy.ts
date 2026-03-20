import type { SignTransferRequest } from './schemas.js';

export interface PolicyConfig {
  maxAmountHbar: number;
  allowedRecipients: string[];
  allowedTransactionTypes: string[];
  allowedHoursUtc: { start: number; end: number };
}

export interface PolicyResult {
  approved: boolean;
  violations: string[];
}

export function loadPolicyConfig(): PolicyConfig {
  return {
    maxAmountHbar: Number(process.env.POLICY_MAX_AMOUNT_HBAR ?? '5'),
    allowedRecipients: (process.env.POLICY_ALLOWED_RECIPIENTS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    allowedTransactionTypes: (process.env.POLICY_ALLOWED_TRANSACTION_TYPES ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    allowedHoursUtc: {
      start: Number(process.env.POLICY_ALLOWED_HOURS_START ?? '0'),
      end: Number(process.env.POLICY_ALLOWED_HOURS_END ?? '24'),
    },
  };
}

// Load config at module level (Lambda cold start)
export const defaultPolicyConfig: PolicyConfig = loadPolicyConfig();

export function evaluatePolicy(
  request: SignTransferRequest,
  config: PolicyConfig,
): PolicyResult {
  const violations: string[] = [];

  // Rule 1: AMOUNT_EXCEEDS_MAX
  if (request.amountHbar > config.maxAmountHbar) {
    violations.push('AMOUNT_EXCEEDS_MAX');
  }

  // Rule 2: RECIPIENT_NOT_ALLOWED
  if (!config.allowedRecipients.includes(request.recipientAccountId)) {
    violations.push('RECIPIENT_NOT_ALLOWED');
  }

  // Rule 3: TRANSACTION_TYPE_NOT_ALLOWED
  if (!config.allowedTransactionTypes.includes('CryptoTransfer')) {
    violations.push('TRANSACTION_TYPE_NOT_ALLOWED');
  }

  // Rule 4: OUTSIDE_ALLOWED_HOURS
  const currentHourUtc = new Date().getUTCHours();
  if (currentHourUtc < config.allowedHoursUtc.start || currentHourUtc >= config.allowedHoursUtc.end) {
    violations.push('OUTSIDE_ALLOWED_HOURS');
  }

  return {
    approved: violations.length === 0,
    violations,
  };
}
