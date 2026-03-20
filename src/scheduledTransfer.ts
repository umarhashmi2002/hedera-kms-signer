import { createHash } from 'node:crypto';
import {
  Client,
  TransferTransaction,
  ScheduleCreateTransaction,
  AccountId,
  Hbar,
  PublicKey,
  TransactionId,
  Timestamp,
} from '@hashgraph/sdk';
import { keccak_256 } from '@noble/hashes/sha3';
import { signWithKms } from './kms.js';
import { getPublicKeyInfo } from './publicKey.js';

const KMS_KEY_ID = process.env.KMS_KEY_ID ?? 'alias/hedera-signer-dev';
const HEDERA_OPERATOR_ID = process.env.HEDERA_OPERATOR_ID ?? '';
const HEDERA_NETWORK = process.env.HEDERA_NETWORK ?? 'testnet';

function createHederaClient(): InstanceType<typeof Client> {
  switch (HEDERA_NETWORK) {
    case 'mainnet':
      return Client.forMainnet();
    case 'previewnet':
      return Client.forPreviewnet();
    default:
      return Client.forTestnet();
  }
}

export interface ScheduleTransferParams {
  senderAccountId: string;
  recipientAccountId: string;
  amountHbar: number;
  memo?: string;
  executeAfterSeconds: number;
}

export interface ScheduleTransferResult {
  scheduleId: string;
  transactionId: string;
  status: string;
  transactionHash: string;
}

/**
 * Build a frozen ScheduleCreateTransaction wrapping a CryptoTransfer.
 * The inner transfer is scheduled for future execution.
 */
export function buildFrozenScheduledTransfer(
  params: ScheduleTransferParams,
): InstanceType<typeof ScheduleCreateTransaction> {
  const operatorId = HEDERA_OPERATOR_ID;
  if (!operatorId) {
    throw new Error('HEDERA_OPERATOR_ID environment variable is not set');
  }

  if (params.senderAccountId !== operatorId) {
    throw new Error(
      `Sender account "${params.senderAccountId}" does not match operator account "${operatorId}". ` +
        'Only the KMS-backed operator account can sign transactions.',
    );
  }

  if (params.amountHbar <= 0) {
    throw new Error(`amountHbar must be positive, got ${params.amountHbar}`);
  }

  if (params.executeAfterSeconds < 1 || params.executeAfterSeconds > 5184000) {
    throw new Error(
      `executeAfterSeconds must be between 1 and 5184000 (60 days), got ${params.executeAfterSeconds}`,
    );
  }

  const senderAccount = AccountId.fromString(params.senderAccountId);
  const recipientAccount = AccountId.fromString(params.recipientAccountId);
  const client = createHederaClient();

  // Build the inner transfer (not frozen — ScheduleCreateTransaction wraps it)
  const innerTransfer = new TransferTransaction()
    .addHbarTransfer(senderAccount, Hbar.fromTinybars(-params.amountHbar * 100_000_000))
    .addHbarTransfer(recipientAccount, Hbar.fromTinybars(params.amountHbar * 100_000_000));

  // Calculate expiration timestamp
  const nowSeconds = Math.floor(Date.now() / 1000);
  const expirationTime = Timestamp.fromDate(
    new Date((nowSeconds + params.executeAfterSeconds) * 1000),
  );

  const txId = TransactionId.generate(senderAccount);
  const nodeAccountIds = client.network
    ? Object.values(client.network).slice(0, 1)
    : [new AccountId(3)];

  const scheduleTx = new ScheduleCreateTransaction()
    .setTransactionId(txId)
    .setNodeAccountIds(nodeAccountIds as AccountId[])
    .setScheduledTransaction(innerTransfer)
    .setPayerAccountId(senderAccount)
    .setExpirationTime(expirationTime)
    .setWaitForExpiry(false);

  if (params.memo) {
    scheduleTx.setScheduleMemo(params.memo);
  }

  scheduleTx.freezeWith(client);
  return scheduleTx;
}

/**
 * Build, sign via KMS, and submit a scheduled CryptoTransfer to Hedera.
 *
 * The transaction is scheduled for future execution. The KMS key signs the
 * ScheduleCreateTransaction, and the inner transfer executes when the
 * expiration time is reached (or immediately if all required signatures are present).
 */
export async function buildAndSubmitScheduledTransfer(
  params: ScheduleTransferParams,
): Promise<ScheduleTransferResult> {
  const scheduleTx = buildFrozenScheduledTransfer(params);

  const pubKeyInfo = await getPublicKeyInfo();
  const compressedKeyBytes = Buffer.from(pubKeyInfo.publicKeyCompressed, 'hex');
  const hederaPublicKey = PublicKey.fromBytesECDSA(compressedKeyBytes);

  const frozenBytes = scheduleTx.toBytes();
  const transactionHash = createHash('sha256').update(frozenBytes).digest('hex');

  const signerFn = async (message: Uint8Array): Promise<Uint8Array> => {
    const hash = keccak_256(message);
    const { r, s } = await signWithKms(new Uint8Array(hash), KMS_KEY_ID);
    const signatureBytes = new Uint8Array(64);
    signatureBytes.set(r, 0);
    signatureBytes.set(s, 32);
    return signatureBytes;
  };

  await scheduleTx.signWith(hederaPublicKey, signerFn);

  const client = createHederaClient();
  const response = await scheduleTx.execute(client);
  const receipt = await response.getReceipt(client);

  return {
    scheduleId: receipt.scheduleId?.toString() ?? '',
    transactionId: response.transactionId.toString(),
    status: receipt.status.toString(),
    transactionHash,
  };
}
