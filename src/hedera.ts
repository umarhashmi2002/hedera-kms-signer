import { createHash } from 'node:crypto';
import {
  Client,
  TransferTransaction,
  AccountId,
  Hbar,
  PublicKey,
  TransactionId,
} from '@hashgraph/sdk';
import { keccak_256 } from '@noble/hashes/sha3';
import { signWithKms } from './kms.js';
import { getPublicKeyInfo } from './publicKey.js';

const KMS_KEY_ID = process.env.KMS_KEY_ID ?? 'alias/hedera-signer-dev';
const HEDERA_OPERATOR_ID = process.env.HEDERA_OPERATOR_ID ?? '';
const HEDERA_NETWORK = process.env.HEDERA_NETWORK ?? 'testnet';

/**
 * Create a Hedera Client for the configured network.
 * Does NOT set an operator (we sign externally via KMS).
 */
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

export interface TransferParams {
  senderAccountId: string;
  recipientAccountId: string;
  amountHbar: number;
  memo?: string;
}

export interface TransferResult {
  transactionId: string;
  status: string;
  transactionHash: string;
}

/**
 * Build and freeze a CryptoTransfer transaction without signing or submitting.
 * Exported for testing (Property 6 / Property 7).
 */
export function buildFrozenTransfer(params: TransferParams): InstanceType<typeof TransferTransaction> {
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

  const senderAccount = AccountId.fromString(params.senderAccountId);
  const recipientAccount = AccountId.fromString(params.recipientAccountId);

  if (params.amountHbar <= 0) {
    throw new Error(`amountHbar must be positive, got ${params.amountHbar}`);
  }

  const client = createHederaClient();

  const txId = TransactionId.generate(senderAccount);

  // Use a single node to avoid multi-node signature issues with external signing
  const nodeAccountIds = client.network
    ? Object.values(client.network).slice(0, 1)
    : [new AccountId(3)];

  const tx = new TransferTransaction()
    .setTransactionId(txId)
    .setNodeAccountIds(nodeAccountIds as AccountId[])
    .setTransactionValidDuration(120)
    .addHbarTransfer(senderAccount, Hbar.fromTinybars(-params.amountHbar * 100_000_000))
    .addHbarTransfer(recipientAccount, Hbar.fromTinybars(params.amountHbar * 100_000_000));

  if (params.memo) {
    tx.setTransactionMemo(params.memo);
  }

  tx.freezeWith(client);

  return tx;
}

/**
 * Build, sign via KMS, and submit a CryptoTransfer transaction to the Hedera network.
 *
 * Flow: validate → build → freeze → SHA-256 hash → KMS sign → attach sig → submit → receipt
 */
export async function buildAndSubmitTransfer(
  params: TransferParams,
): Promise<TransferResult> {
  // 1. Build and freeze the transaction (single node for external signing)
  const tx = buildFrozenTransfer(params);

  // 2. Get the KMS public key and convert to Hedera PublicKey
  const pubKeyInfo = await getPublicKeyInfo();
  const compressedKeyBytes = Buffer.from(pubKeyInfo.publicKeyCompressed, 'hex');
  const hederaPublicKey = PublicKey.fromBytesECDSA(compressedKeyBytes);

  // 3. Get frozen transaction bytes and compute SHA-256 hash
  const frozenBytes = tx.toBytes();
  const transactionHash = createHash('sha256').update(frozenBytes).digest('hex');

  // 4. Sign each inner transaction body via KMS
  //    The Hedera SDK uses keccak256 for ECDSA signing (not SHA-256).
  //    We hash with keccak256, then send the digest to KMS with MessageType=DIGEST.
  const signerFn = async (message: Uint8Array): Promise<Uint8Array> => {
    const hash = keccak_256(message);
    const { r, s } = await signWithKms(new Uint8Array(hash), KMS_KEY_ID);
    const signatureBytes = new Uint8Array(64);
    signatureBytes.set(r, 0);
    signatureBytes.set(s, 32);
    return signatureBytes;
  };

  // Use the SDK's signWith method which handles multi-node correctly
  await tx.signWith(hederaPublicKey, signerFn);

  // 5. Submit the transaction and wait for receipt
  const client = createHederaClient();
  const response = await tx.execute(client);
  const receipt = await response.getReceipt(client);

  // 6. Return result
  return {
    transactionId: response.transactionId.toString(),
    status: receipt.status.toString(),
    transactionHash,
  };
}
