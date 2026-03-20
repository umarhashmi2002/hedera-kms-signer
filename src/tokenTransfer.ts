import { createHash } from 'node:crypto';
import {
  Client,
  TransferTransaction,
  AccountId,
  PublicKey,
  TransactionId,
  TokenId,
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

export interface TokenTransferParams {
  senderAccountId: string;
  recipientAccountId: string;
  tokenId: string;
  amount: number;
  memo?: string;
}

export interface TokenTransferResult {
  transactionId: string;
  status: string;
  transactionHash: string;
}

/**
 * Build and freeze a token transfer transaction without signing or submitting.
 */
export function buildFrozenTokenTransfer(
  params: TokenTransferParams,
): InstanceType<typeof TransferTransaction> {
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
  const tokenId = TokenId.fromString(params.tokenId);

  if (params.amount <= 0) {
    throw new Error(`amount must be positive, got ${params.amount}`);
  }

  const client = createHederaClient();
  const txId = TransactionId.generate(senderAccount);

  const nodeAccountIds = client.network
    ? Object.values(client.network).slice(0, 1)
    : [new AccountId(3)];

  const tx = new TransferTransaction()
    .setTransactionId(txId)
    .setNodeAccountIds(nodeAccountIds as AccountId[])
    .setTransactionValidDuration(120)
    .addTokenTransfer(tokenId, senderAccount, -params.amount)
    .addTokenTransfer(tokenId, recipientAccount, params.amount);

  if (params.memo) {
    tx.setTransactionMemo(params.memo);
  }

  tx.freezeWith(client);
  return tx;
}

/**
 * Build, sign via KMS, and submit a Hedera Token Service transfer.
 *
 * Uses the same keccak256 + KMS signing bridge as CryptoTransfer.
 */
export async function buildAndSubmitTokenTransfer(
  params: TokenTransferParams,
): Promise<TokenTransferResult> {
  const tx = buildFrozenTokenTransfer(params);

  const pubKeyInfo = await getPublicKeyInfo();
  const compressedKeyBytes = Buffer.from(pubKeyInfo.publicKeyCompressed, 'hex');
  const hederaPublicKey = PublicKey.fromBytesECDSA(compressedKeyBytes);

  const frozenBytes = tx.toBytes();
  const transactionHash = createHash('sha256').update(frozenBytes).digest('hex');

  const signerFn = async (message: Uint8Array): Promise<Uint8Array> => {
    const hash = keccak_256(message);
    const { r, s } = await signWithKms(new Uint8Array(hash), KMS_KEY_ID);
    const signatureBytes = new Uint8Array(64);
    signatureBytes.set(r, 0);
    signatureBytes.set(s, 32);
    return signatureBytes;
  };

  await tx.signWith(hederaPublicKey, signerFn);

  const client = createHederaClient();
  const response = await tx.execute(client);
  const receipt = await response.getReceipt(client);

  return {
    transactionId: response.transactionId.toString(),
    status: receipt.status.toString(),
    transactionHash,
  };
}
