import {
  Client,
  TopicMessageSubmitTransaction,
  TopicCreateTransaction,
  AccountId,
  PublicKey,
  TransactionId,
  TopicId,
} from '@hashgraph/sdk';
import { keccak_256 } from '@noble/hashes/sha3';
import { signWithKms } from './kms.js';
import { getPublicKeyInfo } from './publicKey.js';

const KMS_KEY_ID = process.env.KMS_KEY_ID ?? 'alias/hedera-signer-dev';
const HEDERA_OPERATOR_ID = process.env.HEDERA_OPERATOR_ID ?? '';
const HEDERA_NETWORK = process.env.HEDERA_NETWORK ?? 'testnet';
const HCS_TOPIC_ID = process.env.HCS_TOPIC_ID ?? '';

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

export interface ConsensusLogEntry {
  event: string;
  requestId: string;
  status: string;
  timestamp: string;
  account: string;
  transactionType?: string;
  policyViolations?: string[];
  hederaTransactionId?: string;
}

export interface ConsensusLogResult {
  topicId: string;
  sequenceNumber: string;
  transactionId: string;
  status: string;
}

/**
 * Submit a signing event log entry to Hedera Consensus Service (HCS).
 *
 * This creates a tamper-proof, decentralized audit trail on the Hedera network.
 * Each signing decision (approved, denied, failed) is recorded as an HCS message.
 *
 * Requires HCS_TOPIC_ID environment variable to be set.
 * If not set, logging is silently skipped (non-blocking).
 */
export async function submitConsensusLog(
  entry: ConsensusLogEntry,
): Promise<ConsensusLogResult | null> {
  const topicIdStr = HCS_TOPIC_ID;
  if (!topicIdStr) {
    // HCS logging not configured — skip silently
    return null;
  }

  const operatorId = HEDERA_OPERATOR_ID;
  if (!operatorId) {
    throw new Error('HEDERA_OPERATOR_ID environment variable is not set');
  }

  const client = createHederaClient();
  const operatorAccount = AccountId.fromString(operatorId);
  const topicId = TopicId.fromString(topicIdStr);

  const pubKeyInfo = await getPublicKeyInfo();
  const compressedKeyBytes = Buffer.from(pubKeyInfo.publicKeyCompressed, 'hex');
  const hederaPublicKey = PublicKey.fromBytesECDSA(compressedKeyBytes);

  const message = JSON.stringify(entry);

  const txId = TransactionId.generate(operatorAccount);
  const nodeAccountIds = client.network
    ? Object.values(client.network).slice(0, 1)
    : [new AccountId(3)];

  const submitTx = new TopicMessageSubmitTransaction()
    .setTransactionId(txId)
    .setNodeAccountIds(nodeAccountIds as AccountId[])
    .setTopicId(topicId)
    .setMessage(message)
    .freezeWith(client);

  const signerFn = async (msg: Uint8Array): Promise<Uint8Array> => {
    const hash = keccak_256(msg);
    const { r, s } = await signWithKms(new Uint8Array(hash), KMS_KEY_ID);
    const signatureBytes = new Uint8Array(64);
    signatureBytes.set(r, 0);
    signatureBytes.set(s, 32);
    return signatureBytes;
  };

  await submitTx.signWith(hederaPublicKey, signerFn);

  const response = await submitTx.execute(client);
  const receipt = await response.getReceipt(client);

  return {
    topicId: topicIdStr,
    sequenceNumber: receipt.topicSequenceNumber?.toString() ?? '0',
    transactionId: response.transactionId.toString(),
    status: receipt.status.toString(),
  };
}

/**
 * Create a new HCS topic for audit logging.
 * The topic's submit key is set to the KMS-derived public key,
 * so only the Lambda function can submit messages.
 *
 * Returns the new topic ID.
 */
export async function createAuditTopic(
  memo?: string,
): Promise<{ topicId: string; transactionId: string }> {
  const operatorId = HEDERA_OPERATOR_ID;
  if (!operatorId) {
    throw new Error('HEDERA_OPERATOR_ID environment variable is not set');
  }

  const client = createHederaClient();
  const operatorAccount = AccountId.fromString(operatorId);

  const pubKeyInfo = await getPublicKeyInfo();
  const compressedKeyBytes = Buffer.from(pubKeyInfo.publicKeyCompressed, 'hex');
  const hederaPublicKey = PublicKey.fromBytesECDSA(compressedKeyBytes);

  const txId = TransactionId.generate(operatorAccount);
  const nodeAccountIds = client.network
    ? Object.values(client.network).slice(0, 1)
    : [new AccountId(3)];

  const createTx = new TopicCreateTransaction()
    .setTransactionId(txId)
    .setNodeAccountIds(nodeAccountIds as AccountId[])
    .setSubmitKey(hederaPublicKey)
    .setTopicMemo(memo ?? 'Hedera KMS Signer Audit Log')
    .freezeWith(client);

  const signerFn = async (msg: Uint8Array): Promise<Uint8Array> => {
    const hash = keccak_256(msg);
    const { r, s } = await signWithKms(new Uint8Array(hash), KMS_KEY_ID);
    const signatureBytes = new Uint8Array(64);
    signatureBytes.set(r, 0);
    signatureBytes.set(s, 32);
    return signatureBytes;
  };

  await createTx.signWith(hederaPublicKey, signerFn);

  const response = await createTx.execute(client);
  const receipt = await response.getReceipt(client);

  return {
    topicId: receipt.topicId?.toString() ?? '',
    transactionId: response.transactionId.toString(),
  };
}
