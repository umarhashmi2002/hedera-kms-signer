/**
 * One-time script to update a Hedera testnet account's key to the KMS public key.
 *
 * CRITICAL DISCOVERY: The Hedera SDK uses keccak256 (NOT SHA-256) for ECDSA signing.
 * AWS KMS ECDSA_SHA_256 with MessageType=DIGEST signs a pre-hashed digest directly.
 * So we hash with keccak256 ourselves, then send the digest to KMS.
 */

import {
  Client,
  AccountUpdateTransaction,
  AccountId,
  PrivateKey,
  PublicKey,
  TransactionId,
} from '@hashgraph/sdk';
import { KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { keccak_256 } from '@noble/hashes/sha3';
import { derToRawSignature } from './src/kms.js';

const KMS_KEY_ID = process.env.KMS_KEY_ID ?? '16a4f211-abea-41f9-9e73-ce51d3b6c876';
const KMS_PUBLIC_KEY_COMPRESSED = '02a030d167c5880a0587e064495ccbf57ed01a5380223504100e590313c505fc79';

const kmsClient = new KMSClient({ region: process.env.AWS_REGION ?? 'us-east-1' });

const [accountId, privateKeyDer] = process.argv.slice(2);

if (!accountId || !privateKeyDer) {
  console.error('Usage: npx tsx update-account-key.ts <accountId> <currentPrivateKeyDER>');
  process.exit(1);
}

/**
 * Sign message bytes using KMS with keccak256 hashing (matching Hedera SDK).
 */
async function signWithKmsKeccak(message: Uint8Array): Promise<Uint8Array> {
  // Hash with keccak256 (same as Hedera SDK's ecdsa.sign)
  const hashBytes = keccak_256(message);

  console.log('  keccak256 hash:', Buffer.from(hashBytes).toString('hex').substring(0, 40) + '...');

  // Send pre-hashed digest to KMS (KMS signs it directly, no re-hashing)
  const command = new SignCommand({
    KeyId: KMS_KEY_ID,
    Message: hashBytes,
    MessageType: 'DIGEST',
    SigningAlgorithm: 'ECDSA_SHA_256',
  });
  const response = await kmsClient.send(command);
  if (!response.Signature) throw new Error('KMS returned empty signature');

  const { r, s } = derToRawSignature(new Uint8Array(response.Signature));
  const sig = new Uint8Array(64);
  sig.set(r, 0);
  sig.set(s, 32);
  console.log('  r:', Buffer.from(r).toString('hex'));
  console.log('  s:', Buffer.from(s).toString('hex'));
  return sig;
}

async function main() {
  const currentKey = PrivateKey.fromStringDer(privateKeyDer);
  const newPublicKey = PublicKey.fromBytesECDSA(
    Buffer.from(KMS_PUBLIC_KEY_COMPRESSED, 'hex'),
  );

  const client = Client.forTestnet();
  client.setOperator(accountId, currentKey);

  console.log(`Account:          ${accountId}`);
  console.log(`Current pub key:  ${currentKey.publicKey.toStringDer()}`);
  console.log(`New KMS pub key:  ${newPublicKey.toStringDer()}`);
  console.log();

  const acctId = AccountId.fromString(accountId);
  const nodeAccountIds = Object.values(client.network).slice(0, 1) as AccountId[];

  const tx = new AccountUpdateTransaction()
    .setAccountId(acctId)
    .setKey(newPublicKey)
    .setTransactionId(TransactionId.generate(acctId))
    .setNodeAccountIds(nodeAccountIds)
    .setTransactionValidDuration(120)
    .freezeWith(client);

  // Sign with the NEW key via KMS (keccak256 hashing)
  console.log('Signing with KMS (new key, keccak256)...');
  await tx.signWith(newPublicKey, signWithKmsKeccak);

  // Sign with the OLD key
  console.log('Signing with old key...');
  await tx.sign(currentKey);

  // Submit
  console.log('Submitting to Hedera...');
  const response = await tx.execute(client);
  const receipt = await response.getReceipt(client);

  console.log();
  console.log(`Status:           ${receipt.status.toString()}`);
  console.log(`Transaction ID:   ${response.transactionId.toString()}`);
  console.log();
  console.log('Account key updated to KMS key successfully!');
  console.log(`View on HashScan: https://hashscan.io/testnet/account/${accountId}`);
}

main().catch((err) => {
  console.error('Failed:', err.message ?? err);
  process.exit(1);
});
