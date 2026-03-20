import { keccak256 } from 'js-sha3';
import { getKmsPublicKey } from './kms.js';

const KMS_KEY_ID = process.env.KMS_KEY_ID ?? 'alias/hedera-signer-dev';

/**
 * SPKI header length for secp256k1 uncompressed public keys.
 * The DER/SPKI envelope is 23 bytes; the remaining 65 bytes are 04 || x(32) || y(32).
 */
const SPKI_HEADER_LENGTH = 23;

/** Cached result so KMS is only called once per Lambda execution context. */
let cachedInfo: {
  publicKeyDer: string;
  publicKeyCompressed: string;
  publicKeyUncompressed: string;
  evmAddress: string;
} | null = null;

/**
 * Retrieve the KMS public key and derive all Hedera-compatible representations.
 *
 * Results are cached after the first call for Lambda execution context reuse.
 */
export async function getPublicKeyInfo(): Promise<{
  publicKeyDer: string;
  publicKeyCompressed: string;
  publicKeyUncompressed: string;
  evmAddress: string;
}> {
  if (cachedInfo) {
    return cachedInfo;
  }

  const derBytes = await getKmsPublicKey(KMS_KEY_ID);

  // Hex-encoded full DER public key (raw KMS output)
  const publicKeyDer = Buffer.from(derBytes).toString('hex');

  // Extract the uncompressed point (65 bytes: 04 || x || y) from the SPKI envelope
  const uncompressedPoint = derBytes.subarray(SPKI_HEADER_LENGTH);
  const publicKeyUncompressed = Buffer.from(uncompressedPoint).toString('hex');

  // x is bytes [1..33), y is bytes [33..65) of the uncompressed point
  const x = uncompressedPoint.subarray(1, 33);
  const y = uncompressedPoint.subarray(33, 65);

  // Compressed key: prefix 02 if y is even, 03 if y is odd, followed by x
  const prefix = y[31] & 1 ? 0x03 : 0x02;
  const compressed = new Uint8Array(33);
  compressed[0] = prefix;
  compressed.set(x, 1);
  const publicKeyCompressed = Buffer.from(compressed).toString('hex');

  // EVM address: last 20 bytes of keccak256(x || y)
  const xyBytes = uncompressedPoint.subarray(1); // 64 bytes: x || y
  const hash = keccak256(xyBytes); // returns hex string (64 hex chars = 32 bytes)
  const evmAddress = '0x' + hash.slice(-40);

  cachedInfo = { publicKeyDer, publicKeyCompressed, publicKeyUncompressed, evmAddress };
  return cachedInfo;
}
