import {
  KMSClient,
  SignCommand,
  GetPublicKeyCommand,
} from '@aws-sdk/client-kms';

const kmsClient = new KMSClient({});

/** Module-level cache for public key bytes (Lambda execution context reuse). */
let cachedPublicKey: Uint8Array | null = null;
let cachedPublicKeyId: string | null = null;

/**
 * Parse an ASN.1 DER-encoded ECDSA signature into raw (r, s) components.
 *
 * DER layout:
 *   SEQUENCE { INTEGER r, INTEGER s }
 *   30 <seqLen> 02 <rLen> <rBytes...> 02 <sLen> <sBytes...>
 *
 * Each INTEGER may have a leading 0x00 byte when the high bit is set.
 * We strip leading zeros and left-pad to exactly 32 bytes.
 */
export function derToRawSignature(derSignature: Uint8Array): {
  r: Uint8Array;
  s: Uint8Array;
} {
  let offset = 0;

  // SEQUENCE tag
  if (derSignature[offset] !== 0x30) {
    throw new Error('Invalid DER signature: expected SEQUENCE tag 0x30');
  }
  offset += 1;

  // SEQUENCE length (skip — we parse by tag)
  const seqLen = derSignature[offset];
  offset += 1;

  // Validate total length
  if (offset + seqLen > derSignature.length) {
    throw new Error('Invalid DER signature: SEQUENCE length exceeds buffer');
  }

  // Parse first INTEGER (r)
  const r = readDerInteger(derSignature, offset);
  offset = r.nextOffset;

  // Parse second INTEGER (s)
  const s = readDerInteger(derSignature, offset);

  return { r: r.value, s: s.value };
}

/**
 * Read a DER INTEGER at the given offset and return a 32-byte big-endian
 * unsigned integer (stripped of leading zeros, left-padded as needed).
 */
function readDerInteger(
  buf: Uint8Array,
  offset: number,
): { value: Uint8Array; nextOffset: number } {
  if (buf[offset] !== 0x02) {
    throw new Error(
      `Invalid DER signature: expected INTEGER tag 0x02 at offset ${offset}`,
    );
  }
  offset += 1;

  const len = buf[offset];
  offset += 1;

  let value = buf.subarray(offset, offset + len);

  // Strip leading zero bytes (DER uses them to keep the integer positive)
  while (value.length > 1 && value[0] === 0x00) {
    value = value.subarray(1);
  }

  // Left-pad to exactly 32 bytes
  const padded = new Uint8Array(32);
  if (value.length <= 32) {
    padded.set(value, 32 - value.length);
  } else {
    // Shouldn't happen for secp256k1, but handle gracefully
    padded.set(value.subarray(value.length - 32));
  }

  return { value: padded, nextOffset: offset + len };
}

/** Simple promise-based delay. */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Sign a pre-computed SHA-256 hash using KMS ECDSA_SHA_256.
 *
 * Retries up to 2 times with exponential backoff (200ms, 400ms).
 * Total: up to 3 attempts.
 */
export async function signWithKms(
  hash: Uint8Array,
  keyId: string,
): Promise<{ r: Uint8Array; s: Uint8Array }> {
  const maxRetries = 2;
  const baseDelayMs = 200;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const command = new SignCommand({
        KeyId: keyId,
        Message: hash,
        MessageType: 'DIGEST',
        SigningAlgorithm: 'ECDSA_SHA_256',
      });

      const response = await kmsClient.send(command);

      if (!response.Signature) {
        throw new Error('KMS Sign returned empty signature');
      }

      return derToRawSignature(new Uint8Array(response.Signature));
    } catch (error) {
      if (attempt < maxRetries) {
        await delay(baseDelayMs * Math.pow(2, attempt));
        continue;
      }
      throw error;
    }
  }

  // Unreachable, but satisfies TypeScript
  throw new Error('KMS Sign failed after all retry attempts');
}

/**
 * Retrieve the DER/SPKI-encoded public key from KMS.
 *
 * The result is cached in a module-level variable so that subsequent calls
 * within the same Lambda execution context avoid extra KMS API calls.
 */
export async function getKmsPublicKey(keyId: string): Promise<Uint8Array> {
  if (cachedPublicKey && cachedPublicKeyId === keyId) {
    return cachedPublicKey;
  }

  const command = new GetPublicKeyCommand({ KeyId: keyId });
  const response = await kmsClient.send(command);

  if (!response.PublicKey) {
    throw new Error('KMS GetPublicKey returned empty public key');
  }

  cachedPublicKey = new Uint8Array(response.PublicKey);
  cachedPublicKeyId = keyId;
  return cachedPublicKey;
}
