import { describe, it, expect, vi, beforeEach } from 'vitest';
import { keccak256 } from 'js-sha3';

// ─── Build a fake SPKI-encoded secp256k1 public key ───
// SPKI header for secp256k1 (23 bytes) + 65-byte uncompressed point
const SPKI_HEADER = Uint8Array.from(
  '3056301006072a8648ce3d020106052b8104000a034200'
    .match(/.{2}/g)!
    .map((b) => parseInt(b, 16)),
);

const TEST_X = new Uint8Array(32).fill(0x01);
const TEST_Y = new Uint8Array(32).fill(0x02); // last byte 0x02 → even → prefix 0x02

function buildSpkiKey(x: Uint8Array, y: Uint8Array): Uint8Array {
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);
  const spki = new Uint8Array(SPKI_HEADER.length + uncompressed.length);
  spki.set(SPKI_HEADER);
  spki.set(uncompressed, SPKI_HEADER.length);
  return spki;
}

const FAKE_SPKI_KEY = buildSpkiKey(TEST_X, TEST_Y);

// ─── Mock ./kms.js ───
const mockGetKmsPublicKey = vi.hoisted(() => vi.fn());

vi.mock('../kms.js', () => ({
  getKmsPublicKey: mockGetKmsPublicKey,
}));

// We must dynamically import the module under test so the mock is in place,
// and we need a way to reset the module-level cache between tests.
// Since the cache is a module-level variable, we use vi.resetModules() + re-import.

describe('getPublicKeyInfo', () => {
  beforeEach(() => {
    vi.resetModules();
    mockGetKmsPublicKey.mockReset();
    mockGetKmsPublicKey.mockResolvedValue(FAKE_SPKI_KEY);
  });

  async function loadModule() {
    const mod = await import('../publicKey.js');
    return mod.getPublicKeyInfo;
  }

  it('returns correct publicKeyDer (hex of full SPKI bytes)', async () => {
    const getPublicKeyInfo = await loadModule();
    const result = await getPublicKeyInfo();

    const expectedDerHex = Buffer.from(FAKE_SPKI_KEY).toString('hex');
    expect(result.publicKeyDer).toBe(expectedDerHex);
  });

  it('returns correct publicKeyUncompressed (hex of 65-byte uncompressed point)', async () => {
    const getPublicKeyInfo = await loadModule();
    const result = await getPublicKeyInfo();

    // 04 + 32 bytes of 0x01 + 32 bytes of 0x02
    const uncompressed = new Uint8Array(65);
    uncompressed[0] = 0x04;
    uncompressed.set(TEST_X, 1);
    uncompressed.set(TEST_Y, 33);
    const expectedHex = Buffer.from(uncompressed).toString('hex');
    expect(result.publicKeyUncompressed).toBe(expectedHex);
  });

  it('returns correct publicKeyCompressed with 0x02 prefix for even y', async () => {
    const getPublicKeyInfo = await loadModule();
    const result = await getPublicKeyInfo();

    // y last byte is 0x02 (even) → prefix 0x02
    const compressed = new Uint8Array(33);
    compressed[0] = 0x02;
    compressed.set(TEST_X, 1);
    const expectedHex = Buffer.from(compressed).toString('hex');
    expect(result.publicKeyCompressed).toBe(expectedHex);
  });

  it('returns correct publicKeyCompressed with 0x03 prefix for odd y', async () => {
    // Build a key where y's last byte is odd
    const oddY = new Uint8Array(32).fill(0x02);
    oddY[31] = 0x03; // odd
    const oddSpki = buildSpkiKey(TEST_X, oddY);
    mockGetKmsPublicKey.mockResolvedValue(oddSpki);

    const getPublicKeyInfo = await loadModule();
    const result = await getPublicKeyInfo();

    const compressed = new Uint8Array(33);
    compressed[0] = 0x03;
    compressed.set(TEST_X, 1);
    const expectedHex = Buffer.from(compressed).toString('hex');
    expect(result.publicKeyCompressed).toBe(expectedHex);
  });

  it('returns correct evmAddress (0x-prefixed, last 20 bytes of keccak256(x||y))', async () => {
    const getPublicKeyInfo = await loadModule();
    const result = await getPublicKeyInfo();

    // Compute expected: keccak256(x || y) → last 40 hex chars
    const xy = new Uint8Array(64);
    xy.set(TEST_X, 0);
    xy.set(TEST_Y, 32);
    const hash = keccak256(xy); // hex string
    const expectedAddress = '0x' + hash.slice(-40);
    expect(result.evmAddress).toBe(expectedAddress);
  });

  it('caches result — second call does not invoke getKmsPublicKey again', async () => {
    const getPublicKeyInfo = await loadModule();

    const result1 = await getPublicKeyInfo();
    const result2 = await getPublicKeyInfo();

    expect(mockGetKmsPublicKey).toHaveBeenCalledTimes(1);
    expect(result1).toEqual(result2);
  });
});
