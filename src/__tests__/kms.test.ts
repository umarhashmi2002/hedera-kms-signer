import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// The mock send function must be created via vi.hoisted so it exists
// before vi.mock's factory runs (both are hoisted, but vi.hoisted first).
const mockSend = vi.hoisted(() => vi.fn());

vi.mock('@aws-sdk/client-kms', () => {
  return {
    KMSClient: class MockKMSClient {
      send(...args: unknown[]) {
        return mockSend(...args);
      }
    },
    SignCommand: class MockSignCommand {
      constructor(public input: unknown) {}
    },
    GetPublicKeyCommand: class MockGetPublicKeyCommand {
      constructor(public input: unknown) {}
    },
  };
});

import { derToRawSignature, signWithKms, getKmsPublicKey } from '../kms.js';

// ─── Helper: build a valid DER-encoded ECDSA signature from raw r and s ───
function buildDerSignature(r: Uint8Array, s: Uint8Array): Uint8Array {
  const rPadded = r[0] >= 0x80 ? new Uint8Array([0x00, ...r]) : r;
  const sPadded = s[0] >= 0x80 ? new Uint8Array([0x00, ...s]) : s;
  const rLen = rPadded.length;
  const sLen = sPadded.length;
  const seqLen = 2 + rLen + 2 + sLen;
  const der = new Uint8Array(2 + seqLen);
  let offset = 0;
  der[offset++] = 0x30;
  der[offset++] = seqLen;
  der[offset++] = 0x02;
  der[offset++] = rLen;
  der.set(rPadded, offset);
  offset += rLen;
  der[offset++] = 0x02;
  der[offset++] = sLen;
  der.set(sPadded, offset);
  return der;
}

// ─── derToRawSignature tests (pure function, no mocking needed) ───
describe('derToRawSignature', () => {
  it('parses a valid DER signature with standard r and s values', () => {
    const r = new Uint8Array(32).fill(0xab);
    const s = new Uint8Array(32).fill(0xcd);
    const result = derToRawSignature(buildDerSignature(r, s));
    expect(result.r).toEqual(r);
    expect(result.s).toEqual(s);
  });

  it('handles leading zero bytes in r and s (high bit set)', () => {
    const r = new Uint8Array(32);
    r[0] = 0x80; r.fill(0x11, 1);
    const s = new Uint8Array(32);
    s[0] = 0xff; s.fill(0x22, 1);
    const result = derToRawSignature(buildDerSignature(r, s));
    expect(result.r).toEqual(r);
    expect(result.s).toEqual(s);
  });

  it('left-pads short r and s values to 32 bytes', () => {
    const rShort = new Uint8Array(20).fill(0x42);
    const sShort = new Uint8Array(16).fill(0x37);
    const result = derToRawSignature(buildDerSignature(rShort, sShort));
    const expectedR = new Uint8Array(32);
    expectedR.set(rShort, 12);
    const expectedS = new Uint8Array(32);
    expectedS.set(sShort, 16);
    expect(result.r).toEqual(expectedR);
    expect(result.s).toEqual(expectedS);
  });

  it('rejects DER with wrong SEQUENCE tag', () => {
    const bad = new Uint8Array([0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    expect(() => derToRawSignature(bad)).toThrow('expected SEQUENCE tag 0x30');
  });

  it('rejects DER with wrong INTEGER tag for r', () => {
    const bad = new Uint8Array([0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01]);
    expect(() => derToRawSignature(bad)).toThrow('expected INTEGER tag 0x02');
  });

  it('rejects DER with wrong INTEGER tag for s', () => {
    const bad = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01]);
    expect(() => derToRawSignature(bad)).toThrow('expected INTEGER tag 0x02');
  });

  it('parses max-length r and s (32 bytes, no leading zeros)', () => {
    const r = new Uint8Array(32);
    r[0] = 0x7f; r.fill(0xff, 1);
    const s = new Uint8Array(32);
    s[0] = 0x7f; s.fill(0xee, 1);
    const result = derToRawSignature(buildDerSignature(r, s));
    expect(result.r).toEqual(r);
    expect(result.s).toEqual(s);
  });

  it('parses minimal DER encoding (1-byte r and s)', () => {
    const result = derToRawSignature(
      buildDerSignature(new Uint8Array([0x01]), new Uint8Array([0x02])),
    );
    const expectedR = new Uint8Array(32);
    expectedR[31] = 0x01;
    const expectedS = new Uint8Array(32);
    expectedS[31] = 0x02;
    expect(result.r).toEqual(expectedR);
    expect(result.s).toEqual(expectedS);
  });
});

// ─── signWithKms tests ───
describe('signWithKms', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockSend.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function makeMockDerSig(): Uint8Array {
    return buildDerSignature(
      new Uint8Array(32).fill(0x11),
      new Uint8Array(32).fill(0x22),
    );
  }

  it('succeeds on first attempt', async () => {
    mockSend.mockResolvedValueOnce({ Signature: makeMockDerSig().buffer });
    const result = await signWithKms(new Uint8Array(32).fill(0xaa), 'alias/k');
    expect(mockSend).toHaveBeenCalledTimes(1);
    expect(result.r).toEqual(new Uint8Array(32).fill(0x11));
    expect(result.s).toEqual(new Uint8Array(32).fill(0x22));
  });

  it('retries on failure and succeeds on second attempt', async () => {
    const derSig = makeMockDerSig();
    mockSend
      .mockRejectedValueOnce(new Error('KMS throttle'))
      .mockResolvedValueOnce({ Signature: derSig.buffer });

    const promise = signWithKms(new Uint8Array(32).fill(0xbb), 'alias/k');
    // Advance past the 200ms backoff delay and flush microtasks
    await vi.advanceTimersByTimeAsync(250);
    const result = await promise;

    expect(mockSend).toHaveBeenCalledTimes(2);
    expect(result.r).toBeDefined();
    expect(result.s).toBeDefined();
  });

  it('retries twice and succeeds on third attempt', async () => {
    const derSig = makeMockDerSig();
    mockSend
      .mockRejectedValueOnce(new Error('fail 1'))
      .mockRejectedValueOnce(new Error('fail 2'))
      .mockResolvedValueOnce({ Signature: derSig.buffer });

    const promise = signWithKms(new Uint8Array(32).fill(0xcc), 'alias/k');
    // Advance past both backoff delays (200ms + 400ms) in one go
    await vi.advanceTimersByTimeAsync(700);
    const result = await promise;

    expect(mockSend).toHaveBeenCalledTimes(3);
    expect(result.r).toBeDefined();
    expect(result.s).toBeDefined();
  });

  it('fails after all 3 attempts are exhausted', async () => {
    // Use real timers for this test to avoid unhandled rejection timing issues
    vi.useRealTimers();
    mockSend.mockRejectedValue(new Error('KMS unavailable'));

    const hash = new Uint8Array(32).fill(0xdd);
    await expect(signWithKms(hash, 'alias/k')).rejects.toThrow('KMS unavailable');
    expect(mockSend).toHaveBeenCalledTimes(3);
  });
});

// ─── getKmsPublicKey tests ───
describe('getKmsPublicKey', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('returns the public key from KMS', async () => {
    const fakePubKey = new Uint8Array(91).fill(0x04);
    mockSend.mockResolvedValueOnce({ PublicKey: fakePubKey.buffer });

    const result = await getKmsPublicKey('alias/fresh-key');
    expect(result).toEqual(fakePubKey);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('caches the public key for the same keyId', async () => {
    const fakePubKey = new Uint8Array(91).fill(0x05);
    mockSend.mockResolvedValueOnce({ PublicKey: fakePubKey.buffer });

    const result1 = await getKmsPublicKey('alias/cache-key');
    const result2 = await getKmsPublicKey('alias/cache-key');

    expect(result1).toEqual(fakePubKey);
    expect(result2).toEqual(fakePubKey);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });
});
