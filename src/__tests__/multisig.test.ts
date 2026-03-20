import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getMultiSigConfig } from '../multisig.js';

describe('getMultiSigConfig', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Reset env for each test
    delete process.env.MULTISIG_ENABLED;
    delete process.env.MULTISIG_THRESHOLD;
    delete process.env.MULTISIG_KEYS;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('returns single-key config when MULTISIG_ENABLED is not set', () => {
    const config = getMultiSigConfig();
    expect(config.enabled).toBe(false);
    expect(config.threshold).toBe(1);
    expect(config.totalKeys).toBe(1);
    expect(config.keys).toHaveLength(1);
    expect(config.keys[0].signingMethod).toBe('kms');
  });

  it('returns single-key config when MULTISIG_ENABLED is false', () => {
    process.env.MULTISIG_ENABLED = 'false';
    const config = getMultiSigConfig();
    expect(config.enabled).toBe(false);
    expect(config.threshold).toBe(1);
  });

  it('returns multi-sig config when enabled', () => {
    process.env.MULTISIG_ENABLED = 'true';
    process.env.MULTISIG_THRESHOLD = '2';
    process.env.MULTISIG_KEYS = 'kms:key-123:Primary,manual:02abcd1234:ColdKey';

    const config = getMultiSigConfig();
    expect(config.enabled).toBe(true);
    expect(config.threshold).toBe(2);
    expect(config.totalKeys).toBe(2);
    expect(config.keys).toHaveLength(2);
    expect(config.keys[0].signingMethod).toBe('kms');
    expect(config.keys[0].label).toBe('Primary');
    expect(config.keys[0].kmsKeyId).toBe('key-123');
    expect(config.keys[1].signingMethod).toBe('manual');
    expect(config.keys[1].publicKeyHex).toBe('02abcd1234');
    expect(config.keys[1].label).toBe('ColdKey');
  });

  it('defaults threshold to 2 when not specified', () => {
    process.env.MULTISIG_ENABLED = 'true';
    process.env.MULTISIG_KEYS = 'kms:key-1:A,manual:02ff:B';

    const config = getMultiSigConfig();
    expect(config.threshold).toBe(2);
  });

  it('handles 3-of-3 configuration', () => {
    process.env.MULTISIG_ENABLED = 'true';
    process.env.MULTISIG_THRESHOLD = '3';
    process.env.MULTISIG_KEYS = 'kms:k1:Hot,manual:02aa:Cold,manual:02bb:Recovery';

    const config = getMultiSigConfig();
    expect(config.threshold).toBe(3);
    expect(config.totalKeys).toBe(3);
    expect(config.keys[2].label).toBe('Recovery');
  });

  it('description reflects threshold and key count', () => {
    process.env.MULTISIG_ENABLED = 'true';
    process.env.MULTISIG_THRESHOLD = '2';
    process.env.MULTISIG_KEYS = 'kms:k1:A,manual:02aa:B,manual:02bb:C';

    const config = getMultiSigConfig();
    expect(config.description).toContain('2-of-3');
  });
});
