/**
 * Multi-Signature / Threshold Key Configuration
 *
 * Enterprises rarely rely on a single signing key. This module provides
 * configuration and utilities for Hedera threshold key (KeyList) support.
 *
 * Architecture:
 *   Account Key (KeyList, threshold=2)
 *   ├── KMS Key (hot signer — Lambda)
 *   ├── Cold Key (offline/hardware — manual approval)
 *   └── Recovery Key (break-glass — vault)
 *
 * The KMS key signs via Lambda automatically. Additional signatures
 * (cold key, recovery key) are collected out-of-band and attached
 * before submission when the threshold requires them.
 */

export interface MultiSigKeyEntry {
  /** Human-readable label for this key */
  label: string;
  /** Hedera-compatible compressed public key (hex) */
  publicKeyHex: string;
  /** Signing method: 'kms' (automatic), 'manual' (out-of-band) */
  signingMethod: 'kms' | 'manual';
  /** For KMS keys: the KMS key ID */
  kmsKeyId?: string;
}

export interface MultiSigConfig {
  /** Whether multi-sig is enabled for this deployment */
  enabled: boolean;
  /** Number of signatures required to authorize a transaction */
  threshold: number;
  /** Total number of keys in the KeyList */
  totalKeys: number;
  /** Key entries */
  keys: MultiSigKeyEntry[];
  /** Description of the multi-sig policy */
  description: string;
}

/**
 * Load multi-sig configuration from environment variables.
 *
 * For MVP, multi-sig is configured via environment variables:
 *   MULTISIG_ENABLED=true
 *   MULTISIG_THRESHOLD=2
 *   MULTISIG_KEYS=kms:<keyId>:<label>,manual:<pubKeyHex>:<label>
 *
 * When disabled, the system operates in single-key mode (KMS only).
 */
export function getMultiSigConfig(): MultiSigConfig {
  const enabled = process.env.MULTISIG_ENABLED === 'true';

  if (!enabled) {
    return {
      enabled: false,
      threshold: 1,
      totalKeys: 1,
      keys: [
        {
          label: 'KMS Primary',
          publicKeyHex: '(derived at runtime from KMS)',
          signingMethod: 'kms',
          kmsKeyId: process.env.KMS_KEY_ID ?? 'alias/hedera-signer-dev',
        },
      ],
      description:
        'Single-key mode. The KMS key is the sole signer. ' +
        'Enable MULTISIG_ENABLED=true for threshold key support.',
    };
  }

  const threshold = Number(process.env.MULTISIG_THRESHOLD ?? '2');
  const keysRaw = process.env.MULTISIG_KEYS ?? '';

  const keys: MultiSigKeyEntry[] = keysRaw
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [method, id, label] = entry.split(':');
      if (method === 'kms') {
        return {
          label: label ?? 'KMS Key',
          publicKeyHex: '(derived at runtime)',
          signingMethod: 'kms' as const,
          kmsKeyId: id,
        };
      }
      return {
        label: label ?? 'Manual Key',
        publicKeyHex: id,
        signingMethod: 'manual' as const,
      };
    });

  return {
    enabled: true,
    threshold,
    totalKeys: keys.length,
    keys,
    description:
      `Threshold key mode: ${threshold}-of-${keys.length} signatures required. ` +
      `KMS keys sign automatically; manual keys require out-of-band signatures.`,
  };
}
