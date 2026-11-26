/**
 * A seal check: the application's own check of a replica, run in place of
 * the verifier's appraisal. It fetches and checks a fresh attestation
 * document, and returns the X25519 HPKE public key that the one request
 * about to be sent is sealed to. The client never imports the check, so
 * this package stays independent of it.
 *
 * Its result is reported as a {@link SealChecked}: the key, under the hpke
 * id, and an expiry, with none of a {@link Verification}'s code, config or
 * measurement facts, since the verifier appraised none of them. The
 * transport code works on {@link Attested}, either kind.
 */
import { CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT, toHex, type CryptoMaterialItem, type Verification } from "@tinfoilsh/verifier";
import { AttestationError, ConfigurationError } from "../errors.js";
import type { SealCheck } from "../options.js";

/** The gap a seal check's key may wait for the send that claims it; each check protects one send only. */
export const SEAL_CHECK_LIFETIME_MS = 60_000;
const HPKE_KEY_BYTES = 32;

const SEAL_CHECKED: unique symbol = Symbol("SealChecked");

/** A seal check's result, as the transport code reads a verification. */
export interface SealChecked {
  readonly [SEAL_CHECKED]: true;
  readonly cryptoMaterial: readonly CryptoMaterialItem[];
  readonly freshnessExpiresAt: Date;
  readonly hpkePublicKey: string;
  readonly tlsPublicKeyFP?: undefined;
}

/** What the transport code reads of a verification: the verifier's, or a seal check's. */
export type Attested = Verification | SealChecked;

export function isSealChecked(v: Attested): v is SealChecked {
  return SEAL_CHECKED in v;
}

/** `v` as the verifier's verification; a seal check's result, which has none of its facts, is a {@link ConfigurationError}. */
export function asVerification(v: Attested): Verification {
  if (isSealChecked(v)) throw new ConfigurationError("with a seal check, the client holds no verification: the seal check's own result describes the replica");
  return v;
}

/**
 * Runs `check` for `host`, through `relay`, and reports its key. A refusal
 * or a malformed key throws, for the enclave to report as a rejection.
 */
export async function runSealCheck(check: SealCheck, host: string, relay: string | undefined, now: Date, signal?: AbortSignal): Promise<SealChecked> {
  const key = await check({ relay: relay ?? "", host }, signal);
  if (!(key instanceof Uint8Array) || key.length !== HPKE_KEY_BYTES) {
    throw new AttestationError(`returned an HPKE key that isn't ${HPKE_KEY_BYTES} bytes`);
  }
  const hpkePublicKey = toHex(key);
  return Object.freeze({
    [SEAL_CHECKED]: true as const,
    cryptoMaterial: Object.freeze([Object.freeze({ id: CRYPTO_MATERIAL_ID_HPKE, format: KEY_X25519_HPKE_V1_FORMAT, data: hpkePublicKey })]),
    freshnessExpiresAt: new Date(now.getTime() + SEAL_CHECK_LIFETIME_MS),
    hpkePublicKey,
  });
}
