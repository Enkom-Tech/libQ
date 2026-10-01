export interface AkpJwk {
  kty: 'AKP';
  alg: 'ML-DSA-65';
  /** Unpadded base64url encoding of the 1952-byte public key. */
  pub: string;
  kid?: string;
  use?: 'sig';
  key_ops?: readonly ['verify'];
  [member: string]: unknown;
}

export interface Jwks {
  /** Non-selected keys may use other algorithms. The selected key must be an AKP. */
  keys: readonly Record<string, unknown>[];
}

export interface ImportedAkpJwk {
  publicKey: Uint8Array;
  /** RFC 7638 SHA-256 thumbprint over alg, kty, pub (RFC 9964 section 6). */
  thumbprint: string;
  /** Supplied kid, or the thumbprint when absent. */
  kid: string;
}

export function importAkpJwk(jwk: unknown): ImportedAkpJwk;

export interface CompactJwsOptions {
  algorithms: readonly ['ML-DSA-65'];
}

/** Synchronous; throws on malformed input, ambiguous/missing kid, or invalid signature.
 * Returns authenticated payload bytes, not JSON. Does not validate JWT claims.
 */
export function verifyCompactJws(jws: string, jwks: Jwks, options: CompactJwsOptions): Uint8Array;

export type IdTokenOptions = {
  issuer: string;
  /** OIDC client ID. */
  audience: string;
  /** Expected nonce from the login transaction; required and nonempty. */
  nonce: string;
  /** Nonnegative finite seconds, capped at 300; default zero. */
  clockToleranceSec?: number;
  /** Minimum milliseconds between rotation refetches for an unrecognized kid on a given
   * jwksUri, to bound how often an attacker-supplied unknown kid can force a fetch.
   * Nonnegative; default 30000 (30s). Only meaningful with jwksUri. */
  kidRefetchCooldownMs?: number;
} & ({ jwks: Jwks; jwksUri?: never } | { jwksUri: string; jwks?: never });

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  azp?: string;
  exp: number;
  iat: number;
  nonce: string;
  nbf?: number;
  [claim: string]: unknown;
}

/** Signature + iss/sub/aud/azp/exp/iat/nonce and optional nbf validation.
 * Remote keys require a caller-configured HTTPS URL, are cached for five minutes,
 * and refreshed once on a cached kid miss. Rejects on fetch/validation failure.
 */
export function verifyIdToken(jws: string, options: IdTokenOptions): Promise<IdTokenClaims>;
