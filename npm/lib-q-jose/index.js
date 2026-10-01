import { createHash, timingSafeEqual } from 'node:crypto';
import { MlDsa } from '@lib-q/sig';

const ALGORITHM = 'ML-DSA-65';
const EMPTY_CONTEXT = new Uint8Array(0);
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const MAX_JWS_BYTES = 1024 * 1024;
const MAX_JWKS_BYTES = 1024 * 1024;
const CACHE_TTL_MS = 5 * 60 * 1000;
const remoteSets = new Map();

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function nonemptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function decodeBase64url(value) {
  requireValue(typeof value === 'string' && /^[A-Za-z0-9_-]*$/.test(value), 'Invalid base64url');
  const bytes = Buffer.from(value, 'base64url');
  requireValue(bytes.toString('base64url') === value, 'Noncanonical base64url');
  return bytes;
}

function decodeObject(bytes) {
  const value = JSON.parse(utf8.decode(bytes));
  requireValue(isObject(value), 'Expected a JSON object');
  return value;
}

/** Import a public RFC 9964 AKP and compute its RFC 7638 SHA-256 thumbprint. */
export function importAkpJwk(jwk) {
  requireValue(isObject(jwk) && jwk.kty === 'AKP' && jwk.alg === ALGORITHM, 'Expected an ML-DSA-65 AKP');
  requireValue(!('priv' in jwk), 'Private JWK material is not accepted');
  requireValue(jwk.use === undefined || jwk.use === 'sig', 'JWK use must be sig');
  requireValue(jwk.key_ops === undefined || (Array.isArray(jwk.key_ops) &&
    jwk.key_ops.length === 1 && jwk.key_ops[0] === 'verify'), 'JWK key_ops must permit only verify');
  requireValue(jwk.kid === undefined || nonemptyString(jwk.kid), 'Invalid JWK kid');
  requireValue(typeof jwk.pub === 'string' && jwk.pub.length === 2603, 'Invalid ML-DSA-65 public key length');
  const publicKey = decodeBase64url(jwk.pub);
  requireValue(publicKey.length === 1952, 'Invalid ML-DSA-65 public key length');
  // Only required members, in lexicographic order (RFC 9964 section 6).
  const canonical = JSON.stringify({ alg: ALGORITHM, kty: 'AKP', pub: jwk.pub });
  const thumbprint = createHash('sha256').update(canonical).digest('base64url');
  return { publicKey, thumbprint, kid: jwk.kid ?? thumbprint };
}

function parseCompact(jws) {
  requireValue(typeof jws === 'string' && jws.length <= MAX_JWS_BYTES, 'Invalid compact JWS');
  const parts = jws.split('.');
  requireValue(parts.length === 3 && parts[0].length > 0, 'Expected compact JWS');
  const header = decodeObject(decodeBase64url(parts[0]));
  requireValue(header.alg === ALGORITHM, 'Only ML-DSA-65 is accepted');
  requireValue(nonemptyString(header.kid), 'Protected kid is required');
  // No extensions are implemented. In particular, never reinterpret the signing input
  // as an unencoded/detached payload, or follow a token-supplied jku/x5u/jwk.
  requireValue(!('crit' in header), 'Critical extensions are not supported');
  requireValue(header.b64 === undefined || header.b64 === true, 'Unencoded payloads are not supported');
  const payload = decodeBase64url(parts[1]);
  requireValue(parts[2].length === 4412, 'Invalid ML-DSA-65 signature length');
  const signature = decodeBase64url(parts[2]);
  requireValue(signature.length === 3309, 'Invalid ML-DSA-65 signature length');
  return { header, payload, signature, signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii') };
}

function validateJwks(jwks) {
  requireValue(isObject(jwks) && Array.isArray(jwks.keys) && jwks.keys.every(isObject), 'Invalid JWKS');
  return jwks;
}

function matchingKeys(jwks, kid) {
  return validateJwks(jwks).keys.filter(key => key.kid === kid);
}

function verifyParsed(parsed, jwks) {
  const keys = matchingKeys(jwks, parsed.header.kid);
  requireValue(keys.length === 1, keys.length === 0 ? 'Unknown kid' : 'Ambiguous kid');
  const { publicKey } = importAkpJwk(keys[0]);
  requireValue(typeof MlDsa.ml_dsa_65 === 'function', 'Install the patched @lib-q/sig Node build with MlDsa.ml_dsa_65');
  const verifier = MlDsa.ml_dsa_65();
  try {
    requireValue(verifier.verify_with_context_wasm(publicKey, parsed.signingInput, EMPTY_CONTEXT, parsed.signature) === true,
      'Invalid ML-DSA-65 signature');
  } finally {
    verifier.free();
  }
  return parsed.payload;
}

/** Verify the original compact signing input; return authenticated payload bytes. */
export function verifyCompactJws(jws, jwks, options) {
  requireValue(isObject(options) && Array.isArray(options.algorithms) &&
    options.algorithms.length === 1 && options.algorithms[0] === ALGORITHM, 'Pin algorithms to ["ML-DSA-65"]');
  return verifyParsed(parseCompact(jws), jwks);
}

async function fetchJwks(url) {
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(5000), headers: { accept: 'application/json' } });
  requireValue(response.ok && response.body !== null, 'JWKS fetch failed');
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      requireValue(length <= MAX_JWKS_BYTES, 'JWKS response too large');
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
  }
  return validateJwks(decodeObject(Buffer.concat(chunks, length)));
}

const DEFAULT_KID_REFETCH_COOLDOWN_MS = 30 * 1000;

async function refreshRemote(url, entry) {
  if (!entry.pending) {
    entry.pending = fetchJwks(url).then(jwks => {
      entry.jwks = jwks;
      entry.expires = Date.now() + CACHE_TTL_MS;
      return jwks;
    }).finally(() => { entry.pending = undefined; });
  }
  return entry.pending;
}

async function remoteJwks(uri, kid, kidRefetchCooldownMs) {
  requireValue(nonemptyString(uri), 'jwksUri must be a configured HTTPS URL');
  const url = new URL(uri);
  requireValue(url.protocol === 'https:' && !url.username && !url.password && !url.hash,
    'jwksUri must be a configured HTTPS URL without credentials or fragment');
  const key = url.href;
  let entry = remoteSets.get(key);
  if (!entry) {
    // Bound process-wide cache growth. The URI must come from configuration, not a token.
    if (remoteSets.size >= 64) remoteSets.delete(remoteSets.keys().next().value);
    entry = { jwks: undefined, expires: 0, pending: undefined, lastRotationFetch: 0 };
    remoteSets.set(key, entry);
  }
  const fresh = !entry.jwks || Date.now() >= entry.expires;
  let jwks = fresh ? await refreshRemote(key, entry) : entry.jwks;
  // A fresh response is already authoritative. A cached miss gets one rotation fetch, throttled
  // so a flood of tokens carrying an unknown kid cannot be used to hammer the JWKS endpoint.
  const now = Date.now();
  if (!fresh && matchingKeys(jwks, kid).length === 0 && now - entry.lastRotationFetch >= kidRefetchCooldownMs) {
    entry.lastRotationFetch = now;
    jwks = await refreshRemote(key, entry);
  }
  return jwks;
}

function numericDate(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

/** Authenticate an OIDC ID token. No userinfo or classical-signature fallback. */
export async function verifyIdToken(jws, options) {
  requireValue(isObject(options), 'ID token options are required');
  const { issuer, audience, nonce, clockToleranceSec = 0, kidRefetchCooldownMs = DEFAULT_KID_REFETCH_COOLDOWN_MS } = options;
  requireValue(nonemptyString(issuer) && nonemptyString(audience) && nonemptyString(nonce),
    'Expected issuer, audience, and transaction nonce');
  requireValue(numericDate(clockToleranceSec) && clockToleranceSec >= 0 && clockToleranceSec <= 300, 'Invalid clock tolerance');
  requireValue(numericDate(kidRefetchCooldownMs) && kidRefetchCooldownMs >= 0, 'Invalid kid refetch cooldown');
  requireValue((options.jwks !== undefined) !== (options.jwksUri !== undefined), 'Supply exactly one of jwks or jwksUri');
  const parsed = parseCompact(jws);
  const jwks = options.jwks ?? await remoteJwks(options.jwksUri, parsed.header.kid, kidRefetchCooldownMs);
  const claims = decodeObject(verifyParsed(parsed, jwks));
  const now = Date.now() / 1000;
  requireValue(claims.iss === issuer, 'Issuer mismatch');
  requireValue(nonemptyString(claims.sub), 'Missing subject');
  const audiences = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
  requireValue(Array.isArray(audiences) && audiences.length > 0 && audiences.every(nonemptyString) &&
    new Set(audiences).size === audiences.length && audiences.includes(audience), 'Audience mismatch');
  requireValue((audiences.length === 1 && claims.azp === undefined) || claims.azp === audience, 'Authorized party mismatch');
  requireValue(numericDate(claims.exp) && claims.exp > now - clockToleranceSec, 'Expired or invalid exp');
  requireValue(numericDate(claims.iat) && claims.iat <= now + clockToleranceSec && claims.iat < claims.exp, 'Invalid iat');
  requireValue(claims.nbf === undefined || (numericDate(claims.nbf) && claims.nbf <= now + clockToleranceSec), 'Token not yet valid');
  requireValue(nonemptyString(claims.nonce), 'Missing nonce');
  const expectedNonce = Buffer.from(nonce);
  const actualNonce = Buffer.from(claims.nonce);
  requireValue(expectedNonce.length === actualNonce.length && timingSafeEqual(expectedNonce, actualNonce), 'Nonce mismatch');
  return claims;
}
