import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test, after } from 'node:test';
import { MlDsa } from '@lib-q/sig';
import { importAkpJwk, verifyCompactJws, verifyIdToken } from '../index.js';

const signer = MlDsa.ml_dsa_65();
const pair = signer.generate_keypair_wasm(new Uint8Array(32).fill(7));
const secret = pair.secret_key;
const publicKey = pair.public_key;
after(() => { secret.fill(0); pair.free(); signer.free(); });
const jwk = { kty: 'AKP', alg: 'ML-DSA-65', pub: Buffer.from(publicKey).toString('base64url') };
jwk.kid = importAkpJwk(jwk).thumbprint;
const jwks = { keys: [jwk] };
const pinned = { algorithms: ['ML-DSA-65'] };
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const options = { jwks, issuer: 'https://id.example', audience: 'client', nonce: 'transaction-nonce' };
const now = Math.floor(Date.now() / 1000);
const claims = { iss: options.issuer, sub: 'subject', aud: options.audience, nonce: options.nonce, iat: now - 60, exp: now + 3600 };

function sign(payload = claims, header = {}, context = new Uint8Array()) {
  const input = `${encode({ alg: 'ML-DSA-65', kid: jwk.kid, ...header })}.${encode(payload)}`;
  const sig = signer.sign_with_context_wasm(secret, Buffer.from(input), context, new Uint8Array(32));
  return `${input}.${Buffer.from(sig).toString('base64url')}`;
}

const token = sign();

test('lib-q-sig signer verifies compact bytes and an ID token', async () => {
  assert.deepEqual(JSON.parse(Buffer.from(verifyCompactJws(token, jwks, pinned)).toString()), claims);
  assert.deepEqual(await verifyIdToken(token, options), claims);
});

test('AKP thumbprint uses exactly alg/kty/pub in RFC 9964 order', () => {
  const expected = createHash('sha256').update(`{"alg":"ML-DSA-65","kty":"AKP","pub":"${jwk.pub}"}`).digest('base64url');
  const imported = importAkpJwk({ ...jwk, kid: 'issuer-key', use: 'sig', key_ops: ['verify'] });
  assert.equal(imported.thumbprint, expected);
  assert.equal(imported.kid, 'issuer-key');
  assert.deepEqual(imported.publicKey, Buffer.from(publicKey));
  assert.equal(importAkpJwk({ ...jwk, kid: undefined }).kid, expected);
});

test('tampered payload, signature, and context never verify', () => {
  const [h, p, s] = token.split('.');
  assert.throws(() => verifyCompactJws(`${h}.${encode({ ...claims, sub: 'attacker' })}.${s}`, jwks, pinned));
  const bad = Buffer.from(s, 'base64url'); bad[100] ^= 1;
  assert.throws(() => verifyCompactJws(`${h}.${p}.${bad.toString('base64url')}`, jwks, pinned));
  assert.throws(() => verifyCompactJws(sign(claims, {}, Buffer.from('other-protocol')), jwks, pinned));
});

test('kid selection rejects unknown, absent, duplicate, and wrong-key bindings', () => {
  assert.throws(() => verifyCompactJws(sign(claims, { kid: 'unknown' }), jwks, pinned));
  assert.throws(() => verifyCompactJws(sign(claims, { kid: undefined }), jwks, pinned));
  assert.throws(() => verifyCompactJws(token, { keys: [jwk, { ...jwk }] }, pinned));
  const other = signer.generate_keypair_wasm(new Uint8Array(32).fill(9));
  try {
    const key = { ...jwk, pub: Buffer.from(other.public_key).toString('base64url') };
    assert.throws(() => verifyCompactJws(token, { keys: [key] }, pinned));
  } finally { other.secret_key.fill(0); other.free(); }
  // Unrelated key types do not prevent selecting the configured ML-DSA key.
  assert.deepEqual(verifyCompactJws(token, { keys: [{ kty: 'EC', kid: 'other' }, jwk] }, pinned), verifyCompactJws(token, jwks, pinned));
});

for (const alg of ['none', 'ES256', 'RS256', 'EdDSA']) {
  test(`refuses protected alg ${alg} even with a valid ML-DSA signature`, () => {
    assert.throws(() => verifyCompactJws(sign(claims, { alg }), jwks, pinned));
  });
}

test('algorithm policy cannot be widened or omitted', () => {
  for (const algorithms of [[], ['ES256'], ['ML-DSA-65', 'ES256']]) {
    assert.throws(() => verifyCompactJws(token, jwks, { algorithms }));
  }
  assert.throws(() => verifyCompactJws(token, jwks));
});

test('key import rejects invalid lengths, key type, algorithm, private material, and use', () => {
  for (const patch of [
    { pub: Buffer.alloc(1951).toString('base64url') },
    { pub: Buffer.alloc(1953).toString('base64url') },
    { pub: `${jwk.pub}=` }, { kty: 'OKP' }, { alg: 'ES256' },
    { priv: '' }, { use: 'enc' }, { key_ops: ['sign'] }, { kid: '' },
  ]) assert.throws(() => importAkpJwk({ ...jwk, ...patch }));
  const wrongLength = { keys: [{ ...jwk, pub: Buffer.alloc(32).toString('base64url') }] };
  assert.throws(() => verifyCompactJws(token, wrongLength, pinned));
});

test('rejects malformed compact serialization and unsupported protected extensions', () => {
  for (const value of ['', 'a.b', `${token}.extra`, token.replace('.', '=.'), `[].${token}`]) {
    assert.throws(() => verifyCompactJws(value, jwks, pinned));
  }
  for (const header of [{ crit: ['new'] }, { crit: [] }, { b64: false }, { b64: 'true' }]) {
    assert.throws(() => verifyCompactJws(sign(claims, header), jwks, pinned));
  }
  assert.deepEqual(verifyCompactJws(sign(claims, { b64: true }), jwks, pinned), verifyCompactJws(token, jwks, pinned));
});

test('ID token rejects an expired token even when iat < exp both lie in the past', async () => {
  // Isolates the `claims.exp > now - clockToleranceSec` check (index.js verifyIdToken, the exp
  // line): iat < exp holds here, so the separate iat<exp check cannot mask removal of this one.
  const expired = { ...claims, iat: now - 3600, exp: now - 1800 };
  await assert.rejects(verifyIdToken(sign(expired), options), /exp/i);
});

test('ID token rejects iat after exp even when exp is in the future and iat is within tolerance', async () => {
  // Isolates the `claims.iat < claims.exp` half of the iat check (index.js verifyIdToken, the iat
  // line) from its `claims.iat <= now + clockToleranceSec` half: a generous tolerance keeps iat's
  // own bound satisfied, so only iat<exp can be responsible for the rejection.
  const iatAfterExp = { ...claims, exp: now + 100, iat: now + 200 };
  await assert.rejects(verifyIdToken(sign(iatAfterExp), { ...options, clockToleranceSec: 300 }), /iat/i);
});

test('ID token enforces issuer, subject, audience/azp, times, and transaction nonce', async () => {
  for (const patch of [
    { iss: 'https://attacker.example' }, { sub: '' }, { sub: undefined },
    { aud: 'other' }, { aud: [] }, { aud: ['client', 1] }, { aud: ['client', 'client'] },
    { aud: ['client', 'other'] }, { aud: ['client', 'other'], azp: 'other' }, { azp: 'other' },
    { exp: now - 100 }, { exp: String(now + 3600) }, { exp: undefined },
    { iat: now + 300 }, { iat: undefined }, { iat: '0' }, { iat: now - 60, exp: now - 61 },
    { nonce: undefined }, { nonce: 'other' }, { nbf: now + 300 }, { nbf: '0' },
  ]) await assert.rejects(verifyIdToken(sign({ ...claims, ...patch }), options));
  const multi = { ...claims, aud: ['other', 'client'], azp: 'client' };
  assert.deepEqual(await verifyIdToken(sign(multi), options), multi);
  const tolerated = { ...claims, iat: now + 20, nbf: now + 20 };
  assert.deepEqual(await verifyIdToken(sign(tolerated), { ...options, clockToleranceSec: 30 }), tolerated);
  const expiredWithinTolerance = { ...claims, exp: now - 5 };
  assert.deepEqual(await verifyIdToken(sign(expiredWithinTolerance), { ...options, clockToleranceSec: 30 }), expiredWithinTolerance);
});

test('ID token refuses missing expectations, invalid options, and non-object claims', async () => {
  for (const patch of [
    { issuer: '' }, { audience: '' }, { nonce: undefined }, { clockToleranceSec: -1 },
    { clockToleranceSec: Infinity }, { jwksUri: 'https://id.example/keys' }, { jwks: undefined },
  ]) await assert.rejects(verifyIdToken(token, { ...options, ...patch }));
  await assert.rejects(verifyIdToken(sign(['not', 'claims']), options));
});

test('remote JWKS caches hits, refetches on rotation, coalesces misses, and fails closed', async t => {
  let calls = 0;
  let servedKeys = { keys: [{ ...jwk, kid: 'old' }] };
  let status = 200;
  // kidRefetchCooldownMs: 0 disables the rotation-refetch throttle added elsewhere in this suite,
  // since this test's assertions are specifically about triggering a fresh fetch per rotation.
  const remoteOptions = { ...options, jwks: undefined, jwksUri: 'https://issuer.example/jwks', kidRefetchCooldownMs: 0 };
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, remoteOptions.jwksUri);
    assert.equal(init.redirect, 'error');
    calls++;
    return new Response(JSON.stringify(servedKeys), { status });
  });
  const oldToken = sign(claims, { kid: 'old', jku: 'https://attacker.example/keys' });
  assert.deepEqual(await verifyIdToken(oldToken, remoteOptions), claims);
  assert.deepEqual(await verifyIdToken(oldToken, remoteOptions), claims);
  assert.equal(calls, 1);
  servedKeys = jwks;
  const results = await Promise.all(Array.from({ length: 4 }, () => verifyIdToken(token, remoteOptions)));
  for (const result of results) assert.deepEqual(result, claims);
  assert.equal(calls, 2);
  await assert.rejects(verifyIdToken(oldToken, remoteOptions));
  assert.equal(calls, 3);
  // Signature errors must not provoke a fetch.
  const [h, p, s] = token.split('.');
  const corrupted = Buffer.from(s, 'base64url'); corrupted[0] ^= 1;
  await assert.rejects(verifyIdToken(`${h}.${p}.${corrupted.toString('base64url')}`, remoteOptions));
  assert.equal(calls, 3);
  status = 503;
  await assert.rejects(verifyIdToken(oldToken, remoteOptions));
  status = 200; servedKeys = { keys: 'invalid' };
  await assert.rejects(verifyIdToken(oldToken, remoteOptions));
  await assert.rejects(verifyIdToken(token, { ...remoteOptions, jwksUri: 'http://issuer.example/keys' }));
});

test('protected header requires a kid', () => {
  assert.throws(() => verifyCompactJws(sign(claims, { kid: undefined }), jwks, pinned), /kid is required/i);
});

test('base64url decoding rejects non-canonical encodings', () => {
  const [h, p, s] = token.split('.');
  // "AB" and "AA" both decode to the same single zero byte (the trailing 4 bits of "B" are
  // dropped), but "AA" is the only canonical encoding of that byte; JOSE requires exact
  // reproduction, not merely a decodable string, so appending it must not silently normalize.
  assert.equal(Buffer.from('AB', 'base64url').toString('base64url'), 'AA');
  assert.throws(() => verifyCompactJws(`${h}AB.${p}.${s}`, jwks, pinned), /[Nn]oncanonical base64url/);
  assert.throws(() => verifyCompactJws(`${h}+.${p}.${s}`, jwks, pinned), /Invalid base64url/);
});

test('JWKS responses over the size cap are rejected without buffering unbounded data', async t => {
  const remoteOptions = { ...options, jwks: undefined, jwksUri: 'https://issuer.example/jwks-oversized' };
  const oversized = JSON.stringify({ keys: [jwk], pad: 'x'.repeat(2 * 1024 * 1024) });
  t.mock.method(globalThis, 'fetch', async () => new Response(oversized, { status: 200 }));
  await assert.rejects(verifyIdToken(token, remoteOptions), /too large/i);
});

test('verifies the original protected header bytes, not a re-encoded JSON.stringify of it', () => {
  // Re-serializing the header with different whitespace/key order changes the base64url segment
  // and therefore the signing input; the signature must fail against the re-encoded bytes even
  // though the decoded header object is deep-equal.
  const [h, p, s] = token.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  assert.deepEqual(header, { alg: 'ML-DSA-65', kid: jwk.kid });
  const reencoded = Buffer.from(JSON.stringify(header, Object.keys(header).sort())).toString('base64url');
  if (reencoded !== h) assert.throws(() => verifyCompactJws(`${reencoded}.${p}.${s}`, jwks, pinned));
  const withSpace = Buffer.from(JSON.stringify(header) + ' ').toString('base64url');
  assert.notEqual(withSpace, h);
  assert.throws(() => verifyCompactJws(`${withSpace}.${p}.${s}`, jwks, pinned));
});

test('remote JWKS is only ever fetched over HTTPS, even if a fake fetch would happily serve http', async t => {
  t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify(jwks), { status: 200 }));
  const httpOptions = { ...options, jwks: undefined, jwksUri: 'http://issuer.example/jwks' };
  await assert.rejects(verifyIdToken(token, httpOptions), /HTTPS/);
});

test('unknown-kid rotation refetch is throttled to at most one per cooldown window', async t => {
  let calls = 0;
  let servedKeys = { keys: [{ ...jwk, kid: 'old' }] };
  const remoteOptions = { ...options, jwks: undefined, jwksUri: 'https://issuer.example/jwks-cooldown', kidRefetchCooldownMs: 10_000 };
  t.mock.method(globalThis, 'fetch', async () => { calls++; return new Response(JSON.stringify(servedKeys), { status: 200 }); });
  const oldToken = sign(claims, { kid: 'old' });
  await verifyIdToken(oldToken, remoteOptions);
  assert.equal(calls, 1);
  // The cache is fresh (within CACHE_TTL_MS) and `token`'s kid is unknown to it, so this first
  // lookup against an unknown kid gets its one rotation refetch.
  await assert.rejects(verifyIdToken(token, remoteOptions));
  assert.equal(calls, 2);
  // A second unknown-kid lookup immediately afterward falls inside the cooldown window from the
  // refetch above, so it must not trigger another fetch.
  await assert.rejects(verifyIdToken(token, remoteOptions));
  assert.equal(calls, 2);
  // With cooldown disabled, an unknown kid triggers a fresh rotation fetch every time.
  const noCooldown = { ...remoteOptions, jwksUri: 'https://issuer.example/jwks-cooldown-2', kidRefetchCooldownMs: 0 };
  await verifyIdToken(oldToken, noCooldown);
  assert.equal(calls, 3);
  await assert.rejects(verifyIdToken(token, noCooldown));
  assert.equal(calls, 4);
  servedKeys = jwks;
  assert.deepEqual(await verifyIdToken(token, noCooldown), claims);
  assert.equal(calls, 5);
});

test('existing FIPS 204 ML-DSA-65 KAT matches hashes and verifies through WASM', () => {
  // Byte-for-byte upstream libcrux/dilithium-py KAT: FIPS 204, NOT a NIST ACVP vector.
  // Provenance: lib-q-ml-dsa/tests/kats/PROVENANCE.md; no generated fixture added here.
  const vectors = JSON.parse(readFileSync(new URL('../../../lib-q-ml-dsa/tests/kats/dilithium-py-kats-65.json', import.meta.url)));
  const kat = vectors[0];
  const kp = signer.generate_keypair_wasm(Buffer.from(kat.key_generation_seed, 'hex'));
  const sk = kp.secret_key;
  const hash = bytes => createHash('sha3-256').update(bytes).digest('hex');
  try {
    assert.equal(hash(kp.public_key), kat.sha3_256_hash_of_verification_key);
    assert.equal(hash(sk), kat.sha3_256_hash_of_signing_key);
    const message = Buffer.from(kat.message, 'hex');
    const signature = signer.sign_wasm(sk, message, Buffer.from(kat.signing_randomness, 'hex'));
    assert.equal(hash(signature), kat.sha3_256_hash_of_signature);
    assert.equal(signer.verify_with_context_wasm(kp.public_key, message, new Uint8Array(), signature), true);
    signature[0] ^= 1;
    assert.equal(signer.verify_with_context_wasm(kp.public_key, message, new Uint8Array(), signature), false);
  } finally { sk.fill(0); kp.free(); }
});

test('existing independent Wycheproof FIPS 204 signature verifies through WASM', () => {
  const vectors = JSON.parse(readFileSync(new URL('../../../lib-q-ml-dsa/tests/wycheproof/mldsa_65_standard_verify_test.json', import.meta.url)));
  const group = vectors.testGroups[0];
  const vector = group.tests[0];
  assert.equal(vector.result, 'valid');
  assert.equal(signer.verify_with_context_wasm(Buffer.from(group.publicKey, 'hex'),
    Buffer.from(vector.msg, 'hex'), Buffer.from(vector.ctx ?? '', 'hex'), Buffer.from(vector.sig, 'hex')), true);
});

test('existing independent Wycheproof FIPS 204 invalid signature is rejected through WASM', () => {
  const vectors = JSON.parse(readFileSync(new URL('../../../lib-q-ml-dsa/tests/wycheproof/mldsa_65_standard_verify_test.json', import.meta.url)));
  const group = vectors.testGroups[0];
  const vector = group.tests.find((t) => t.tcId === 8);
  assert.equal(vector.result, 'invalid');
  assert.ok(vector.flags.includes('ModifiedSignature'));
  assert.equal(signer.verify_with_context_wasm(Buffer.from(group.publicKey, 'hex'),
    Buffer.from(vector.msg, 'hex'), Buffer.from(vector.ctx ?? '', 'hex'), Buffer.from(vector.sig, 'hex')), false);
});
