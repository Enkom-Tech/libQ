# @lib-q/jose — Node ML-DSA-65 verifier

Compact JWS and OIDC ID token verification using lib-q-sig's WASM primitive.
Node 20+; ESM; no browser build, classical signature fallback, userinfo fallback,
or new signature implementation. SHA3-256 is used only for the RFC 7638 key
identifier, not for signing or prehashing the JWS. No SHA-2 is used anywhere.

## Install

```sh
npm install @lib-q/jose@0.0.12
```

`@lib-q/jose` is released with the rest of lib-Q at the workspace version and
depends on `@lib-q/sig` at exactly the same version. It needs the
`MlDsa.ml_dsa_65()` factory, which `@lib-q/sig` exports from 0.0.12 on
(`@lib-q/sig@0.0.11` has no JavaScript factory), so 0.0.12 is the first usable
pair.

## Building and testing from source

From the repository root, with the repository's Rust toolchain, wasm-pack and
npm available, build the companion `@lib-q/sig` Node package the way CD does
and test against it:

```sh
export LIBQ="$PWD" VERSION=0.0.12
wasm-pack build lib-q-sig --target nodejs --out-dir ../target/jose-sig -- --features wasm,ml-dsa
cd "$LIBQ/target/jose-sig"
npm pkg set 'name=@lib-q/sig' "version=$VERSION"
NPM_PUBLISH_STEM=lib_q_sig node "$LIBQ/scripts/npm-publish-annotate.mjs"
npm pack --ignore-scripts
cd "$LIBQ/npm/lib-q-jose"
npm install --no-save --package-lock=false --ignore-scripts --no-audit --no-fund "$LIBQ/target/jose-sig/lib-q-sig-$VERSION.tgz"
npm test
npm pack --ignore-scripts
```

## API

```js
import { importAkpJwk, verifyCompactJws, verifyIdToken } from '@lib-q/jose';

const { publicKey, thumbprint, kid } = importAkpJwk(publicJwk);
const bytes = verifyCompactJws(compactJws, trustedJwks, {
  algorithms: ['ML-DSA-65'],
});
const claims = await verifyIdToken(idToken, {
  jwksUri: 'https://issuer.example/.well-known/jwks.json',
  issuer: 'https://issuer.example',
  audience: 'registered-client-id',
  nonce: expectedNonceFromLoginTransaction,
  clockToleranceSec: 30,
});
```

- `importAkpJwk`: accepts public RFC 9964 `kty: "AKP"`, `alg: "ML-DSA-65"`,
  `pub` only. Public key length is 1952 bytes. Rejects `priv`, incompatible
  `use`/`key_ops`, and noncanonical base64url. Thumbprint is SHA3-256 of canonical
  `{"alg":"ML-DSA-65","kty":"AKP","pub":"..."}`, base64url-encoded.
  RFC 7638 leaves the hash to the application. This differs from the common
  SHA-256 thumbprint, so a `kid` computed elsewhere with SHA-256 will not match.
  In RFC 9278 URI form the hash name is `sha3-256`:
  `urn:ietf:params:oauth:jwk-thumbprint:sha3-256:<thumbprint>`. Returned `kid` defaults to
  the thumbprint if absent; an issuer-supplied `kid` need not equal it.
- `verifyCompactJws`: synchronous; returns authenticated **Uint8Array bytes**,
  not parsed JSON. Requires the exact algorithm allowlist shown. Requires a
  protected `kid` matching exactly one explicit `jwks.keys[].kid`. Rejects
  unsupported `crit` and unencoded/detached payloads. Verifies the original ASCII
  `protected.payload` signing input with **empty ML-DSA context**, without
  reserializing JSON or prehashing. Does not validate JWT claims.
- `verifyIdToken`: asynchronous; returns parsed authenticated claims. Requires
  exactly one of `jwks` or `jwksUri`, plus nonempty expected issuer, audience
  (client ID), and transaction nonce. Checks `iss`, nonempty `sub`, `aud`, `azp`,
  numeric `exp`/`iat`, nonce, and optional numeric `nbf`. Multiple audiences require
  matching `azp`; any present `azp` must match the client ID. `iat` cannot be in
  the future beyond tolerance or at/after `exp`. Tolerance defaults to zero.
  No maximum token age beyond expiry is imposed; applications may add one.
- Failures throw/reject. Treat all failures as authentication failure, not as a
  reason to try a classical verifier or trust unverified claims.

Remote JWKS URLs must be caller-configured HTTPS URLs without credentials or
fragments. Token headers such as `jku`, `x5u`, or `jwk` never choose trust roots.
Redirects are refused. Fetches have a five-second timeout and one-MiB body cap;
compact input is capped at one MiB. Successful sets are cached for five minutes
(up to 64 configured URLs per process). A **cached** kid miss triggers one
refetch; a just-fetched miss is final. Concurrent fetches for a URI are coalesced.
Signature failures do not trigger refetches. Fetch/parse failures never authorize
with stale keys. Rate-limit the login callback at the application boundary:
sequential unknown-kid requests can each trigger a refetch. Removing a known key
from the issuer takes effect at cache expiry; use local JWKS where immediate
revocation is required.

## Integrating with an OIDC relying party

Install `@lib-q/jose` in the server workspace; it pulls in `@lib-q/sig` at the
same exact version. Keep this package server-side; it loads
Node's WASM glue and is not an Edge/browser verifier.

In a relying party's OIDC callback (for example, a `jose`-based `jwtVerify` call
in a control-plane server, or a Better Auth OIDC callback), replace an ES256
`jwtVerify` call with `await verifyIdToken(idToken, options)` and use its returned
claims directly (there is no `{ payload }` wrapper). Keep expected issuer and
JWKS URI in trusted provider configuration, audience as the registered client
ID, and nonce in the existing one-use login transaction. Do not derive these
expectations from the token.

Authenticate the token with this function **before** using any claim for
account lookup, linking, or session creation. Pass the nonce saved when
redirecting to the provider. Keep the framework's state/PKCE validation and
one-use transaction consumption. Userinfo may enrich an already authenticated
identity, never replace ID token verification. This package does not implement
OAuth state, PKCE, nonce storage/replay prevention, `at_hash`/`c_hash`,
discovery, or account-linking policy. This example targets the code flow; it
is not a complete implicit/hybrid-flow implementation.

No downstream application is modified or exercised by this package; the above
is integration guidance only.

## Scratch plain-JavaScript install / verify

After building the two tarballs above, with `LIBQ` and `VERSION` still set:

```sh
mkdir -p /tmp/libq-jose-smoke
cd /tmp/libq-jose-smoke
npm init -y
npm install --ignore-scripts --no-audit --no-fund \
  "$LIBQ/target/jose-sig/lib-q-sig-$VERSION.tgz" \
  "$LIBQ/npm/lib-q-jose/lib-q-jose-$VERSION.tgz"
node --input-type=module <<'JS'
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { MlDsa } from '@lib-q/sig';
import { importAkpJwk, verifyIdToken } from '@lib-q/jose';
const signer = MlDsa.ml_dsa_65();
const pair = signer.generate_keypair_wasm(randomBytes(32));
const secret = pair.secret_key;
try {
  const key = { kty: 'AKP', alg: 'ML-DSA-65', pub: Buffer.from(pair.public_key).toString('base64url') };
  key.kid = importAkpJwk(key).thumbprint;
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: 'https://issuer.example', sub: 'alice', aud: 'client', nonce: 'smoke-nonce', iat: now, exp: now + 60 };
  const encode = x => Buffer.from(JSON.stringify(x)).toString('base64url');
  const input = `${encode({ alg: key.alg, kid: key.kid })}.${encode(claims)}`;
  const signature = signer.sign_with_context_wasm(secret, Buffer.from(input), new Uint8Array(), randomBytes(32));
  const jws = `${input}.${Buffer.from(signature).toString('base64url')}`;
  assert.deepEqual(await verifyIdToken(jws, { jwks: { keys: [key] }, issuer: claims.iss, audience: claims.aud, nonce: claims.nonce }), claims);
  console.log('plain JS ML-DSA-65 ID token verified');
} finally { secret.fill(0); pair.free(); signer.free(); }
JS
```

`npm test` additionally includes tampering, algorithm/key confusion, claims,
remote rotation, a FIPS 204 libcrux/dilithium-py KAT (with fixed key/signature
hashes), and an independent Wycheproof signature from the existing libQ corpus.
The dilithium-py KAT is **not** a NIST ACVP vector; see the existing KAT provenance
document. A separate cross-implementation vector is not included.

## Algorithms and testing

This package verifies ML-DSA-65 (FIPS 204) signatures for JOSE, using the JWS algorithm identifier `ML-DSA-65` and the JWK key type `AKP` defined in RFC 9964.

`npm test` covers tampered payloads and signatures, algorithm and key confusion, kid selection, claims validation, and remote JWKS rotation. It also checks the WASM primitive against one FIPS 204 known-answer vector from the libcrux/dilithium-py set (not a NIST ACVP vector) and two Wycheproof ML-DSA-65 vectors: one valid, and one with a modified signature.
